using PacketDotNet;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Timers;

namespace IDSApp.Helper
{
    // -------------------- Result model --------------------
    public class SmbParseResult
    {
        public string Command { get; set; } = "unknown";
        public string Filename { get; set; } = "unknown";
        public string Share { get; set; } = "unknown";
        public string Service { get; set; } = "none";
        public uint TreeId { get; set; } = 0;
        public uint SessionId { get; set; } = 0;
        public string Dialect { get; set; } = "unknown";
        public int PayloadSize { get; set; } = 0;
        public string TcpFlags { get; set; } = string.Empty;
        public bool IsSuspicious { get; set; } = false;
        public List<string> Notes { get; set; } = new List<string>();
        public List<string> SuspicionReasons { get; set; } = new List<string>();

        public override string ToString() =>
            $"Cmd={Command}, Share={Share}, File={Filename}, Service={Service}, TreeID={TreeId}, SessionID={SessionId}, Suspicious={IsSuspicious}, Notes=[{string.Join(',', Notes)}]";
    }


        public static class SmbParsingHelpers
        {
            // Remove NetBIOS Session header (4 bytes) if present and return new buffer + offset
            public static byte[] NormalizeNetBiosAndReturnPayload(byte[] buf)
            {
                if (buf == null || buf.Length < 4) return buf;
                // NetBIOS Session Service header: first byte usually 0x00 and next 3 bytes length (for many captures)
                // We detect common markers (0x00, 0x81, 0x82) used in your code previously and strip them safely.
                if (buf.Length >= 4 && (buf[0] == 0x00 || buf[0] == 0x81 || buf[0] == 0x82))
                {
                    int reportedLen = ((buf[1] << 16) | (buf[2] << 8) | buf[3]);
                    // reportedLen sometimes not reliable; check minimal sanity
                    if (reportedLen <= buf.Length - 4 || reportedLen > 0)
                    {
                        var outbuf = new byte[buf.Length - 4];
                        Buffer.BlockCopy(buf, 4, outbuf, 0, outbuf.Length);
                        return outbuf;
                    }
                }
                return buf;
            }

            // Try to read a UTF-16LE string from offset with specified length
            public static string TryGetUnicodeString(byte[] buf, int offset, int length)
            {
                try
                {
                    if (buf == null) return null;
                    if (offset < 0 || length <= 0) return null;
                    if (offset + length > buf.Length) return null;
                    return Encoding.Unicode.GetString(buf, offset, length).Trim('\0', ' ');
                }
                catch { return null; }
            }

            // Try to read ASCII string
            public static string TryGetAsciiString(byte[] buf, int offset, int length)
            {
                try
                {
                    if (buf == null) return null;
                    if (offset < 0 || length <= 0) return null;
                    if (offset + length > buf.Length) return null;
                    return Encoding.ASCII.GetString(buf, offset, length).Trim('\0', ' ');
                }
                catch { return null; }
            }

            // Scan payload for first UNC pattern \\server\share (ASCII) or Unicode version
            public static string FindUncOrShare(byte[] buf)
            {
                if (buf == null || buf.Length == 0) return null;

                // Try Unicode UNC: look for 0x5C 0x00 0x5C 0x00  ( '\\' in UTF-16LE repeated )
                for (int i = 0; i + 3 < buf.Length; i++)
                {
                    if (buf[i] == 0x5C && buf[i + 1] == 0x00 && buf[i + 2] == 0x5C && buf[i + 3] == 0x00)
                    {
                        // extract following Unicode chars up to null
                        int j = i + 4;
                        while (j + 1 < buf.Length && !(buf[j] == 0x00 && buf[j + 1] == 0x00)) j += 2;
                        int len = j - (i + 4);
                        if (len > 0 && (i + 4 + len) <= buf.Length)
                        {
                            string s = TryGetUnicodeString(buf, i + 4, len);
                            if (!string.IsNullOrEmpty(s)) return CleanShareName(s);
                        }
                    }
                }

                // ASCII UNC: \\server\share
                string ascii = Encoding.ASCII.GetString(buf);
                var m = Regex.Match(ascii, @"\\\\[^\\\r\n]+\\[^\\\r\n]+");
                if (m.Success) return CleanShareName(m.Value);

                // admin share heuristics
                var adminMatches = new[] { "C$", "ADMIN$", "IPC$", "PRINT$" };
                foreach (var a in adminMatches)
                {
                    if (ascii.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0) return a;
                }

                return null;
            }

            public static string CleanShareName(string share)
            {
                if (string.IsNullOrEmpty(share)) return null;
                share = share.Trim('\0', ' ', '\\', '/');
                share = Regex.Replace(share, @"[^\u0020-\u007E\u00A0-\u00FF\\\/]", "");
                if (string.IsNullOrWhiteSpace(share)) return null;
                return share;
            }

            public static string CleanFilename(string name)
            {
                if (string.IsNullOrEmpty(name)) return null;
                name = name.Trim('\0', ' ', '\\', '/');
                name = Regex.Replace(name, @"[^\u0020-\u007E\u00A0-\u00FF\u0100-\u017F\\\/\.\-_]", "");
                if (string.IsNullOrWhiteSpace(name)) return null;
                return name;
            }

            // Try to extract a readable Unicode string starting at 'offset' or scanning forward up to maxLen bytes
            public static string ScanForReadableString(byte[] buf, int offset, int maxLen = 512)
            {
                if (buf == null || buf.Length == 0) return null;
                offset = Math.Max(0, offset);
                int end = Math.Min(buf.Length, offset + maxLen);
                // Try Unicode chunks first
                for (int i = offset; i + 2 < end; i += 2)
                {
                    int j = i;
                    // accumulate until double-null
                    while (j + 1 < end && !(buf[j] == 0x00 && buf[j + 1] == 0x00)) j += 2;
                    int len = j - i;
                    if (len >= 4) // at least 2 chars
                    {
                        string s = TryGetUnicodeString(buf, i, len);
                        if (!string.IsNullOrEmpty(s) && s.Count(c => char.IsLetterOrDigit(c)) >= 1)
                            return s;
                    }
                }
                // fallback to ASCII
                var asciiSlice = Encoding.ASCII.GetString(buf, offset, end - offset);
                var match = Regex.Match(asciiSlice, @"[A-Za-z0-9_\-\\/\.]{3,}");
                if (match.Success) return match.Value;
                return null;
            }
        }

        public class SmbParser
        {
            // Try to parse SMB message and fill result with best-effort values
            public SmbParseResult ParseSmbPacket(byte[] rawPayload, string sessionKey, string srcIp, string dstIp, int originalCommand = -1)
            {
                var result = new SmbParseResult
                {
                    PayloadSize = rawPayload?.Length ?? 0,
                    // keep defaults defined in SmbParseResult
                };

                if (rawPayload == null || rawPayload.Length == 0)
                {
                    result.Notes.Add("Empty raw payload");
                    return result;
                }

                // 1) Normalize (strip NetBIOS header if present)
                var payload = SmbParsingHelpers.NormalizeNetBiosAndReturnPayload(rawPayload) ?? rawPayload;
                result.PayloadSize = payload.Length;

                // 2) Quick header check
                if (payload.Length < 4)
                {
                    result.Notes.Add("Payload too short after normalization");
                    result.Notes.Add($"RawFirstBytes: {BitConverter.ToString(payload.Take(Math.Min(8, payload.Length)).ToArray())}");
                    return result;
                }

                // 3) Detect SMB version/signature
                // common signatures:
                // SMB1: 0xFF 'S' 'M' 'B'  -> bytes: 0xFF 0x53 0x4D 0x42
                // SMB2: 0xFE 0x53 0x4D 0x42
                byte b0 = payload[0];
                bool handled = false;

                try
                {
                    if (b0 == 0xFF && payload.Length >= 32 && payload[1] == 0x53 && payload[2] == 0x4D && payload[3] == 0x42)
                    {
                        // SMB1
                        result.Notes.Add("Detected SMB1 signature");
                        handled = true;
                        ParseSmb1(payload, sessionKey, result, originalCommand);
                    }
                    else if ((b0 == 0xFE || b0 == 0xFD) && payload.Length >= 16 && payload[1] == 0x53 && payload[2] == 0x4D && payload[3] == 0x42)
                    {
                        // SMB2+
                        result.Notes.Add("Detected SMB2/SMB2.x signature");
                        handled = true;
                        ParseSmb2(payload, sessionKey, result, originalCommand);
                    }
                    else
                    {
                        // fallback: maybe NetBIOS not stripped or fragment - scan for SMB signature inside
                        int found = IndexOfSequence(payload, new byte[] { 0xFF, 0x53, 0x4D, 0x42 });
                        if (found < 0)
                            found = IndexOfSequence(payload, new byte[] { 0xFE, 0x53, 0x4D, 0x42 });
                        if (found >= 0 && payload.Length - found >= 8)
                        {
                            result.Notes.Add($"SMB signature found at offset {found}, trying parse from there");
                            var sliced = new byte[payload.Length - found];
                            Buffer.BlockCopy(payload, found, sliced, 0, sliced.Length);
                            if (sliced[0] == 0xFF) ParseSmb1(sliced, sessionKey, result, originalCommand);
                            else ParseSmb2(sliced, sessionKey, result, originalCommand);
                            handled = true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Notes.Add($"Exception in version-detect: {ex.Message}");
                }

                if (!handled)
                {
                    // Try heuristics to extract UNC or filename strings
                    string unc = SmbParsingHelpers.FindUncOrShare(payload);
                    if (!string.IsNullOrEmpty(unc))
                    {
                        result.Share = unc;
                        result.Notes.Add("Heuristic: found UNC/share by scanning payload");
                    }

                    // scan for any readable filename
                    var anyName = SmbParsingHelpers.ScanForReadableString(payload, 0, 600);
                    if (!string.IsNullOrEmpty(anyName))
                    {
                        // if share empty assign as filename etc.
                        if (string.IsNullOrEmpty(result.Filename) || result.Filename == "unknown")
                            result.Filename = SmbParsingHelpers.CleanFilename(anyName) ?? result.Filename;
                        result.Notes.Add("Heuristic: found readable string in payload");
                    }

                    result.Notes.Add("SMB signature not confidently detected");
                }

                // If still default values, add raw bytes for later offline analysis (don't bloat Notes list)
                if ((string.IsNullOrEmpty(result.Share) || result.Share == "unknown") &&
                    (string.IsNullOrEmpty(result.Filename) || result.Filename == "unknown"))
                {
                    // include short hex snippet
                    var snippet = BitConverter.ToString(payload.Take(Math.Min(64, payload.Length)).ToArray());
                    result.Notes.Add($"RawSnippet: {snippet}");
                }

                // final: remove "none"/"unknown" where we can present empty string instead (optional)
                if (result.Share == "none") result.Share = "unknown";
                if (result.Service == "none") result.Service = "unknown";

                return result;
            }

            private void ParseSmb1(byte[] payload, string sessionKey, SmbParseResult result, int originalCommand)
            {
                // Ensure we have at least SMB1 header length
                try
                {
                    if (payload.Length < 8)
                    {
                        result.Notes.Add("SMB1 payload too short");
                        return;
                    }

                    // command at offset 4
                    byte cmd = payload[4];
                    result.Command = GetSmb1CommandName(cmd);

                    // attempt TreeId extraction if possible (common offset 28)
                    if (payload.Length >= 32)
                    {
                        try { result.TreeId = BitConverter.ToUInt32(payload, 28); }
                        catch { }
                    }

                    // For negotiate
                    if (result.Command?.IndexOf("NEGOTIATE", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        result.Filename = "SMB1 Protocol Negotiation";
                        ParseNegotiateDialect(payload, result);
                        return;
                    }

                    // For tree connect — extract share via FindUncOrShare or scanning
                    if (result.Command?.IndexOf("TREE_CONNECT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        result.Command?.IndexOf("TREE_CONNECT_ANDX", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string share = SmbParsingHelpers.FindUncOrShare(payload);
                        if (!string.IsNullOrEmpty(share))
                        {
                            result.Share = share;
                            result.Notes.Add("SMB1: extracted share via UNC scan");
                            _ = _TryMapTreeId(sessionKey, result.TreeId, result.Share); // ephemeral mapping attempt
                        }
                        else
                        {
                            // fallback: scan region after header
                            var s = SmbParsingHelpers.ScanForReadableString(payload, 32, 200);
                            if (!string.IsNullOrEmpty(s))
                            {
                                result.Share = s.Contains("\\") ? s : s.Split('\\').FirstOrDefault() ?? s;
                                result.Notes.Add("SMB1: fallback scanned share/filename");
                            }
                        }
                        return;
                    }

                    // For create/open — try to scan for filename (Unicode preferred)
                    if (result.Command?.IndexOf("CREATE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        result.Command?.IndexOf("OPEN", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // often filename appears after SMB header; try Unicode then ASCII
                        var filename = SmbParsingHelpers.ScanForReadableString(payload, 32, 512);
                        if (!string.IsNullOrEmpty(filename)) result.Filename = SmbParsingHelpers.CleanFilename(filename);
                        else result.Notes.Add("SMB1 CREATE/OPEN: no filename discovered by scan");
                        return;
                    }

                    // default best-effort scanning for share/filename
                    var unc = SmbParsingHelpers.FindUncOrShare(payload);
                    if (!string.IsNullOrEmpty(unc)) result.Share = unc;
                    var anyName = SmbParsingHelpers.ScanForReadableString(payload, 32, 512);
                    if (!string.IsNullOrEmpty(anyName) && (string.IsNullOrEmpty(result.Filename) || result.Filename == "unknown"))
                        result.Filename = SmbParsingHelpers.CleanFilename(anyName);
                }
                catch (Exception ex)
                {
                    result.Notes.Add($"SMB1 parse exception: {ex.Message}");
                }
            }

            private void ParseSmb2(byte[] payload, string sessionKey, SmbParseResult result, int originalCommand)
            {
                try
                {
                    if (payload.Length < 16)
                    {
                        result.Notes.Add("SMB2 payload too short");
                        return;
                    }

                    // command is two bytes at offset 12 (little-endian)
                    if (payload.Length >= 14)
                    {
                        ushort cmd = BitConverter.ToUInt16(payload, 12);
                        result.Command = GetSmb2CommandName(cmd);
                    }

                    // tree id at offset 36 (DWORD) if present
                    if (payload.Length >= 40)
                    {
                        try { result.TreeId = BitConverter.ToUInt32(payload, 36); }
                        catch { }
                        // try to fetch previously stored share
                        if (result.TreeId != 0)
                        {
                            // Caller can keep mapping - we attempt but safe if not available
                            // result.Share = _treeIdMapper.Get(sessionKey, result.TreeId); // caller's real mapper
                        }
                    }

                    // If negotiate
                    if (result.Command?.IndexOf("NEGOTIATE", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        result.Filename = "SMB2 Protocol Negotiation";
                        ParseNegotiateDialect(payload, result);
                        return;
                    }

                    // For CREATE (0x0005) — SMB2 Create Request contains name offset/length (common positions vary)
                    // Many implementations have NameOffset at payload offset 8 and NameLength at 10 for the Create request portion.
                    if (result.Command?.IndexOf("CREATE", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // attempt to parse nameOffset/nameLength in both little-endian Uint16 positions 8/10
                        if (payload.Length >= 12)
                        {
                            try
                            {
                                ushort nameOffset = BitConverter.ToUInt16(payload, 8);
                                ushort nameLength = BitConverter.ToUInt16(payload, 10);
                                // nameOffset is usually relative to the beginning of the SMB2 header (i.e., payload)
                                if (nameOffset > 0 && nameLength > 0 && nameOffset + nameLength <= payload.Length)
                                {
                                    // SMB2 filenames are UTF-16LE
                                    string fname = SmbParsingHelpers.TryGetUnicodeString(payload, nameOffset, nameLength);
                                    if (!string.IsNullOrEmpty(fname))
                                    {
                                        result.Filename = SmbParsingHelpers.CleanFilename(fname);
                                        result.Notes.Add("SMB2 Create: filename extracted using explicit offsets");
                                    }
                                }
                            }
                            catch { /* ignore and fallback */ }
                        }

                        // fallback: scan buffer for Unicode/ASCII path
                        if (string.IsNullOrEmpty(result.Filename) || result.Filename == "unknown")
                        {
                            var found = SmbParsingHelpers.ScanForReadableString(payload, 64, 1024);
                            if (!string.IsNullOrEmpty(found))
                            {
                                result.Filename = SmbParsingHelpers.CleanFilename(found);
                                result.Notes.Add("SMB2 Create: filename extracted by scanning payload");
                            }
                        }

                        // also try to find UNC/share
                        if (string.IsNullOrEmpty(result.Share) || result.Share == "unknown")
                        {
                            var unc = SmbParsingHelpers.FindUncOrShare(payload);
                            if (!string.IsNullOrEmpty(unc))
                            {
                                result.Share = unc;
                                result.Notes.Add("SMB2 Create: share extracted by UNC scan");
                            }
                        }

                        return;
                    }

                    // For TREE_CONNECT (0x0003)
                    if (result.Command?.IndexOf("TREE_CONNECT", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // Try to get path offset/length: common offsets similar to Create
                        var unc = SmbParsingHelpers.FindUncOrShare(payload);
                        if (!string.IsNullOrEmpty(unc))
                        {
                            result.Share = unc;
                            result.Notes.Add("SMB2 TreeConnect: share extracted by UNC scan");
                        }
                        else
                        {
                            var scanned = SmbParsingHelpers.ScanForReadableString(payload, 48, 400);
                            if (!string.IsNullOrEmpty(scanned)) { result.Share = scanned; result.Notes.Add("SMB2 TreeConnect: fallback scanned share"); }
                        }

                        // map treeId if present (caller mapper)
                        return;
                    }

                    // Default SMB2 fallback heuristics
                    var heuristicName = SmbParsingHelpers.ScanForReadableString(payload, 36, 512);
                    if (!string.IsNullOrEmpty(heuristicName) && (string.IsNullOrEmpty(result.Filename) || result.Filename == "unknown"))
                    {
                        result.Filename = SmbParsingHelpers.CleanFilename(heuristicName);
                        result.Notes.Add("SMB2: heuristic filename found");
                    }

                    var heuristicShare = SmbParsingHelpers.FindUncOrShare(payload);
                    if (!string.IsNullOrEmpty(heuristicShare) && (string.IsNullOrEmpty(result.Share) || result.Share == "unknown"))
                    {
                        result.Share = heuristicShare;
                        result.Notes.Add("SMB2: heuristic share found");
                    }
                }
                catch (Exception ex)
                {
                    result.Notes.Add($"SMB2 parse exception: {ex.Message}");
                }
            }

            // minimal index search
            private int IndexOfSequence(byte[] buf, byte[] seq)
            {
                if (buf == null || seq == null || seq.Length == 0) return -1;
                for (int i = 0; i + seq.Length <= buf.Length; i++)
                {
                    bool ok = true;
                    for (int j = 0; j < seq.Length; j++) if (buf[i + j] != seq[j]) { ok = false; break; }
                    if (ok) return i;
                }
                return -1;
            }

            // Fallback mapping helper (no-op here: you should call treeId mapper from your real instance)
            private bool _TryMapTreeId(string sessionKey, uint treeId, string share)
            {
                try
                {
                    // if you have TreeIdMapper instance accessible, call AddOrUpdate here.
                    // e.g. _treeIdMapper.AddOrUpdate(sessionKey, treeId, share);
                    return true;
                }
                catch { return false; }
            }

            // reuse existing command maps if you want (mirror of your SmbParser)
            private string GetSmb1CommandName(byte cmd)
            {
                try
                {
                    // map common codes to names (kept minimal here)
                    return cmd switch
                    {
                        0x72 => "NEGOTIATE",
                        0x75 => "TREE_CONNECT",
                        0x70 => "TREE_CONNECT_ANDX",
                        0x0D => "CREATE",
                        0x05 => "CREATE_ANDX",
                        0x0A => "OPEN",
                        0x71 => "TREE_DISCONNECT",
                        0x74 => "LOGOFF",
                        _ => $"SMB1_{cmd:X2}"
                    };
                }
                catch { return $"SMB1_{cmd:X2}"; }
            }

            private string GetSmb2CommandName(ushort cmd)
            {
                try
                {
                    return cmd switch
                    {
                        0x0000 => "NEGOTIATE",
                        0x0001 => "SESSION_SETUP",
                        0x0002 => "LOGOFF",
                        0x0003 => "TREE_CONNECT",
                        0x0004 => "TREE_DISCONNECT",
                        0x0005 => "CREATE",
                        0x0006 => "CLOSE",
                        0x0008 => "READ",
                        0x0009 => "WRITE",
                        0x000A => "LOCK",
                        0x000B => "IOCTL",
                        0x000E => "QUERY_INFO",
                        0x0010 => "SET_INFO",
                        0x0011 => "OPLOCK_BREAK",
                        _ => $"SMB2_{cmd:X4}"
                    };
                }
                catch { return $"SMB2_{cmd:X4}"; }
            }

            private void ParseNegotiateDialect(byte[] payload, SmbParseResult result)
            {
                try
                {
                    // try to find readable ASCII dialect strings in the payload
                    if (payload.Length <= 36) return;
                    var dialects = new List<string>();
                    int offset = 36;
                    while (offset + 2 < payload.Length)
                    {
                        // heuristic: ASCII printable bytes ending with 0x00
                        int start = offset;
                        while (offset < payload.Length && payload[offset] != 0x00 && payload[offset] >= 32 && payload[offset] <= 126) offset++;
                        if (offset > start)
                        {
                            string dialect = Encoding.ASCII.GetString(payload, start, offset - start);
                            if (!string.IsNullOrEmpty(dialect) && dialect.Any(char.IsLetterOrDigit))
                                dialects.Add(dialect);
                        }
                        offset++;
                    }
                    if (dialects.Count > 0) { result.Dialect = dialects.First(); result.Notes.Add($"Dialects: {string.Join(',', dialects)}"); }
                    else result.Dialect = "unknown";
                }
                catch { result.Dialect = "unknown"; }
            }
        }
    


    // -------------------- Security analysis --------------------
    public class SmbSecurityAnalysis
    {
        public string RiskLevel { get; set; } = "Low";
        public List<string> Threats { get; set; } = new List<string>();
        public List<string> Recommendations { get; set; } = new List<string>();
    }

    // -------------------- Brute force & Optimizations --------------------
    public class SmbBruteForceDetector
    {
        private readonly ConcurrentDictionary<string, List<DateTime>> _authAttempts = new();
        private readonly int _maxAttempts = 5;
        private readonly TimeSpan _timeWindow = TimeSpan.FromMinutes(5);

        public bool DetectBruteForce(string srcIp, SmbParseResult result)
        {
            if (!IsAuthenticationAttempt(result)) return false;
            var attempts = _authAttempts.GetOrAdd(srcIp, _ => new List<DateTime>());
            attempts.Add(DateTime.Now);
            attempts.RemoveAll(t => DateTime.Now - t > _timeWindow);
            return attempts.Count >= _maxAttempts;
        }

        private bool IsAuthenticationAttempt(SmbParseResult result)
        {
            return result.Command?.IndexOf("SessionSetup", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   result.Command?.IndexOf("Negotiate", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }

    public class SmbProcessingOptimizations
    {
        private readonly ConcurrentDictionary<string, (byte[] Payload, DateTime LastSeen)> _sessions = new();

        public bool ShouldProcessSmbPacket(string sessionKey, byte[] payload)
        {
            if (payload == null || payload.Length < 4)
                return false;

            if (_sessions.TryGetValue(sessionKey, out var last))
            {
                if (payload.SequenceEqual(last.Payload))
                {
                    _sessions[sessionKey] = (last.Payload, DateTime.Now);
                    return false;
                }
            }

            _sessions[sessionKey] = (payload, DateTime.Now);
            return true;
        }

        public void CleanupOldSessions()
        {
            var threshold = DateTime.Now.AddMinutes(-5);
            foreach (var key in _sessions.Keys)
            {
                if (_sessions[key].LastSeen < threshold)
                {
                    _sessions.TryRemove(key, out _);
                }
            }
        }
    }

    public static class SmbDetectionHelper
    {
        public static bool IsValidSmbPacket(byte[] payload, int srcPort, int dstPort)
        {
            if (!IsLikelySmbPacket(payload, srcPort, dstPort))
                return false;

            // Additional validation for SMB structure
            if (payload.Length < 8) return false;

            int offset = 0;
            if (payload.Length >= 4 && (payload[0] == 0x00 || payload[0] == 0x81 || payload[0] == 0x82))
                offset = 4;

            if (payload.Length <= offset + 4) return false;

            // Check for valid SMB signature
            bool isSmb1 = payload[offset] == 0xFF &&
                          payload[offset + 1] == 0x53 &&
                          payload[offset + 2] == 0x4D &&
                          payload[offset + 3] == 0x42;

            bool isSmb2 = (payload[offset] == 0xFE || payload[offset] == 0xFD) &&
                          payload[offset + 1] == 0x53 &&
                          payload[offset + 2] == 0x4D &&
                          payload[offset + 3] == 0x42;

            return isSmb1 || isSmb2;
        }
        public static bool IsLikelySmbPacket(byte[] payload, int srcPort, int dstPort)
        {
            bool isSmbPort = dstPort == 445 || srcPort == 445 || dstPort == 139 || srcPort == 139;
            if (!isSmbPort) return false;
            if (payload == null || payload.Length < 4) return false;
            int startIndex = 0;
            if (payload.Length >= 4 && (payload[0] == 0x00 || payload[0] == 0x81 || payload[0] == 0x82)) startIndex = 4;
            if (payload.Length < startIndex + 4) return false;
            bool isSmb1 = payload[startIndex] == 0xFF && payload[startIndex + 1] == 0x53 && payload[startIndex + 2] == 0x4D && payload[startIndex + 3] == 0x42;
            bool isSmb2 = (payload[startIndex] == 0xFE || payload[startIndex] == 0xFD) && payload[startIndex + 1] == 0x53 && payload[startIndex + 2] == 0x4D && payload[startIndex + 3] == 0x42;
            return isSmb1 || isSmb2;
        }

        public static byte[] ExtractSmbPayload(byte[] payload)
        {
            if (payload == null) return null;
            int startIndex = 0;
            if (payload.Length >= 4 && (payload[0] == 0x00 || payload[0] == 0x81 || payload[0] == 0x82)) startIndex = 4;
            if (payload.Length <= startIndex) return null;
            var result = new byte[payload.Length - startIndex];
            Buffer.BlockCopy(payload, startIndex, result, 0, result.Length);
            return result;
        }

        public static bool ValidateSmbStructure(byte[] payload)
        {
            if (payload == null || payload.Length < 8) return false;
            try
            {
                if (payload[0] == 0xFF)
                {
                    if (payload.Length < 32) return false;
                    byte command = payload[4];
                    return command >= 0x00 && command <= 0xFF;
                }
                else if (payload[0] == 0xFE || payload[0] == 0xFD)
                {
                    if (payload.Length < 64) return false;
                    ushort structureSize = BitConverter.ToUInt16(payload, 4);
                    return structureSize >= 64;
                }
            }
            catch { return false; }
            return true;
        }

        public static bool DetectSmbAttack(byte[] payload, string srcIp, string dstIp)
        {
            if (payload == null) return false;
            string payloadText;
            try { payloadText = Encoding.UTF8.GetString(payload); }
            catch { payloadText = string.Empty; }
            string[] attackPatterns = { "EternalBlue", "EternalRomance", "EternalChampion", "SMBGhost", "SMBleed", "BlueKeep" };
            foreach (var pattern in attackPatterns)
            {
                if (!string.IsNullOrEmpty(payloadText) && payloadText.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            if (IsSuspiciousSmbCommand(payload)) return true;
            return false;
        }

        private static bool IsSuspiciousSmbCommand(byte[] payload)
        {
            if (payload == null || payload.Length < 5) return false;
            int offset = 0;
            if (payload.Length >= 4 && (payload[0] == 0x00 || payload[0] == 0x81 || payload[0] == 0x82)) offset = 4;
            if (payload.Length - offset < 5) return false;
            if (payload[offset] == 0xFF)
            {
                byte command = payload[offset + 4];
                return command == 0x32 || command == 0x33; // Trans2 or NTTrans
            }
            if (payload[offset] == 0xFE || payload[offset] == 0xFD)
            {
                if (payload.Length >= offset + 14)
                {
                    ushort command = BitConverter.ToUInt16(payload, offset + 12);
                    return command == 0x000B || command == 0x000A; // IOCTL / Lock maybe suspicious
                }
            }
            return false;
        }
    }
    public class EnhancedSmbParser
    {
        private static readonly string[] SuspiciousCommands = { "Trans2", "NTTrans", "IOCTL", "Lock" };
        private static readonly string[] AdminShares = { "C$", "ADMIN$", "IPC$", "PRINT$" };

        public SmbSecurityAnalysis AnalyzeSecurity(SmbParseResult result, string srcIp, string dstIp)
        {
            var analysis = new SmbSecurityAnalysis();

            // تحقق أكثر دقة لـ Admin Shares
            if (result.Share != "none" && result.Share != "unknown" &&
                AdminShares.Any(s => result.Share.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                analysis.RiskLevel = "High";
                analysis.Threats.Add($"Administrative share access: {result.Share}");
            }

            if (SuspiciousCommands.Any(c => result.Command?.IndexOf(c, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                analysis.RiskLevel = analysis.RiskLevel == "High" ? "High" : "Medium";
                analysis.Threats.Add($"Suspicious SMB command: {result.Command}");
            }

            // pass-the-hash hint
            if (result.Command?.IndexOf("SessionSetup", StringComparison.OrdinalIgnoreCase) >= 0 &&
                (result.Filename?.IndexOf("NTLM", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 result.Share?.IndexOf("NTLM", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                analysis.RiskLevel = "High";
                analysis.Threats.Add("Potential Pass-the-Hash indicator");
            }

            if (analysis.RiskLevel == "High")
                analysis.Recommendations.Add("Isolate host and review auth logs; block SMB access if unnecessary.");
            else if (analysis.RiskLevel == "Medium")
                analysis.Recommendations.Add("Review SMB traffic and confirm expected shares/commands.");

            return analysis;
        }
    }
}