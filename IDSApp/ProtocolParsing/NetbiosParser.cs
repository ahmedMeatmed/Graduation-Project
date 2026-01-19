// =============================================
// CLASS SUMMARY: NetbiosParser
// =============================================
/// <summary>
/// NetBIOS Name Service Protocol Parser - Main class for analyzing NetBIOS network packets
/// Provides comprehensive parsing, security analysis, and logging of NetBIOS-NS and Datagram Service traffic
/// Implements IDisposable for proper resource management
/// </summary>

using IDSApp.BLL;
using IDSApp.DAL;
using IDSApp.Entity;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IDSApp.ProtocolParsing
{
    public class NetbiosParser : IDisposable
    {
        private string _queryName;
        private string _queryType;
        private string _response;
        private string _responderIp;
        private string _sourceIp;
        private string _destinationIp;
        private DateTime _timestamp;
        private string _sessionId;
        private string _status;
        private MemoryStream _bodyStream;
        private readonly object _lock;
        private bool _disposed;

        private const int MaxPayloadSnippet = 128;
        private const int MaxPayloadSize = 1024 * 1024;

        private static readonly HashSet<string> ValidQueryTypes = new HashSet<string>(new[]
        {
            "NB", "NBSTAT", "GENERAL", "WorkstationService", "MessengerService",
            "DomainController", "MasterBrowser", "GeneralNameQuery", "Unknown",
            "DatagramService", "BrowserBroadcast"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly Regex SuspiciousNameRegex = new Regex(
            @"(?:password|secret|key|auth|token|attack|exploit|admin|root)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public NetbiosParser()
        {
            _bodyStream = new MemoryStream();
            _lock = new object();
            Reset();
        }

        private static string MapRecordType(ushort type)
        {
            return type switch
            {
                0x0020 => "WorkstationService",
                0x0021 => "MessengerService",
                0x002B => "DomainController",
                0x002C => "MasterBrowser",
                0x0000 => "GeneralNameQuery",
                0x0022 => "NetBIOS_NBNAME",
                _ => $"Unknown (0x{type:X4})"
            };
        }

        public void Reset()
        {
            lock (_lock)
            {
                _queryName = null;
                _queryType = null;
                _response = null;
                _responderIp = null;
                _sourceIp = null;
                _destinationIp = null;
                _timestamp = DateTime.UtcNow;
                _sessionId = null;
                _status = null;
                _bodyStream?.SetLength(0);
            }
        }

        public void Parse(byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort, string sessionId = null)
        {
            if (payload == null || payload.Length == 0)
            {
                LogError("Empty or null payload", srcIp, dstIp);
                return;
            }
            if (payload.Length > MaxPayloadSize)
            {
                LogError($"Payload too large: {payload.Length} bytes", srcIp, dstIp);
                return;
            }
            if (!IsValidIPAddress(srcIp) || !IsValidIPAddress(dstIp))
            {
                LogError($"Invalid IP address: Src={srcIp}, Dst={dstIp}", srcIp, dstIp);
                return;
            }

            lock (_lock)
            {
                _sourceIp = srcIp;
                _destinationIp = dstIp;
                _timestamp = DateTime.UtcNow;
                _sessionId = sessionId ?? $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";
                _bodyStream.SetLength(0);
                _bodyStream.Write(payload, 0, payload.Length);

                try
                {
                    // ✅ تفرقة بين NetBIOS Name Service (137) و Datagram Service (138)
                    if (srcPort == 137 || dstPort == 137)
                        ParseNetbiosNameService(payload);
                    else if (srcPort == 138 || dstPort == 138)
                        ParseNetbiosDatagram(payload);
                    else
                        _status = "UnsupportedPort";

                    LogToDb(false, $"Parsed NetBIOS packet: QueryName={Truncate(_queryName, 200)}, QueryType={_queryType}, Response={Truncate(_response, 200)}");
                }
                catch (Exception ex)
                {
                    LogToDb(true, $"NetBIOS parse failed: {ex.Message}");
                }
            }
        }

        // ========================= NAME SERVICE =========================
        private void ParseNetbiosNameService(byte[] payload)
        {
            if (payload.Length < 12)
            {
                LogSuspicious("Invalid NetBIOS packet: too short");
                return;
            }

            ushort transactionId = (ushort)((payload[0] << 8) | payload[1]);
            bool isResponse = (payload[2] & 0x80) != 0;
            byte rcode = (byte)(payload[3] & 0x0F);
            ushort qdCount = (ushort)((payload[4] << 8) | payload[5]);
            ushort anCount = (ushort)((payload[6] << 8) | payload[7]);
            int offset = 12;

            _queryName = "unknown";
            _queryType = "Unknown";
            _response = "none";
            _responderIp = _destinationIp;

            if (qdCount > 0 && ParseNetbiosName(payload, ref offset, out string qname))
            {
                _queryName = string.IsNullOrWhiteSpace(qname) ? "unknown" : qname;
                if (offset + 4 <= payload.Length)
                {
                    ushort qType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    _queryType = MapRecordType(qType);
                    offset += 4;
                }
            }

            // 🔹 تحسينات للتعرف على أنواع الخدمات
            if (_queryName.Contains("__MSBROWSE__", StringComparison.OrdinalIgnoreCase))
                _queryType = "BrowserAnnouncement";
            else if (_queryName.EndsWith("<00>"))
                _queryType = "WorkstationService";
            else if (_queryName.EndsWith("<03>"))
                _queryType = "MessengerService";
            else if (_queryName.EndsWith("<1B>"))
                _queryType = "DomainController";
            else if (_queryName.EndsWith("<1D>"))
                _queryType = "MasterBrowser";
            else if (_queryType == "Unknown" && _queryName != "unknown")
                _queryType = "GeneralNameQuery";

            // 🔹 Response parsing
            if (isResponse && anCount > 0)
            {
                if (offset + 10 <= payload.Length)
                {
                    ushort aType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    offset += 4;
                    uint ttl = (uint)((payload[offset] << 24) | (payload[offset + 1] << 16) |
                                      (payload[offset + 2] << 8) | payload[offset + 3]);
                    offset += 4;
                    ushort rdLength = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    offset += 2;

                    if (offset + rdLength <= payload.Length)
                    {
                        if (aType == 0x0020 && rdLength >= 6)
                        {
                            byte flags = payload[offset];
                            byte[] ipBytes = new byte[4];
                            Array.Copy(payload, offset + 2, ipBytes, 0, 4);
                            _responderIp = new IPAddress(ipBytes).ToString();
                            _response = $"NB_Response: IP={_responderIp}, Flags=0x{flags:X2}";
                            _queryType = "NB";
                        }
                        else if (aType == 0x0021)
                        {
                            byte[] nodeData = new byte[rdLength];
                            Array.Copy(payload, offset, nodeData, 0, rdLength);
                            _response = TryGetAsciiString(nodeData, out string nodeStr)
                                ? $"NodeStatus: {Truncate(nodeStr, 200)}"
                                : $"NodeStatus: {rdLength} bytes";
                            _queryType = "NBSTAT";
                        }
                        else
                        {
                            _response = $"UnknownAnswer (Type=0x{aType:X4}, Len={rdLength})";
                        }
                    }
                }
            }
            else
            {
                _response = isResponse ? "NB_Response" : "NB_Query";
            }

            if (!ValidQueryTypes.Contains(_queryType))
                LogSuspicious($"Invalid or unknown query type: {_queryType}");
            if (!string.IsNullOrEmpty(_queryName) && SuspiciousNameRegex.IsMatch(_queryName))
                LogSuspicious($"Suspicious query name: {Truncate(_queryName, 200)}");
            if (isResponse && rcode != 0)
                LogSuspicious($"NetBIOS response error: RCODE={rcode}");

            _status = "OK";
        }

        // ========================= DATAGRAM SERVICE =========================
        private void ParseNetbiosDatagram(byte[] payload)
        {
            try
            {
                if (payload.Length < 14)
                {
                    LogSuspicious("Invalid NetBIOS Datagram: too short");
                    return;
                }

                byte msgType = payload[0];
                ushort flags = (ushort)((payload[1] << 8) | payload[2]);
                ushort dgramId = (ushort)((payload[3] << 8) | payload[4]);
                byte[] srcIpBytes = new byte[4];
                Array.Copy(payload, 6, srcIpBytes, 0, 4);
                string srcIp = new IPAddress(srcIpBytes).ToString();

                _responderIp = srcIp;
                _queryType = "DatagramService";
                _response = "none";

                string messageDesc = msgType switch
                {
                    0x10 => "DirectUnique",
                    0x11 => "DirectGroup",
                    0x12 => "Broadcast",
                    0x13 => "QueryRequest",
                    0x14 => "PositiveResponse",
                    0x15 => "NegativeResponse",
                    0x1E => "DatagramError",
                    0x1F => "DatagramTerminate",
                    _ => $"Unknown(0x{msgType:X2})"
                };

                _response = $"NBDS_{messageDesc}";
                _queryType = messageDesc.Contains("Broadcast") ? "BrowserBroadcast" : "DatagramService";

                int dataOffset = 14;
                if (payload.Length > dataOffset + 10)
                {
                    if (TryGetAsciiString(payload[dataOffset..], out string content))
                    {
                        var nameMatch = Regex.Match(content, @"[A-Z0-9\-]{3,15}\x00");
                        if (nameMatch.Success)
                            _queryName = nameMatch.Value.TrimEnd('\0');
                        else
                            _queryName = "unknown";
                    }
                }

                _status = "OK";
            }
            catch (Exception ex)
            {
                _status = "Error";
                LogSuspicious($"Exception while parsing NetBIOS Datagram: {ex.Message}");
            }
        }

        // ========================= UTILITIES =========================
        private bool ParseNetbiosName(byte[] payload, ref int offset, out string name)
        {
            name = null;
            if (offset >= payload.Length || payload[offset] == 0)
                return false;

            try
            {
                int labelLength = payload[offset++];
                if (labelLength != 32 || offset + labelLength > payload.Length)
                    return false;

                byte[] encoded = new byte[labelLength];
                Array.Copy(payload, offset, encoded, 0, labelLength);
                offset += labelLength;

                byte[] decoded = new byte[16];
                for (int i = 0; i < 16; i++)
                {
                    byte c1 = (byte)(encoded[i * 2] - 'A');
                    byte c2 = (byte)(encoded[i * 2 + 1] - 'A');
                    decoded[i] = (byte)((c1 << 4) | c2);
                }

                name = Encoding.ASCII.GetString(decoded).TrimEnd();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool TryGetAsciiString(byte[] data, out string result)
        {
            try { result = Encoding.ASCII.GetString(data); return true; }
            catch { result = null; return false; }
        }

        private static string Truncate(string s, int max) => string.IsNullOrEmpty(s) ? s : s.Length <= max ? s : s[..max] + "...";

        private void LogSuspicious(string message) => LogToDb(true, message);
        private void LogError(string message, string srcIp, string dstIp) => LogToDb(true, $"ERROR: {message}");

        private void LogToDb(bool isSuspicious, string message)
        {
            try
            {
                string payloadSnippet = _bodyStream?.Length > 0
                    ? BitConverter.ToString(_bodyStream.ToArray(), 0, (int)Math.Min(MaxPayloadSnippet, _bodyStream.Length))
                    : "-";
                string fingerprint = GeneratePayloadFingerprintSafe(_bodyStream?.ToArray());
                DateTime safeTimestamp = (_timestamp < new DateTime(1753, 1, 1) || _timestamp > new DateTime(9999, 12, 31, 23, 59, 59))
                    ? DateTime.UtcNow : _timestamp;

                int logId = LogBLL.Insert(
                    safeTimestamp,
                    _sourceIp ?? "unknown",
                    _destinationIp ?? "unknown",
                    (int)(_bodyStream?.Length ?? 0),
                    isSuspicious,
                    "NetBIOS",
                    "UDP",
                    0,
                    137,
                    (int)(_bodyStream?.Length ?? 0),
                    _queryType ?? "-",
                    "in",
                    0,
                    0,
                    null,
                    $"{message}; Snippet={payloadSnippet}; fingerprint={fingerprint}"
                );

                if (logId > 0)
                {
                    NetbiosLogBLL.Insert(
                        logId,
                        _queryName ?? "unknown",
                        _queryType ?? "unknown",
                        _response ?? "none",
                        _responderIp ?? "unknown",
                        _sourceIp ?? "unknown",
                        _destinationIp ?? "unknown",
                        _timestamp,
                        _sessionId,
                        _status ?? "OK"
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetBIOS-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIp}, Dst={_destinationIp}");
            }
        }

        private string GeneratePayloadFingerprintSafe(byte[] payload)
        {
            try
            {
                if (payload == null || payload.Length == 0) return null;
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(payload);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch { return null; }
        }

        private bool IsValidIPAddress(string ip) => !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);
        public byte[] Body => _bodyStream?.ToArray();

        public void Dispose()
        {
            lock (_lock)
            {
                if (!_disposed)
                {
                    _bodyStream?.Dispose();
                    _bodyStream = null;
                    _disposed = true;
                }
            }
        }
    }
}
