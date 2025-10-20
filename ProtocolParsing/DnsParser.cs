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
    /// <summary>
    /// DNS protocol parser for Intrusion Detection System
    /// 
    /// Supports parsing DNS packets, detecting anomalies, and logging DNS queries/responses.
    /// Added support for TTL and RecordType fields in detailed DNS logs.
    /// </summary>
    public class DnsParser : IDisposable
    {
        /// <summary>
        /// Represents a DNS record with name, type, response data, TTL, and record type.
        /// Used for both questions and answers.
        /// </summary>
        public class DnsRecord
        {
            public string Name { get; set; } = "unknown";
            public string Type { get; set; } = "unknown";
            public string Response { get; set; } = "no response";
            public int TTL { get; set; } = 0;                 // ✅ Added field
            public string RecordType { get; set; } = "N/A";   // ✅ Added field
        }

        private string _sourceIP;
        private string _destinationIP;
        private DateTime _timestamp;
        private string _sessionID;
        private MemoryStream _bodyStream;
        private readonly object _lock = new object();
        private bool _disposed;

        private const int MaxPayloadSnippet = 128;

        private static readonly Regex SuspiciousDomainRegex = new Regex(
            @"(?:\btunnel\b|\battack\b|\bmalware\b|\bphish\b|\bexploit\b|\b\d{3,}\b|\b[a-f0-9]{16,}\b)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public DnsParser()
        {
            _bodyStream = new MemoryStream();
            Reset();
        }

        public void Reset()
        {
            lock (_lock)
            {
                _sourceIP = null;
                _destinationIP = null;
                _timestamp = DateTime.MinValue;
                _sessionID = null;
                _bodyStream?.SetLength(0);
            }
        }

        public (List<DnsRecord> Questions, List<DnsRecord> Answers) Parse(byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort, string sessionId = null)
        {
            var questions = new List<DnsRecord>();
            var answers = new List<DnsRecord>();

            if (payload == null || payload.Length == 0)
            {
                LogError("Empty or null payload", srcIp, dstIp);
                return (questions, answers);
            }

            lock (_lock)
            {
                _sourceIP = srcIp;
                _destinationIP = dstIp;
                _timestamp = DateTime.UtcNow;
                _sessionID = sessionId ?? $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";
                _bodyStream.SetLength(0);
                _bodyStream.Write(payload, 0, payload.Length);

                try
                {
                    if (payload.Length < 12)
                    {
                        LogToDb(true, "Invalid DNS packet: too short", questions, answers);
                        return (questions, answers);
                    }

                    ushort qCount = (ushort)((payload[4] << 8) | payload[5]);
                    ushort aCount = (ushort)((payload[6] << 8) | payload[7]);
                    int offset = 12;

                    // Parse questions
                    for (int i = 0; i < qCount; i++)
                    {
                        string qName = ParseDnsName(payload, ref offset);
                        string qTypeStr = "unknown";

                        if (offset + 4 <= payload.Length)
                        {
                            ushort qType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                            qTypeStr = qType switch
                            {
                                1 => "A",
                                2 => "NS",
                                5 => "CNAME",
                                12 => "PTR",
                                28 => "AAAA",
                                _ => qType.ToString()
                            };
                            offset += 4;
                        }

                        if (SuspiciousDomainRegex.IsMatch(qName))
                            LogSuspicious($"Suspicious domain in question: {qName}");

                        questions.Add(new DnsRecord
                        {
                            Name = qName,
                            Type = qTypeStr,
                            Response = "",
                            TTL = 0,
                            RecordType = "Question"
                        });
                    }

                    // Parse answers
                    for (int i = 0; i < aCount; i++)
                    {
                        string aName = ParseDnsName(payload, ref offset);
                        if (offset + 10 > payload.Length) break;

                        ushort rType = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                        offset += 2;

                        ushort rClass = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                        offset += 2;

                        int ttl = (payload[offset] << 24) | (payload[offset + 1] << 16) |
                                  (payload[offset + 2] << 8) | payload[offset + 3];
                        offset += 4;

                        ushort rdLength = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                        offset += 2;

                        string response = "unknown";
                        if (offset + rdLength <= payload.Length)
                        {
                            response = rType switch
                            {
                                1 => ParseIPv4Address(payload, offset),
                                28 => ParseIPv6Address(payload, offset),
                                5 or 12 => ParseDnsName(payload, ref offset),
                                _ => "unknown"
                            };
                            offset += rdLength;
                        }

                        if (SuspiciousDomainRegex.IsMatch(aName) || SuspiciousDomainRegex.IsMatch(response))
                            LogSuspicious($"Suspicious domain in answer: {aName}, Response: {response}");

                        string typeStr = rType switch
                        {
                            1 => "A",
                            2 => "NS",
                            5 => "CNAME",
                            12 => "PTR",
                            28 => "AAAA",
                            _ => rType.ToString()
                        };

                        answers.Add(new DnsRecord
                        {
                            Name = aName,
                            Type = typeStr,
                            Response = response,
                            TTL = ttl,
                            RecordType = "Answer"
                        });
                    }

                    LogToDb(false, $"Parsed DNS packet: {qCount} questions, {aCount} answers", questions, answers);
                }
                catch (Exception ex)
                {
                    LogToDb(true, $"DNS parse failed: {ex.Message}", questions, answers);
                }

                return (questions, answers);
            }
        }

        private string ParseDnsName(byte[] payload, ref int offset)
        {
            var sb = new StringBuilder();
            int originalOffset = offset;
            bool jumped = false;

            while (offset < payload.Length)
            {
                byte len = payload[offset++];
                if (len == 0) break;
                if ((len & 0xC0) == 0xC0 && offset < payload.Length)
                {
                    int pointer = ((len & 0x3F) << 8) | payload[offset++];
                    if (!jumped) originalOffset = offset;
                    offset = pointer;
                    jumped = true;
                    continue;
                }
                if (offset + len <= payload.Length)
                {
                    sb.Append(Encoding.ASCII.GetString(payload, offset, len));
                    sb.Append('.');
                    offset += len;
                }
                else break;
            }

            if (!jumped) originalOffset = offset;
            offset = originalOffset;
            return sb.Length > 0 ? sb.ToString(0, sb.Length - 1) : "unknown";
        }

        private string ParseIPv4Address(byte[] payload, int offset) =>
            offset + 4 <= payload.Length
                ? $"{payload[offset]}.{payload[offset + 1]}.{payload[offset + 2]}.{payload[offset + 3]}"
                : "unknown";

        private string ParseIPv6Address(byte[] payload, int offset) =>
            offset + 16 <= payload.Length
                ? new IPAddress(payload.Skip(offset).Take(16).ToArray()).ToString()
                : "unknown";

        private void LogSuspicious(string message) => LogToDb(true, message, null, null);
        private void LogError(string message, string srcIp, string dstIp) => LogToDb(true, $"ERROR: {message}", null, null);

        /// <summary>
        /// Log DNS data to database, including TTL and RecordType.
        /// </summary>
        private void LogToDb(bool isSuspicious, string message, List<DnsRecord> questions, List<DnsRecord> answers)
        {
            try
            {
                string payloadSnippet = _bodyStream?.Length > 0
                    ? BitConverter.ToString(_bodyStream.ToArray(), 0, (int)Math.Min(MaxPayloadSnippet, _bodyStream.Length))
                    : "-";

                string fingerprint = GeneratePayloadFingerprintSafe(_bodyStream?.ToArray());

                int logId = LogBLL.Insert(
                    _timestamp,
                    _sourceIP ?? "unknown",
                    _destinationIP ?? "unknown",
                    (int)(_bodyStream?.Length ?? 0),
                    isSuspicious,
                    "DNS",
                    "UDP",
                    0,
                    53,
                    (int)(_bodyStream?.Length ?? 0),
                    "-",
                    "in",
                    0,
                    0,
                    null,
                    $"{message}; Snippet={payloadSnippet}; fingerprint={fingerprint}"
                );

                if (logId > 0)
                {
                    if (questions != null)
                    {
                        foreach (var q in questions)
                            DnsLogDal.Insert(logId, q.Name, q.Type, q.Response, q.TTL, q.RecordType);
                    }

                    if (answers != null)
                    {
                        foreach (var a in answers)
                            DnsLogDal.Insert(logId, a.Name, a.Type, a.Response, a.TTL, a.RecordType);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DNS-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIP}, Dst={_destinationIP}");
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
