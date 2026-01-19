// =============================================
// CLASS SUMMARY: SnmpParser
// =============================================
/// <summary>
/// SNMP (Simple Network Management Protocol) Parser - Analyzes network management protocol traffic
/// Detects unauthorized SNMP access, suspicious OID queries, and information leakage attempts
/// Implements IDisposable for proper resource management with configurable security thresholds
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
    public class SnmpParser : IDisposable
    {
        // =============================================
        // FIELD SUMMARY: Class member variables
        // =============================================
        private string _version;              // SNMP protocol version (v1, v2c, v3)
        private string _community;            // SNMP community string (authentication)
        private string _requestType;          // SNMP operation type (GET, SET, GETBULK, etc.)
        private List<string> _oids;           // List of OIDs (Object Identifiers) being queried
        private string _value;                // SNMP response value or SET data
        private string _sourceIP;             // Source IP address of SNMP traffic
        private string _destinationIP;        // Destination IP address (SNMP manager/agent)
        private DateTime _timestamp;          // Packet timestamp
        private string _sessionID;            // Unique session identifier
        private string _status;               // Parsing status (REQUEST, RESPONSE, ERROR)
        private MemoryStream _bodyStream;     // Stream for storing raw SNMP payload
        private readonly object _lock;        // Thread synchronization lock
        private bool _disposed;               // Disposal flag for resource management

        // =============================================
        // CONSTANT SUMMARY: Configuration thresholds
        // =============================================
        private const int MaxPayloadSnippet = 128;        // Maximum payload snippet length for logging
        private const int BulkOidThreshold = 5;           // Threshold for bulk request detection
        private const int LargePayloadThreshold = 4096;   // Threshold for large payload detection

        // =============================================
        // STATIC FIELD SUMMARY: Default security patterns
        // =============================================
        private static readonly HashSet<string> DefaultSuspiciousCommunities = new HashSet<string>(new[] { "public", "private", "admin" }, StringComparer.OrdinalIgnoreCase);
        /// <summary>
        /// Default list of weak/default SNMP community strings that trigger security alerts
        /// </summary>

        private static readonly HashSet<string> DefaultSuspiciousRequestTypes = new HashSet<string>(new[] { "SET", "WALK", "BULKGET", "GETBULK" }, StringComparer.OrdinalIgnoreCase);
        /// <summary>
        /// Default list of sensitive SNMP operations that require monitoring
        /// </summary>

        private static readonly Regex SuspiciousValueRegex = new Regex(
            @"(?:password|passwd|secret|token|key|private|passwd:|root:|/etc/passwd|nmap|hydra|sqlmap|metasploit)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        /// <summary>
        /// Regex pattern for detecting sensitive data or attack tools in SNMP values
        /// </summary>

        private readonly HashSet<string> _suspiciousCommunities; // Configurable suspicious communities
        private readonly HashSet<string> _suspiciousRequestTypes; // Configurable suspicious request types

        // =============================================
        // CONSTRUCTOR SUMMARY: SnmpParser()
        // =============================================
        /// <summary>
        /// Initializes SNMP parser with configurable security patterns and thresholds
        /// Creates memory stream for payload storage and sets up detection rules
        /// </summary>
        /// <param name="suspiciousCommunities">Custom list of suspicious SNMP community strings</param>
        /// <param name="suspiciousRequestTypes">Custom list of suspicious SNMP operation types</param>
        public SnmpParser(IEnumerable<string> suspiciousCommunities = null, IEnumerable<string> suspiciousRequestTypes = null)
        {
            _bodyStream = new MemoryStream();
            _oids = new List<string>();
            _lock = new object();

            // Initialize suspicious communities with custom list or defaults
            _suspiciousCommunities = suspiciousCommunities != null && suspiciousCommunities.Any()
                ? new HashSet<string>(suspiciousCommunities, StringComparer.OrdinalIgnoreCase)
                : DefaultSuspiciousCommunities;

            // Initialize suspicious request types with custom list or defaults
            _suspiciousRequestTypes = suspiciousRequestTypes != null && suspiciousRequestTypes.Any()
                ? new HashSet<string>(suspiciousRequestTypes, StringComparer.OrdinalIgnoreCase)
                : DefaultSuspiciousRequestTypes;

            Reset();
        }

        // =============================================
        // METHOD SUMMARY: Reset()
        // =============================================
        /// <summary>
        /// Resets all parser fields to default values for new session
        /// Clears OID list, body stream, and resets state while maintaining configuration
        /// Thread-safe operation using lock synchronization
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                _version = null;
                _community = null;
                _requestType = null;
                _oids.Clear();
                _value = null;
                _sourceIP = null;
                _destinationIP = null;
                _timestamp = DateTime.UtcNow;
                _sessionID = null;
                _status = null;
                _bodyStream?.SetLength(0);
            }
        }

        // =============================================
        // METHOD SUMMARY: Parse() - Main entry point
        // =============================================
        /// <summary>
        /// Main SNMP packet parsing method - processes SNMP protocol traffic
        /// Validates input parameters, checks packet size, and initiates ASN.1 parsing
        /// Handles both SNMP requests and responses with security analysis
        /// </summary>
        /// <param name="payload">Raw packet bytes to parse</param>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        /// <param name="srcPort">Source port number</param>
        /// <param name="dstPort">Destination port number</param>
        /// <param name="sessionId">Optional session identifier</param>
        public void Parse(byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort, string sessionId = null)
        {
            if (payload == null || payload.Length == 0) return;
            if (payload.Length > 1024 * 1024) // Limit to 1MB
            {
                LogError($"Payload too large: {payload.Length} bytes", srcIp, dstIp);
                return;
            }
            if (!IsValidIPAddress(srcIp) || !IsValidIPAddress(dstIp)) return;
            if (dstPort != 161 && srcPort != 162) // Standard SNMP ports
            {
                LogError($"Non-standard SNMP port: Src={srcPort}, Dst={dstPort}", srcIp, dstIp);
            }
            try
            {
                lock (_lock)
                {
                    _sessionID = sessionId ?? $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";
                    _sourceIP = srcIp;
                    _destinationIP = dstIp;
                    _timestamp = DateTime.UtcNow;
                    // Simulated ASN.1 parsing (replace with SharpSnmpLib in production)
                    (string version, string community, string requestType, List<string> oids, string value, bool isRequest) = ParseSnmpPayload(payload);
                    if (isRequest)
                    {
                        ParseRequest(version, community, requestType, oids, srcIp, dstIp, _sessionID, _timestamp, payload);
                    }
                    else
                    {
                        ParseResponse(value, "OK", payload);
                    }
                }
            }
            catch (Exception ex)
            {
                LogToDb(true, $"SNMP parse failed: {ex.Message}");
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseSnmpPayload()
        // =============================================
        /// <summary>
        /// Simulates ASN.1 BER decoding for SNMP packets (simplified implementation)
        /// Extracts SNMP version, community string, request type, OIDs, and values
        /// Note: Production implementation should use proper ASN.1 parser like SharpSnmpLib
        /// </summary>
        /// <param name="payload">Raw SNMP packet bytes to analyze</param>
        /// <returns>Tuple containing parsed SNMP components and request/response flag</returns>
        private (string version, string community, string requestType, List<string> oids, string value, bool isRequest) ParseSnmpPayload(byte[] payload)
        {
            // Simulated ASN.1 parsing (simplified for example)
            string ascii = Encoding.ASCII.GetString(payload);
            bool isRequest = ascii.Contains("GET") || ascii.Contains("SET") || ascii.Contains("GETNEXT") || ascii.Contains("GETBULK");
            string version = ascii.Contains("v1") ? "SNMPv1" : ascii.Contains("v2c") ? "SNMPv2c" : "unknown";
            string community = ascii.Contains("public") ? "public" : ascii.Contains("private") ? "private" : "unknown";
            string requestType = isRequest ? (ascii.Contains("SET") ? "SET" : ascii.Contains("GETBULK") ? "GETBULK" : ascii.Contains("GETNEXT") ? "GETNEXT" : "GET") : "-";
            var oids = new List<string>();
            var oidMatch = Regex.Match(ascii, @"(\d+\.\d+\.\d+\.\d+\.\d+\.\d+\.\d+\.\d+)");
            if (oidMatch.Success) oids.Add(oidMatch.Value);
            string value = isRequest ? null : ascii.Length > 50 ? ascii.Substring(0, 50) : ascii;
            return (version, community, requestType, oids, value, isRequest);
        }

        // =============================================
        // METHOD SUMMARY: ParseRequest()
        // =============================================
        /// <summary>
        /// Processes SNMP request data and performs security analysis
        /// Validates community strings, request types, and OID patterns
        /// Detects bulk requests, suspicious operations, and weak authentication
        /// </summary>
        /// <param name="version">SNMP protocol version</param>
        /// <param name="community">SNMP community string</param>
        /// <param name="requestType">SNMP operation type</param>
        /// <param name="oids">List of OIDs being queried</param>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        /// <param name="sessionId">Session identifier</param>
        /// <param name="timestamp">Optional timestamp</param>
        /// <param name="rawPayload">Raw packet bytes for fingerprinting</param>
        public void ParseRequest(string version, string community, string requestType, IEnumerable<string> oids,
                                string srcIp, string dstIp, string sessionId, DateTime? timestamp = null, byte[] rawPayload = null)
        {
            if (string.IsNullOrWhiteSpace(requestType)) return;
            if (!IsValidIPAddress(srcIp) || !IsValidIPAddress(dstIp)) return;
            lock (_lock)
            {
                _version = string.IsNullOrWhiteSpace(version) ? "SNMPv2c" : version;
                _community = string.IsNullOrWhiteSpace(community) ? "-" : community;
                _requestType = requestType.ToUpperInvariant();
                _oids = (oids ?? Enumerable.Empty<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToList();
                _sourceIP = srcIp;
                _destinationIP = dstIp;
                _sessionID = sessionId;
                _timestamp = timestamp?.ToUniversalTime() ?? DateTime.UtcNow;
                _status = "REQUEST";
                _bodyStream.SetLength(0);
                if (rawPayload != null && rawPayload.Length > 0) _bodyStream.Write(rawPayload, 0, rawPayload.Length);

                // Security analysis for SNMP requests
                if (_suspiciousCommunities.Contains(_community))
                {
                    LogToDb(true, $"Suspicious community string: {_community}");
                }
                if (_suspiciousRequestTypes.Contains(_requestType))
                {
                    LogToDb(true, $"Suspicious request type: {_requestType}");
                }
                if (IsLikelyBulkRequest(_oids))
                {
                    LogToDb(true, $"Bulk-like request (OID count={_oids.Count})");
                }
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseResponse()
        // =============================================
        /// <summary>
        /// Processes SNMP response data and performs content analysis
        /// Scans response values for sensitive information and attack indicators
        /// Monitors payload size and response patterns for anomalies
        /// </summary>
        /// <param name="value">SNMP response value data</param>
        /// <param name="responseCode">SNMP response status code</param>
        /// <param name="payload">Raw response payload for analysis</param>
        public void ParseResponse(string value, string responseCode = "OK", byte[] payload = null)
        {
            lock (_lock)
            {
                _value = value ?? "-";
                _status = string.IsNullOrWhiteSpace(responseCode) ? "OK" : responseCode.ToUpperInvariant();
                if (payload != null && payload.Length > 0)
                {
                    _bodyStream.Write(payload, 0, payload.Length);
                }

                // Security analysis for SNMP responses
                if (!string.IsNullOrEmpty(_value) && SuspiciousValueRegex.IsMatch(_value))
                {
                    LogToDb(true, "Suspicious content in SNMP value (possible secrets/tools)");
                }
                if (_bodyStream.Length >= LargePayloadThreshold)
                {
                    LogToDb(true, $"Large SNMP payload: {_bodyStream.Length} bytes");
                }
                LogToDb(false, $"Parsed SNMP response: ValueSummary={Truncate(_value, 200)}");
            }
        }

        // =============================================
        // METHOD SUMMARY: IsLikelyBulkRequest()
        // =============================================
        /// <summary>
        /// Detects potential SNMP bulk requests based on OID count threshold
        /// Bulk requests can indicate network scanning or information harvesting
        /// </summary>
        /// <param name="oids">List of OIDs from SNMP request</param>
        /// <returns>True if request appears to be a bulk operation, false otherwise</returns>
        private bool IsLikelyBulkRequest(List<string> oids) => oids?.Count >= BulkOidThreshold;

        // =============================================
        // METHOD SUMMARY: LogSuspicious()
        // =============================================
        /// <summary>
        /// Shortcut method for logging suspicious SNMP activities
        /// Marks log entries as suspicious for security monitoring
        /// </summary>
        /// <param name="message">Suspicious activity description</param>
        private void LogSuspicious(string message) => LogToDb(true, message);

        // =============================================
        // METHOD SUMMARY: LogError()
        // =============================================
        /// <summary>
        /// Logs SNMP parsing errors with context information
        /// Includes source and destination IP for error tracking
        /// </summary>
        /// <param name="message">Error message</param>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        private void LogError(string message, string srcIp, string dstIp)
        {
            LogToDb(true, $"ERROR: {message}");
        }

        // =============================================
        // METHOD SUMMARY: LogToDb()
        // =============================================
        /// <summary>
        /// Comprehensive database logging method - stores parsed SNMP data and analysis results
        /// Creates both general log entries and SNMP-specific log records
        /// Includes OID tracking, payload fingerprinting, and security classification
        /// </summary>
        /// <param name="isSuspicious">Flag indicating suspicious activity</param>
        /// <param name="message">Log message describing the event</param>
        private void LogToDb(bool isSuspicious, string message)
        {
            try
            {
                string snippet = GetPayloadSnippet();
                string fingerprint = GeneratePayloadFingerprintSafe(_bodyStream?.ToArray());
                DateTime safeTimestamp = (_timestamp < new DateTime(1753, 1, 1) || _timestamp > new DateTime(9999, 12, 31, 23, 59, 59))
            ? DateTime.UtcNow
            : _timestamp;

                if (safeTimestamp != _timestamp)
                {
                    LogSuspicious("Invalid timestamp detected, corrected to current UTC time");
                }
                int logId = LogBLL.Insert(
                    safeTimestamp,
                    _sourceIP ?? "unknown",
                    _destinationIP ?? "unknown",
                    (int)(_bodyStream?.Length ?? 0),
                    isSuspicious,
                    "SNMP",
                    "UDP",
                    0,
                    161,
                    (int)(_bodyStream?.Length ?? 0),
                    _requestType ?? "-",
                    "in",
                    1,
                    0,
                    null,
                    $"{message}; OIDs={string.Join(",", _oids ?? Enumerable.Empty<string>())}; Snippet={snippet}; fingerprint={fingerprint}"
                );
                if (logId > 0)
                {
                    SnmpLogDal.Insert(
                        logId,
                        _version ?? "unknown",
                        _community ?? "-",
                        _oids != null && _oids.Count > 0 ? _oids.First() : "-",
                        _value ?? "-",
                        _sourceIP ?? "unknown",
                        _destinationIP ?? "unknown",
                        _timestamp,
                        _sessionID,
                        isSuspicious ? "SUSPICIOUS" : "OK",
                        _requestType ?? "-"
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SNMP-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIP}, Dst={_destinationIP}");
            }
        }

        // =============================================
        // METHOD SUMMARY: Truncate()
        // =============================================
        /// <summary>
        /// Utility method for safely truncating strings with ellipsis
        /// Prevents overly long strings in logs and database fields
        /// </summary>
        /// <param name="s">Input string to truncate</param>
        /// <param name="max">Maximum allowed length</param>
        /// <returns>Truncated string with ellipsis if needed</returns>
        private static string Truncate(string s, int max) => string.IsNullOrEmpty(s) ? s : s.Length <= max ? s : s.Substring(0, max) + "...";

        // =============================================
        // METHOD SUMMARY: GetPayloadSnippet()
        // =============================================
        /// <summary>
        /// Extracts hexadecimal snippet from payload for logging purposes
        /// Provides limited payload preview while maintaining performance
        /// </summary>
        /// <returns>Hexadecimal string representation of payload snippet</returns>
        private string GetPayloadSnippet()
        {
            try
            {
                if (_bodyStream == null || _bodyStream.Length == 0) return "-";
                var arr = _bodyStream.ToArray();
                int take = (int)Math.Min(MaxPayloadSnippet, arr.Length);
                return BitConverter.ToString(arr, 0, take);
            }
            catch { return "-"; }
        }

        // =============================================
        // METHOD SUMMARY: GeneratePayloadFingerprintSafe()
        // =============================================
        /// <summary>
        /// Generates SHA-256 hash fingerprint of payload for correlation
        /// Safe implementation with error handling for null or empty payloads
        /// </summary>
        /// <param name="payload">Packet payload bytes to fingerprint</param>
        /// <returns>SHA-256 hash string or null on error</returns>
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

        // =============================================
        // METHOD SUMMARY: IsValidIPAddress()
        // =============================================
        /// <summary>
        /// Validates IP address format using .NET IPAddress parser
        /// Ensures only properly formatted IP addresses are processed
        /// </summary>
        /// <param name="ip">IP address string to validate</param>
        /// <returns>True if valid IP address format, false otherwise</returns>
        private bool IsValidIPAddress(string ip) => !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

        // =============================================
        // METHOD SUMMARY: ToEntity()
        // =============================================
        /// <summary>
        /// Converts parsed data to SnmpLog entity for database storage
        /// Creates entity object with all extracted SNMP information
        /// Thread-safe operation using lock synchronization
        /// </summary>
        /// <param name="logId">Parent log entry identifier</param>
        /// <returns>SnmpLog entity ready for database insertion</returns>
        internal SnmpLog ToEntity(int logId)
        {
            lock (_lock)
            {
                return new SnmpLog(
                    snmpLogId: 0,
                    logId: logId,
                    version: _version ?? "unknown",
                    community: _community ?? "-",
                    oid: _oids != null && _oids.Count > 0 ? _oids.First() : "-",
                    value: _value ?? "-",
                    sourceIP: _sourceIP ?? "unknown",
                    destinationIP: _destinationIP ?? "unknown",
                    timestamp: _timestamp,
                    sessionID: _sessionID,
                    status: _status ?? "unknown",
                    requestType: _requestType ?? "-"
                );
            }
        }

        // =============================================
        // PROPERTY SUMMARY: Body
        // =============================================
        /// <summary>
        /// Read-only property providing access to raw packet payload
        /// Returns copy of stored body stream as byte array
        /// </summary>
        public byte[] Body => _bodyStream?.ToArray();

        // =============================================
        // METHOD SUMMARY: Dispose()
        // =============================================
        /// <summary>
        /// Implements IDisposable pattern for proper resource cleanup
        /// Disposes memory stream and marks instance as disposed
        /// Thread-safe disposal using lock synchronization
        /// </summary>
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