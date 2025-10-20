// =============================================
// CLASS SUMMARY: NtpParser
// =============================================
/// <summary>
/// NTP (Network Time Protocol) Protocol Parser - Analyzes NTP packets for security monitoring
/// Detects NTP-based attacks, protocol anomalies, and suspicious timing activities
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
    public class NtpParser : IDisposable
    {
        // =============================================
        // FIELD SUMMARY: Class member variables
        // =============================================
        private string _version;              // NTP protocol version (v3, v4, etc.)
        private string _mode;                 // NTP operation mode (Client, Server, Broadcast, etc.)
        private int _stratum;                 // NTP stratum level (clock accuracy indicator)
        private DateTime _transmitTimestamp;  // Packet transmission timestamp from NTP
        private decimal _offset;              // Time offset between client and server
        private string _sourceIP;             // Source IP address of NTP packet
        private string _destinationIP;        // Destination IP address of NTP packet
        private DateTime _timestamp;          // Packet arrival timestamp
        private string _sessionID;            // Unique session identifier
        private string _status;               // Parsing status (OK, Error, etc.)
        private MemoryStream _bodyStream;     // Stream for storing packet payload
        private readonly object _lock;        // Thread synchronization lock
        private bool _disposed;               // Disposal flag for resource management

        // =============================================
        // CONSTANT SUMMARY: Configuration constants
        // =============================================
        private const int MaxPayloadSnippet = 128;    // Maximum payload snippet length for logging
        private const int MaxPayloadSize = 1024 * 1024; // Maximum allowed payload size (1MB)

        // =============================================
        // STATIC FIELD SUMMARY: Shared resources
        // =============================================
        private static readonly HashSet<string> SuspiciousModes = new HashSet<string>(new[] { "SymmetricActive", "SymmetricPassive", "Broadcast" }, StringComparer.OrdinalIgnoreCase);
        // Suspicious NTP modes that could indicate amplification attacks or misconfigurations

        private static readonly Regex SuspiciousExtensionRegex = new Regex(
            @"(?:password|secret|key|auth|token|attack|exploit)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        // Pattern for detecting suspicious content in NTP extensions

        // =============================================
        // CONSTRUCTOR SUMMARY: NtpParser()
        // =============================================
        /// <summary>
        /// Initializes a new instance of NTP parser with default values
        /// Creates memory stream for payload storage and resets parser state
        /// </summary>
        public NtpParser()
        {
            _bodyStream = new MemoryStream();
            _lock = new object();
            Reset();
        }

        // =============================================
        // METHOD SUMMARY: Reset()
        // =============================================
        /// <summary>
        /// Resets all parser fields to their default values
        /// Clears the body stream and prepares parser for new packet
        /// Thread-safe operation using lock synchronization
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                _version = null;
                _mode = null;
                _stratum = 0;
                _transmitTimestamp = DateTime.MinValue;
                _offset = 0m;
                _sourceIP = null;
                _destinationIP = null;
                _timestamp = DateTime.UtcNow;
                _sessionID = null;
                _status = null;
                _bodyStream?.SetLength(0);
            }
        }

        // =============================================
        // METHOD SUMMARY: Parse()
        // =============================================
        /// <summary>
        /// Main packet parsing method - processes NTP packet data
        /// Validates input parameters, checks packet size, and initiates parsing
        /// Handles errors gracefully and logs parsing results to database
        /// </summary>
        /// <param name="payload">Raw packet bytes to parse</param>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        /// <param name="srcPort">Source port number</param>
        /// <param name="dstPort">Destination port number</param>
        /// <param name="sessionId">Optional session identifier</param>
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
            if (dstPort != 123 && srcPort != 123) // Standard NTP port
            {
                LogError($"Non-standard NTP port: Src={srcPort}, Dst={dstPort}", srcIp, dstIp);
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
                    ParseNtpPacket(payload);
                    LogToDb(false, $"Parsed NTP packet: Version={_version}, Mode={_mode}, Stratum={_stratum}, Offset={_offset}");
                }
                catch (Exception ex)
                {
                    LogToDb(true, $"NTP parse failed: {ex.Message}");
                }
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseNtpPacket()
        // =============================================
        /// <summary>
        /// Core NTP packet parsing logic - extracts and analyzes NTP packet structure
        /// Parses header fields including version, mode, stratum, and timestamps
        /// Performs security validation and suspicious activity detection
        /// </summary>
        /// <param name="payload">Raw packet bytes to analyze</param>
        private void ParseNtpPacket(byte[] payload)
        {
            if (payload.Length < 48) // Minimum NTP header size
            {
                LogSuspicious("Invalid NTP packet: too short");
                return;
            }

            // Extract LI (Leap Indicator), VN (Version Number), and Mode
            byte firstByte = payload[0];
            int leapIndicator = (firstByte >> 6) & 0x03;
            int versionNumber = (firstByte >> 3) & 0x07;
            int modeNumber = firstByte & 0x07;

            _version = versionNumber switch
            {
                3 => "NTPv3",
                4 => "NTPv4",
                _ => $"Unknown ({versionNumber})"
            };

            _mode = modeNumber switch
            {
                1 => "SymmetricActive",
                2 => "SymmetricPassive",
                3 => "Client",
                4 => "Server",
                5 => "Broadcast",
                6 => "Control",
                7 => "Private",
                _ => "Unknown"
            };

            // Extract Stratum
            _stratum = payload[1];

            // Extract Transmit Timestamp (bytes 40-47)
            if (payload.Length >= 48)
            {
                ulong timestampSeconds = BitConverter.ToUInt32(payload.Skip(40).Take(4).Reverse().ToArray(), 0);
                _transmitTimestamp = DateTime.UnixEpoch.AddSeconds(timestampSeconds);
            }
            else
            {
                _transmitTimestamp = DateTime.MinValue;
            }

            // Calculate Offset (simplified, based on transmit timestamp vs. current time)
            _offset = (decimal)(DateTime.UtcNow - _transmitTimestamp).TotalSeconds;

            // Validate and log suspicious conditions
            if (_stratum < 1 || _stratum > 15)
            {
                LogSuspicious($"Invalid stratum: {_stratum}");
            }
            if (SuspiciousModes.Contains(_mode))
            {
                LogSuspicious($"Suspicious mode: {_mode}");
            }
            if (Math.Abs(_offset) > 3600) // Offset > 1 hour
            {
                LogSuspicious($"Large offset detected: {_offset} seconds");
            }
            if (leapIndicator == 3) // Alarm condition
            {
                LogSuspicious("Leap indicator alarm condition detected");
            }

            // Check for suspicious extensions (if payload > 48 bytes)
            if (payload.Length > 48 && TryGetAsciiString(payload.Skip(48).ToArray(), out string extensionData))
            {
                if (SuspiciousExtensionRegex.IsMatch(extensionData))
                {
                    LogSuspicious($"Suspicious content in NTP extensions: {Truncate(extensionData, 200)}");
                }
            }

            _status = "OK";
        }

        // =============================================
        // METHOD SUMMARY: TryGetAsciiString()
        // =============================================
        /// <summary>
        /// Safely converts byte array to ASCII string with error handling
        /// Used for extracting readable text from NTP extension fields
        /// </summary>
        /// <param name="data">Input byte array to convert</param>
        /// <param name="result">Output parameter for converted string</param>
        /// <returns>True if conversion successful, false on encoding errors</returns>
        private bool TryGetAsciiString(byte[] data, out string result)
        {
            try
            {
                result = Encoding.ASCII.GetString(data);
                return true;
            }
            catch
            {
                result = null;
                return false;
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
        // METHOD SUMMARY: LogSuspicious()
        // =============================================
        /// <summary>
        /// Shortcut method for logging suspicious NTP activities
        /// Marks log entries as suspicious for security monitoring
        /// </summary>
        /// <param name="message">Suspicious activity description</param>
        private void LogSuspicious(string message) => LogToDb(true, message);

        // =============================================
        // METHOD SUMMARY: LogError()
        // =============================================
        /// <summary>
        /// Logs NTP parsing errors with context information
        /// Includes source and destination IP for error tracking
        /// </summary>
        /// <param name="message">Error message</param>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        private void LogError(string message, string srcIp, string dstIp) => LogToDb(true, $"ERROR: {message}");

        // =============================================
        // METHOD SUMMARY: LogToDb()
        // =============================================
        /// <summary>
        /// Comprehensive database logging method - stores parsed NTP data and analysis results
        /// Creates both general log entries and NTP-specific log records
        /// Includes payload fingerprints for correlation and tracking
        /// Handles timestamp validation and offset clamping for database compatibility
        /// </summary>
        /// <param name="isSuspicious">Flag indicating suspicious activity</param>
        /// <param name="message">Log message describing the event</param>
        private void LogToDb(bool isSuspicious, string message)
        {
            try
            {
                string payloadSnippet = _bodyStream?.Length > 0
                    ? BitConverter.ToString(_bodyStream.ToArray(), 0, (int)Math.Min(MaxPayloadSnippet, _bodyStream.Length))
                    : "-";
                string fingerprint = GeneratePayloadFingerprintSafe(_bodyStream?.ToArray());

                DateTime safeTimestamp = (_timestamp < new DateTime(1753, 1, 1) || _timestamp > new DateTime(9999, 12, 31, 23, 59, 59))
                    ? DateTime.UtcNow
                    : _timestamp;

                if (safeTimestamp != _timestamp)
                {
                    LogSuspicious("Invalid timestamp detected, corrected to current UTC time");
                }

                // Clamp offset to prevent overflow in DECIMAL(10,6)
                decimal clampedOffset = _offset;
                if (clampedOffset > 9999m) clampedOffset = 9999m;
                else if (clampedOffset < -9999m) clampedOffset = -9999m;

                int logId = LogBLL.Insert(
                    safeTimestamp,
                    _sourceIP ?? "unknown",
                    _destinationIP ?? "unknown",
                    (int)(_bodyStream?.Length ?? 0),
                    isSuspicious,
                    "NTP",
                    "UDP",
                    0,
                    123,
                    (int)(_bodyStream?.Length ?? 0),
                    _mode ?? "-",
                    "in",
                    0,
                    0,
                    null,
                    $"{message}; Snippet={payloadSnippet}; fingerprint={fingerprint}"
                );

                if (logId > 0)
                {
                    NtpLogBLL.Insert(
                        logId,
                        _version ?? "unknown",
                        _mode ?? "-",
                        _stratum,
                        _transmitTimestamp,
                        _sourceIP ?? "unknown",
                        _destinationIP ?? "unknown",
                        _timestamp,
                        _sessionID,
                        _status ?? "OK",
                        clampedOffset
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NTP-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIP}, Dst={_destinationIP}");
            }
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
        /// Converts parsed data to NtpLog entity for database storage
        /// Creates entity object with all extracted NTP information
        /// Thread-safe operation using lock synchronization
        /// </summary>
        /// <param name="logId">Parent log entry identifier</param>
        /// <returns>NtpLog entity ready for database insertion</returns>
        internal NtpLog ToEntity(int logId)
        {
            lock (_lock)
            {
                return new NtpLog(
                    ntpLogId: 0,
                    logId: logId,
                    version: _version ?? "unknown",
                    mode: _mode ?? "-",
                    stratum: _stratum,
                    transmitTimestamp: _transmitTimestamp,
                    sourceIP: _sourceIP ?? "unknown",
                    destinationIP: _destinationIP ?? "unknown",
                    timestamp: _timestamp,
                    sessionID: _sessionID,
                    status: _status ?? "unknown",
                    offset: _offset
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