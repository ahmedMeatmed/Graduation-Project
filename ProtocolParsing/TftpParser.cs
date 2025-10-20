// =============================================
// CLASS SUMMARY: TftpParser
// =============================================
/// <summary>
/// TFTP (Trivial File Transfer Protocol) Parser - Analyzes TFTP file transfer protocol traffic
/// Detects unauthorized file transfers, suspicious filenames, and potential data exfiltration
/// Implements IDisposable for proper resource management with comprehensive security monitoring
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
    public class TftpParser : IDisposable
    {
        // =============================================
        // FIELD SUMMARY: Class member variables
        // =============================================
        private string _operation;            // TFTP operation type (RRQ, WRQ, DATA, ACK, ERROR)
        private string _filename;             // Name of file being transferred
        private int _transferSize;            // Size of file transfer in bytes
        private string _sourceIP;             // Source IP address of TFTP traffic
        private string _destinationIP;        // Destination IP address (TFTP server/client)
        private DateTime _timestamp;          // Packet timestamp
        private string _sessionID;            // Unique session identifier
        private string _status;               // Parsing status (OK, ERROR, etc.)
        private MemoryStream _bodyStream;     // Stream for storing TFTP payload
        private readonly object _lock;        // Thread synchronization lock
        private bool _disposed;               // Disposal flag for resource management

        // =============================================
        // CONSTANT SUMMARY: Configuration constants
        // =============================================
        private const int MaxPayloadSnippet = 128;    // Maximum payload snippet length for logging
        private const int MaxPayloadSize = 1024 * 1024; // Maximum allowed payload size (1MB)

        // =============================================
        // STATIC FIELD SUMMARY: Security patterns
        // =============================================
        private static readonly HashSet<string> ValidOperations = new HashSet<string>(new[]
        {
            "RRQ", "WRQ", "DATA", "ACK", "ERROR"
        }, StringComparer.OrdinalIgnoreCase);
        /// <summary>
        /// Valid TFTP operation codes according to RFC 1350
        /// RRQ=Read Request, WRQ=Write Request, DATA=Data Transfer, ACK=Acknowledgment, ERROR=Error
        /// </summary>

        private static readonly Regex SuspiciousFilenameRegex = new Regex(
            @"(?:password|secret|key|auth|token|attack|exploit|admin|root|\.\.|\\|/)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        /// <summary>
        /// Regex pattern for detecting suspicious filenames in TFTP transfers
        /// Includes sensitive keywords and path traversal patterns
        /// </summary>

        // =============================================
        // CONSTRUCTOR SUMMARY: TftpParser()
        // =============================================
        /// <summary>
        /// Initializes a new instance of TFTP parser with default values
        /// Creates memory stream for payload storage and resets parser state
        /// </summary>
        public TftpParser()
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
                _operation = null;
                _filename = null;
                _transferSize = 0;
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
        /// Main TFTP packet parsing method - processes TFTP protocol traffic
        /// Validates input parameters, checks packet size, and initiates TFTP parsing
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
            if (dstPort != 69 && srcPort != 69) // Standard TFTP server port
            {
                LogError($"Non-standard TFTP port: Src={srcPort}, Dst={dstPort}", srcIp, dstIp);
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
                    ParseTftpPacket(payload);
                    LogToDb(false, $"Parsed TFTP packet: Operation={_operation}, Filename={Truncate(_filename, 200)}, TransferSize={_transferSize}");
                }
                catch (Exception ex)
                {
                    LogToDb(true, $"TFTP parse failed: {ex.Message}");
                }
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseTftpPacket()
        // =============================================
        /// <summary>
        /// Core TFTP packet parsing logic - extracts and analyzes TFTP packet structure
        /// Parses opcodes, filenames, transfer modes, and data blocks according to RFC 1350
        /// Performs security validation and suspicious activity detection
        /// </summary>
        /// <param name="payload">Raw packet bytes to analyze</param>
        private void ParseTftpPacket(byte[] payload)
        {
            if (payload.Length < 2) // Minimum TFTP header size (opcode)
            {
                LogSuspicious("Invalid TFTP packet: too short");
                return;
            }

            // Extract Opcode (bytes 0-1) - TFTP operation code
            ushort opcode = (ushort)((payload[0] << 8) | payload[1]);
            _operation = opcode switch
            {
                1 => "RRQ",      // Read Request (client downloads file)
                2 => "WRQ",      // Write Request (client uploads file)
                3 => "DATA",     // Data transfer block
                4 => "ACK",      // Acknowledgment of data block
                5 => "ERROR",    // Error response
                _ => $"Unknown ({opcode})"
            };

            int offset = 2;

            // Extract Filename and Mode for RRQ/WRQ (Read/Write Requests)
            if (_operation == "RRQ" || _operation == "WRQ")
            {
                // Filename extraction (null-terminated string)
                int filenameEnd = Array.IndexOf(payload, (byte)0, offset);
                if (filenameEnd < 0 || filenameEnd >= payload.Length)
                {
                    LogSuspicious("Invalid TFTP packet: missing or invalid filename");
                    return;
                }
                _filename = Encoding.ASCII.GetString(payload, offset, filenameEnd - offset);
                offset = filenameEnd + 1;

                // Transfer Mode extraction (null-terminated string)
                int modeEnd = Array.IndexOf(payload, (byte)0, offset);
                if (modeEnd < 0 || modeEnd >= payload.Length)
                {
                    LogSuspicious("Invalid TFTP packet: missing or invalid mode");
                    return;
                }
                string mode = Encoding.ASCII.GetString(payload, offset, modeEnd - offset);
                offset = modeEnd + 1;

                // Parse TFTP Options (RFC 2347, 2348) if present
                ParseTftpOptions(payload, ref offset);
            }
            else if (_operation == "DATA")
            {
                // Extract Block Number and Data Size for DATA packets
                if (offset + 2 <= payload.Length)
                {
                    ushort blockNumber = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    offset += 2;
                    // Data size (remaining bytes in packet)
                    _transferSize = payload.Length - offset;
                }
            }
            else if (_operation == "ACK")
            {
                // Extract Block Number for ACK packets
                if (offset + 2 <= payload.Length)
                {
                    ushort blockNumber = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    offset += 2;
                    _transferSize = 0; // No data in ACK packets
                }
            }
            else if (_operation == "ERROR")
            {
                // Extract Error Code and Message for ERROR packets
                if (offset + 2 <= payload.Length)
                {
                    ushort errorCode = (ushort)((payload[offset] << 8) | payload[offset + 1]);
                    offset += 2;
                    // Error Message extraction (null-terminated string)
                    int errorMsgEnd = Array.IndexOf(payload, (byte)0, offset);
                    if (errorMsgEnd >= 0 && errorMsgEnd < payload.Length)
                    {
                        string errorMsg = Encoding.ASCII.GetString(payload, offset, errorMsgEnd - offset);
                        LogSuspicious($"TFTP error: Code={errorCode}, Message={Truncate(errorMsg, 200)}");
                    }
                    _transferSize = 0; // No data in ERROR packets
                }
            }

            // Security validation and suspicious condition logging
            PerformSecurityValidation();

            _status = "OK";
        }

        // =============================================
        // METHOD SUMMARY: ParseTftpOptions()
        // =============================================
        /// <summary>
        /// Parses TFTP options according to RFC 2347 and RFC 2348
        /// Extracts transfer size (tsize), block size (blksize), and other options
        /// Updates transfer size information for security monitoring
        /// </summary>
        /// <param name="payload">Raw packet bytes to analyze</param>
        /// <param name="offset">Current parsing offset (updated by reference)</param>
        private void ParseTftpOptions(byte[] payload, ref int offset)
        {
            // Parse TFTP options (tsize, blksize, timeout, etc.)
            while (offset < payload.Length)
            {
                int optionEnd = Array.IndexOf(payload, (byte)0, offset);
                if (optionEnd < 0 || optionEnd >= payload.Length) break;
                string optionName = Encoding.ASCII.GetString(payload, offset, optionEnd - offset);
                offset = optionEnd + 1;

                int valueEnd = Array.IndexOf(payload, (byte)0, offset);
                if (valueEnd < 0 || valueEnd >= payload.Length) break;
                string optionValue = Encoding.ASCII.GetString(payload, offset, valueEnd - offset);
                offset = valueEnd + 1;

                // Process specific TFTP options
                if (optionName.Equals("tsize", StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(optionValue, out int tsize))
                    {
                        _transferSize = tsize;
                    }
                }
                // Additional options can be processed here (blksize, timeout, etc.)
            }
        }

        // =============================================
        // METHOD SUMMARY: PerformSecurityValidation()
        // =============================================
        /// <summary>
        /// Performs security validation on parsed TFTP data
        /// Checks for suspicious filenames, invalid operations, and anomalous transfer sizes
        /// Logs security events for monitoring and alerting
        /// </summary>
        private void PerformSecurityValidation()
        {
            // Validate TFTP operation codes
            if (!ValidOperations.Contains(_operation))
            {
                LogSuspicious($"Invalid or unknown operation: {_operation}");
            }

            // Validate filename for suspicious patterns
            if (string.IsNullOrEmpty(_filename))
            {
                LogSuspicious("Empty filename in RRQ/WRQ");
                _filename = "unknown";
            }
            else if (SuspiciousFilenameRegex.IsMatch(_filename))
            {
                LogSuspicious($"Suspicious filename: {Truncate(_filename, 200)}");
            }

            // Validate transfer size boundaries
            if (_transferSize < 0 || _transferSize > MaxPayloadSize)
            {
                LogSuspicious($"Suspicious transfer size: {_transferSize} bytes");
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
        /// Shortcut method for logging suspicious TFTP activities
        /// Marks log entries as suspicious for security monitoring
        /// </summary>
        /// <param name="message">Suspicious activity description</param>
        private void LogSuspicious(string message) => LogToDb(true, message);

        // =============================================
        // METHOD SUMMARY: LogError()
        // =============================================
        /// <summary>
        /// Logs TFTP parsing errors with context information
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
        /// Comprehensive database logging method - stores parsed TFTP data and analysis results
        /// Creates both general log entries and TFTP-specific log records
        /// Includes payload fingerprints for correlation and tracking
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
                int logId = LogBLL.Insert(
                    safeTimestamp,
                    _sourceIP ?? "unknown",
                    _destinationIP ?? "unknown",
                    (int)(_bodyStream?.Length ?? 0),
                    isSuspicious,
                    "TFTP",
                    "UDP",
                    0,
                    69,
                    (int)(_bodyStream?.Length ?? 0),
                    _operation ?? "-",
                    "in",
                    0,
                    0,
                    null,
                    $"{message}; Snippet={payloadSnippet}; fingerprint={fingerprint}"
                );
                if (logId > 0)
                {
                    TftpLogBLL.Insert(
                        logId,
                        _operation ?? "unknown",
                        _filename ?? "unknown",
                        _transferSize,
                        _sourceIP ?? "unknown",
                        _destinationIP ?? "unknown",
                        _timestamp,
                        _sessionID,
                        _status ?? "OK"
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TFTP-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIP}, Dst={_destinationIP}");
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
        /// Converts parsed data to TftpLog entity for database storage
        /// Creates entity object with all extracted TFTP information
        /// Thread-safe operation using lock synchronization
        /// </summary>
        /// <param name="logId">Parent log entry identifier</param>
        /// <returns>TftpLog entity ready for database insertion</returns>
        internal TftpLog ToEntity(int logId)
        {
            lock (_lock)
            {
                return new TftpLog(
                    tftpLogId: 0,
                    logId: logId,
                    operation: _operation ?? "unknown",
                    filename: _filename ?? "unknown",
                    transferSize: _transferSize,
                    sourceIp: _sourceIP ?? "unknown",
                    destinationIp: _destinationIP ?? "unknown",
                    timestamp: _timestamp,
                    sessionId: _sessionID,
                    status: _status ?? "unknown"
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