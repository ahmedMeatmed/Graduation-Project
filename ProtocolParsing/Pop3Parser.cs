// =============================================
// CLASS SUMMARY: Pop3Parser
// =============================================
/// <summary>
/// POP3 (Post Office Protocol v3) Protocol Parser - Analyzes POP3 email protocol traffic
/// Detects unauthorized access attempts, suspicious commands, and malicious payloads
/// Implements IDisposable for proper resource management with configurable security patterns
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
    public class Pop3Parser : IDisposable
    {
        // =============================================
        // FIELD SUMMARY: Class member variables
        // =============================================
        private string _command;              // POP3 command (USER, PASS, RETR, etc.)
        private string _username;             // Extracted username from USER command
        private string _responseCode;         // Server response code (+OK, -ERR)
        private int _messageSize;             // Size of retrieved message
        private string _sourceIP;             // Source IP address of POP3 traffic
        private string _destinationIP;        // Destination IP address (mail server)
        private DateTime _timestamp;          // Packet timestamp
        private string _sessionID;            // Unique session identifier
        private string _status;               // Parsing status (OK, ERR, etc.)
        private int _attemptCount;            // Authentication attempt counter
        private MemoryStream _bodyStream;     // Stream for storing email body content
        private readonly object _lock;        // Thread synchronization lock
        private bool _disposed;               // Disposal flag for resource management

        // =============================================
        // CONSTANT SUMMARY: Configuration constants
        // =============================================
        private const int MaxPayloadSnippet = 64;     // Maximum payload snippet length for logging

        // =============================================
        // STATIC FIELD SUMMARY: Default security patterns
        // =============================================
        private static readonly List<string> DefaultSuspiciousCommands = new List<string> { "USER", "PASS", "RETR", "DELE", "TOP" };
        // Default list of sensitive POP3 commands to monitor

        private static readonly List<Regex> SuspiciousPayloadPatterns = new List<Regex>
        {
            new Regex(@"(?:password|passwd|secret|confidential|admin|root|nmap|hydra|sqlmap|union\s*select|\.\./|\<script\>)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)
        };
        // Default regex patterns for detecting malicious content in email bodies

        private readonly List<string> _suspiciousCommands; // Configurable suspicious commands list

        // =============================================
        // CONSTRUCTOR SUMMARY: Pop3Parser()
        // =============================================
        /// <summary>
        /// Initializes POP3 parser with configurable security patterns
        /// Creates memory stream for payload storage and sets up detection rules
        /// </summary>
        /// <param name="suspiciousCommands">Custom list of suspicious POP3 commands</param>
        /// <param name="suspiciousPayloadPatterns">Custom regex patterns for payload analysis</param>
        public Pop3Parser(IEnumerable<string> suspiciousCommands = null, IEnumerable<string> suspiciousPayloadPatterns = null)
        {
            _bodyStream = new MemoryStream();
            _lock = new object();

            // Initialize suspicious commands with custom list or defaults
            _suspiciousCommands = suspiciousCommands != null && suspiciousCommands.Any()
                ? new List<string>(suspiciousCommands)
                : DefaultSuspiciousCommands;

            // Add custom payload patterns if provided
            if (suspiciousPayloadPatterns?.Any() == true)
            {
                lock (_lock)
                {
                    foreach (var pattern in suspiciousPayloadPatterns)
                    {
                        if (!string.IsNullOrWhiteSpace(pattern))
                            SuspiciousPayloadPatterns.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled));
                    }
                }
            }
            Reset();
        }

        // =============================================
        // METHOD SUMMARY: Reset()
        // =============================================
        /// <summary>
        /// Resets all parser fields to default values for new session
        /// Clears body stream and resets counters while maintaining configuration
        /// Thread-safe operation using lock synchronization
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                _command = null;
                _username = null;
                _responseCode = null;
                _messageSize = 0;
                _sourceIP = null;
                _destinationIP = null;
                _timestamp = DateTime.UtcNow;
                _sessionID = null;
                _status = null;
                _attemptCount = 0;
                _bodyStream?.SetLength(0);
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseCommand()
        // =============================================
        /// <summary>
        /// Parses individual POP3 command lines from client to server
        /// Extracts commands, usernames, and tracks authentication attempts
        /// Detects suspicious commands based on configured patterns
        /// </summary>
        /// <param name="commandLine">Raw command line string to parse</param>
        /// <param name="srcIp">Source IP address (client)</param>
        /// <param name="dstIp">Destination IP address (server)</param>
        /// <param name="sessionId">Session identifier for correlation</param>
        /// <param name="timestamp">Optional timestamp (uses current UTC if null)</param>
        /// <param name="dstPort">Destination port (default 110)</param>
        public void ParseCommand(string commandLine, string srcIp, string dstIp, string sessionId, DateTime? timestamp = null, int dstPort = 110)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                LogError($"Empty or null command line. Src={srcIp}, Dst={dstIp}", srcIp, dstIp);
                return;
            }
            if (!IsValidIPAddress(srcIp) || !IsValidIPAddress(dstIp))
            {
                LogError($"Invalid IP address: Src={srcIp}, Dst={dstIp}", srcIp, dstIp);
                return;
            }
            if (dstPort != 110)
            {
                LogError($"Non-standard POP3 port: {dstPort}", srcIp, dstIp);
            }
            lock (_lock)
            {
                _timestamp = timestamp?.ToUniversalTime() ?? DateTime.UtcNow;
                _sourceIP = srcIp;
                _destinationIP = dstIp;
                _sessionID = sessionId;
                var parts = commandLine.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) return;
                _command = parts[0].ToUpperInvariant();
                if (_command == "USER" && parts.Length > 1) _username = parts[1].Trim();
                if (_command == "PASS") _attemptCount++;
                if (_command == "RETR" || _command == "TOP") _bodyStream.SetLength(0);
                if (_suspiciousCommands.Contains(_command, StringComparer.OrdinalIgnoreCase))
                {
                    LogSuspicious($"Suspicious command detected: {_command}");
                }
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseResponse()
        // =============================================
        /// <summary>
        /// Parses POP3 server response lines (+OK/-ERR)
        /// Extracts status codes, message sizes, and detects error conditions
        /// Automatically logs suspicious error responses
        /// </summary>
        /// <param name="responseLine">Server response line to parse</param>
        public void ParseResponse(string responseLine)
        {
            if (string.IsNullOrWhiteSpace(responseLine))
            {
                LogError($"Empty or null response line. Src={_sourceIP}, Dst={_destinationIP}", _sourceIP, _destinationIP);
                return;
            }
            lock (_lock)
            {
                if (responseLine.StartsWith("+OK", StringComparison.OrdinalIgnoreCase))
                {
                    _status = "OK";
                    var match = Regex.Match(responseLine, @"\+OK\s+(\d+)");
                    if (match.Success && int.TryParse(match.Groups[1].Value, out int size)) _messageSize = size;
                }
                else if (responseLine.StartsWith("-ERR", StringComparison.OrdinalIgnoreCase))
                {
                    _status = "ERR";
                    LogSuspicious($"Error response received: {responseLine}");
                }
                else
                {
                    LogError($"Unrecognized response format: {responseLine}", _sourceIP, _destinationIP);
                }
                _responseCode = _status;
                LogToDb(false, $"Parsed POP3 response: Status={_status}, MessageSize={_messageSize}");
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseBody()
        // =============================================
        /// <summary>
        /// Analyzes email body content for RETR and TOP commands
        /// Performs security scanning using regex patterns on ASCII content
        /// Generates payload fingerprints for tracking and correlation
        /// </summary>
        /// <param name="bodyData">Raw email body data bytes</param>
        public void ParseBody(byte[] bodyData)
        {
            if (bodyData == null || bodyData.Length == 0) return;
            if (bodyData.Length > 1024 * 1024) // Limit to 1MB
            {
                LogError($"Payload too large: {bodyData.Length} bytes", _sourceIP, _destinationIP);
                return;
            }
            lock (_lock)
            {
                if (_command == "RETR" || _command == "TOP")
                {
                    _bodyStream.Write(bodyData, 0, bodyData.Length);
                    if (TryGetAsciiString(bodyData, out string ascii))
                    {
                        foreach (var pattern in SuspiciousPayloadPatterns)
                        {
                            if (pattern.IsMatch(ascii))
                            {
                                LogSuspicious($"Suspicious payload pattern matched: {pattern}");
                                break;
                            }
                        }
                    }
                    string fingerprint = GeneratePayloadFingerprint(bodyData);
                    if (!string.IsNullOrEmpty(fingerprint))
                    {
                        LogToDb(true, $"Payload fingerprint generated: {fingerprint}");
                    }
                }
            }
        }

        // =============================================
        // METHOD SUMMARY: Parse() - Main entry point
        // =============================================
        /// <summary>
        /// Main packet parsing method - processes raw POP3 protocol data
        /// Automatically distinguishes between commands and responses
        /// Handles multi-line protocols and coordinates command/response/body parsing
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
            if (!IsValidIPAddress(srcIp) || !IsValidIPAddress(dstIp)) return;
            try
            {
                lock (_lock)
                {
                    _sessionID = sessionId ?? $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";
                    _sourceIP = srcIp;
                    _destinationIP = dstIp;
                    _timestamp = DateTime.UtcNow;
                    if (!TryGetAsciiString(payload, out string ascii))
                    {
                        LogError("Invalid payload encoding", srcIp, dstIp);
                        return;
                    }
                    var lines = ascii.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                    foreach (var line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        if (line.StartsWith("+OK", StringComparison.OrdinalIgnoreCase) ||
                            line.StartsWith("-ERR", StringComparison.OrdinalIgnoreCase))
                        {
                            ParseResponse(line);
                        }
                        else
                        {
                            ParseCommand(line, srcIp, dstIp, _sessionID, _timestamp, dstPort);
                        }
                    }
                    if ((_command == "RETR" || _command == "TOP") && payload.Length > 0)
                    {
                        ParseBody(payload);
                    }
                }
            }
            catch (Exception ex)
            {
                LogToDb(true, $"POP3 parse failed: {ex.Message}");
            }
        }

        // =============================================
        // METHOD SUMMARY: TryGetAsciiString()
        // =============================================
        /// <summary>
        /// Safely converts byte array to ASCII string with error handling
        /// Used for extracting readable text from protocol payloads
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
        // METHOD SUMMARY: GeneratePayloadFingerprint()
        // =============================================
        /// <summary>
        /// Generates SHA-256 hash fingerprint of payload for correlation
        /// Creates unique identifier for email content tracking
        /// </summary>
        /// <param name="payload">Payload bytes to fingerprint</param>
        /// <returns>SHA-256 hash string or null on error</returns>
        private string GeneratePayloadFingerprint(byte[] payload)
        {
            try
            {
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(payload);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        // =============================================
        // METHOD SUMMARY: LogSuspicious()
        // =============================================
        /// <summary>
        /// Shortcut method for logging suspicious POP3 activities
        /// Marks log entries as suspicious for security monitoring
        /// </summary>
        /// <param name="message">Suspicious activity description</param>
        private void LogSuspicious(string message) => LogToDb(true, message);

        // =============================================
        // METHOD SUMMARY: LogError()
        // =============================================
        /// <summary>
        /// Logs POP3 parsing errors with context information
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
        /// Comprehensive database logging method - stores parsed POP3 data and analysis results
        /// Creates both general log entries and POP3-specific log records
        /// Includes authentication attempt counting and payload analysis results
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
                    _bodyStream?.Length ?? 0,
                    isSuspicious,
                    "POP3",
                    "TCP",
                    0,
                    110,
                    _bodyStream?.Length ?? 0,
                    _command ?? "-",
                    "in",
                    _attemptCount,
                    0,
                    null,
                    $"{message}; PayloadSnippet={payloadSnippet}"
                );
                if (logId > 0)
                {
                    Pop3LogDal.Insert(
                        logId,
                        _command,
                        _username,
                        _responseCode,
                        _messageSize,
                        _sourceIP,
                        _destinationIP,
                        _timestamp,
                        _sessionID,
                        _status,
                        _attemptCount
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[POP3-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIP}, Dst={_destinationIP}");
            }
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
        /// Converts parsed data to Pop3Log entity for database storage
        /// Creates entity object with all extracted POP3 information
        /// Thread-safe operation using lock synchronization
        /// </summary>
        /// <param name="logId">Parent log entry identifier</param>
        /// <returns>Pop3Log entity ready for database insertion</returns>
        internal Pop3Log ToEntity(int logId)
        {
            lock (_lock)
            {
                return new Pop3Log(
                    pop3LogId: 0,
                    logId: logId,
                    command: _command,
                    username: _username,
                    responseCode: _responseCode,
                    messageSize: _messageSize,
                    sourceIP: _sourceIP,
                    destinationIP: _destinationIP,
                    timestamp: _timestamp,
                    sessionID: _sessionID,
                    status: _status,
                    attemptCount: _attemptCount
                );
            }
        }

        // =============================================
        // PROPERTY SUMMARY: Body
        // =============================================
        /// <summary>
        /// Read-only property providing access to stored email body content
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