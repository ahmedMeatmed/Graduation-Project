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
    /// IMAP protocol parser for Intrusion Detection System
    /// 
    /// Main Responsibilities:
    /// - Parse and analyze IMAP (Internet Message Access Protocol) traffic
    /// - Monitor email client-server communications for security threats
    /// - Detect suspicious IMAP commands and authentication attempts
    /// - Analyze email content and attachments for malicious patterns
    /// - Track session activity and command sequences
    /// 
    /// IMAP Protocol Support:
    /// - Standard IMAP commands (LOGIN, SELECT, FETCH, STORE, APPEND, LOGOUT)
    /// - Email folder operations and message management
    /// - Authentication and session management
    /// - Email content retrieval and analysis
    /// 
    /// Security Detection Capabilities:
    /// - Suspicious command patterns and sequences
    /// - Authentication brute force attempts
    /// - Malicious payloads in email content
    /// - Sensitive information extraction attempts
    /// - Protocol anomalies and error conditions
    /// 
    /// Features:
    /// - Comprehensive IMAP command and response parsing
    /// - Configurable suspicious command detection
    /// - Payload fingerprinting for content correlation
    /// - Session tracking and attempt counting
    /// - Real-time threat detection and logging
    /// </summary>
    public class ImapParser : IDisposable
    {
        // IMAP protocol state and parsing results
        private string _command;
        private string _folder;
        private string _responseCode;
        private int _messageSize;
        private string _sourceIP;
        private string _destinationIP;
        private DateTime _timestamp;
        private string _sessionID;
        private string _status;
        private int _attemptCount;
        private MemoryStream _bodyStream;
        private readonly object _lock = new object();
        private bool _disposed;

        // Security and performance constants
        private const int MaxPayloadSnippet = 64;

        // Default suspicious IMAP commands for monitoring
        private static readonly List<string> DefaultSuspiciousCommands = new List<string>
        {
            "LOGIN", "SELECT", "FETCH", "STORE", "APPEND", "LOGOUT"
        };

        // Patterns for detecting malicious content in IMAP payloads
        private static readonly List<Regex> SuspiciousPayloadPatterns = new List<Regex>
        {
            new Regex(@"(?:password|passwd|secret|confidential|admin|root|nmap|hydra|sqlmap|union\s*select|\.\./|\<script\>)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)
        };

        // Configurable suspicious commands list
        private readonly List<string> _suspiciousCommands;

        public ImapParser(IEnumerable<string> suspiciousCommands = null, IEnumerable<string> suspiciousPayloadPatterns = null)
        {
            _bodyStream = new MemoryStream();

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

        /// <summary>
        /// Reset parser state for processing new IMAP session
        /// Clears all extracted information and payload buffer
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                _command = null;
                _folder = null;
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

        /// <summary>
        /// Parse IMAP command line and extract security-relevant information
        /// 
        /// Processing Steps:
        /// 1. Validate input parameters and command format
        /// 2. Extract command type and arguments
        /// 3. Track authentication attempts and suspicious commands
        /// 4. Monitor folder operations and message access
        /// 
        /// Supported Commands:
        /// - LOGIN: Authentication attempts tracking
        /// - SELECT: Folder access monitoring
        /// - FETCH: Email content retrieval
        /// - APPEND: Email submission
        /// - STORE: Email modification
        /// </summary>
        public void ParseCommand(string commandLine, string srcIp, string dstIp, string sessionId, DateTime? timestamp = null, int dstPort = 143)
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
            if (dstPort != 143)
            {
                LogError($"Non-standard IMAP port: {dstPort}", srcIp, dstIp);
            }

            lock (_lock)
            {
                _timestamp = timestamp?.ToUniversalTime() ?? DateTime.UtcNow;
                _sourceIP = srcIp;
                _destinationIP = dstIp;
                _sessionID = sessionId;

                // Parse command line into components
                var parts = commandLine.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) return;

                _command = parts[0].ToUpperInvariant();

                // Extract folder name for SELECT and APPEND commands
                if ((_command == "SELECT" || _command == "APPEND") && parts.Length > 1)
                    _folder = parts[1].Trim();

                // Track authentication attempts
                if (_command == "LOGIN") _attemptCount++;

                // Prepare body stream for content operations
                if (_command == "FETCH" || _command == "APPEND") _bodyStream.SetLength(0);

                // Check for suspicious commands
                if (_suspiciousCommands.Contains(_command, StringComparer.OrdinalIgnoreCase))
                    LogSuspicious($"Suspicious command detected: {_command}");
            }
        }

        /// <summary>
        /// Parse IMAP server response for status and error conditions
        /// 
        /// Response Types:
        /// - OK: Successful command completion
        /// - NO: Command failure or error
        /// - BAD: Protocol error or invalid command
        /// </summary>
        public void ParseResponse(string responseLine)
        {
            if (string.IsNullOrWhiteSpace(responseLine))
            {
                LogError($"Empty or null response line. Src={_sourceIP}, Dst={_destinationIP}", _sourceIP, _destinationIP);
                return;
            }

            lock (_lock)
            {
                if (responseLine.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
                    _status = "OK";
                else if (responseLine.StartsWith("NO", StringComparison.OrdinalIgnoreCase) || responseLine.StartsWith("BAD", StringComparison.OrdinalIgnoreCase))
                {
                    _status = "ERR";
                    LogSuspicious($"Error response received: {responseLine}");
                }
                else
                    LogError($"Unrecognized response format: {responseLine}", _sourceIP, _destinationIP);

                _responseCode = _status;
            }
        }

        /// <summary>
        /// Analyze IMAP message body content for security threats
        /// 
        /// Security Checks:
        /// - Payload size validation to prevent memory exhaustion
        /// - ASCII content analysis for suspicious patterns
        /// - SHA256 fingerprinting for content correlation
        /// - Pattern matching against known attack signatures
        /// </summary>
        public void ParseBody(byte[] bodyData)
        {
            if (bodyData == null || bodyData.Length == 0) return;

            // Limit payload size to prevent memory issues
            if (bodyData.Length > 1024 * 1024)
            {
                LogError($"Payload too large: {bodyData.Length} bytes", _sourceIP, _destinationIP);
                return;
            }

            lock (_lock)
            {
                if (_command == "FETCH" || _command == "APPEND")
                {
                    _bodyStream.Write(bodyData, 0, bodyData.Length);

                    // Analyze ASCII content for suspicious patterns
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

                    // Generate content fingerprint for correlation
                    string fingerprint = GeneratePayloadFingerprint(bodyData);
                    if (!string.IsNullOrEmpty(fingerprint))
                    {
                        LogBLL.Insert(
                            _timestamp,
                            _sourceIP,
                            _destinationIP,
                            bodyData.Length,
                            true,
                            "IMAP-FP",
                            "TCP",
                            0,
                            143,
                            bodyData.Length,
                            _command ?? "-",
                            "in",
                            _attemptCount,
                            0,
                            0,
                            $"Payload fingerprint generated = {fingerprint}"
                        );
                    }
                }
            }
        }

        /// <summary>
        /// Comprehensive IMAP packet parsing method
        /// Processes complete IMAP conversations including commands, responses, and body content
        /// </summary>
        public void Parse(byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort, string sessionId = null)
        {
            if (payload == null || payload.Length == 0) return;
            if (!IsValidIPAddress(srcIp) || !IsValidIPAddress(dstIp)) return;

            lock (_lock)
            {
                _sessionID = sessionId ?? $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";
                _sourceIP = srcIp;
                _destinationIP = dstIp;
                _timestamp = DateTime.UtcNow;

                // Decode payload for analysis
                if (!TryGetAsciiString(payload, out string ascii))
                {
                    LogError("Invalid payload encoding", srcIp, dstIp);
                    return;
                }

                // Split into individual lines for processing
                var lines = ascii.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length > 0)
                {
                    ParseCommand(lines[0], srcIp, dstIp, _sessionID, _timestamp, dstPort);
                }

                // Process remaining lines as commands or responses
                for (int i = 1; i < lines.Length; i++)
                {
                    string line = lines[i];
                    if (line.StartsWith("OK", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("NO", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("BAD", StringComparison.OrdinalIgnoreCase))
                    {
                        ParseResponse(line);
                    }
                    else
                    {
                        ParseCommand(line, srcIp, dstIp, _sessionID, _timestamp, dstPort);
                    }
                }

                ParseBody(payload);
            }
        }

        /// <summary>
        /// Attempt to decode payload as ASCII text for analysis
        /// </summary>
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

        /// <summary>
        /// Generate SHA256 fingerprint for payload correlation and tracking
        /// </summary>
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

        /// <summary>
        /// Log suspicious IMAP activity detection
        /// </summary>
        private void LogSuspicious(string message) => LogToDb(true, message);

        /// <summary>
        /// Log parsing errors and protocol violations
        /// </summary>
        private void LogError(string message, string srcIp, string dstIp) => LogToDb(true, $"ERROR: {message}");

        /// <summary>
        /// Log IMAP activity to persistent storage
        /// Creates both general log entry and detailed IMAP log entry
        /// Includes timestamp validation for database compatibility
        /// </summary>
        private void LogToDb(bool isSuspicious, string message)
        {
            try
            {
                string payloadSnippet = _bodyStream?.Length > 0
                    ? BitConverter.ToString(_bodyStream.ToArray(), 0, (int)Math.Min(MaxPayloadSnippet, _bodyStream.Length))
                    : "-";

                // Validate timestamp for database compatibility
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
                    "IMAP",
                    "TCP",
                    0,
                    143,
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
                    ImapLogDal.Insert(
                        logId,
                        _command,
                        _folder,
                        _responseCode,
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
                System.Diagnostics.Debug.WriteLine($"[IMAP-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIP}, Dst={_destinationIP}");
            }
        }

        /// <summary>
        /// Validate IP address format
        /// </summary>
        private bool IsValidIPAddress(string ip) => !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

        /// <summary>
        /// Convert parsed information to database entity
        /// </summary>
        internal ImapLog ToEntity(int logId)
        {
            lock (_lock)
            {
                return new ImapLog(
                    imapLogId: 0,
                    logId: logId,
                    command: _command,
                    folder: _folder,
                    responseCode: _responseCode,
                    sourceIP: _sourceIP,
                    destinationIP: _destinationIP,
                    timestamp: _timestamp,
                    sessionID: _sessionID,
                    status: _status,
                    attemptCount: _attemptCount
                );
            }
        }

        /// <summary>
        /// Access to raw payload data
        /// </summary>
        public byte[] Body => _bodyStream?.ToArray();

        /// <summary>
        /// Clean up resources
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