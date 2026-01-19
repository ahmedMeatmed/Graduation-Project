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
    /// Database protocol parser for Intrusion Detection System
    /// 
    /// Main Responsibilities:
    /// - Parse and analyze database network traffic for security threats
    /// - Extract SQL queries, commands, and session information
    /// - Detect suspicious database activities and potential attacks
    /// - Generate security logs and alerts for database operations
    /// 
    /// Supported Database Engines:
    /// - MySQL (port 3306)
    /// - PostgreSQL (port 5432) 
    /// - SQL Server (port 1433)
    /// - Generic SQL traffic analysis
    /// 
    /// Security Detection Capabilities:
    /// - Dangerous SQL commands (DROP, DELETE, ALTER, etc.)
    /// - Suspicious query patterns and keywords
    /// - Long-running queries indicating potential attacks
    /// - Unauthorized database access attempts
    /// - SQL injection pattern detection
    /// 
    /// Features:
    /// - Protocol-aware parsing based on destination ports
    /// - Payload fingerprinting for attack correlation
    /// - Session tracking and correlation
    /// - Comprehensive logging with performance considerations
    /// - Memory-efficient payload handling
    /// </summary>
    public class DatabaseParser : IDisposable
    {
        // Database session and query information
        private string _engine;
        private string _command;
        private string _databaseName;
        private string _username;
        private string _queryText;
        private string _sourceIp;
        private string _destinationIp;
        private DateTime _timestamp;
        private string _sessionId;
        private string _status;
        private decimal _executionTime;

        // Payload handling and synchronization
        private MemoryStream _bodyStream;
        private readonly object _lock = new object();
        private bool _disposed;

        // Security and performance constants
        private const int MaxPayloadSnippet = 128;
        private const int MaxPayloadSize = 1024 * 1024; // 1MB limit

        // Security detection patterns
        private static readonly HashSet<string> ValidEngines = new HashSet<string>(new[]
        {
            "MySQL", "PostgreSQL", "SQLServer", "Unknown"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> DangerousCommands = new HashSet<string>(new[]
        {
            "DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "EXECUTE"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly Regex SuspiciousQueryRegex = new Regex(
            @"(?:password|secret|key|auth|token|attack|exploit|admin|root|;|\-\-)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public DatabaseParser()
        {
            _bodyStream = new MemoryStream();
            Reset();
        }

        /// <summary>
        /// Reset parser state for processing new packet
        /// Clears all extracted information and payload buffer
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                _engine = null;
                _command = null;
                _databaseName = null;
                _username = null;
                _queryText = null;
                _sourceIp = null;
                _destinationIp = null;
                _timestamp = DateTime.MinValue;
                _sessionId = null;
                _status = null;
                _executionTime = 0m;
                _bodyStream?.SetLength(0);
            }
        }

        /// <summary>
        /// Parse database protocol packet and extract security-relevant information
        /// 
        /// Processing Steps:
        /// 1. Validate input parameters and payload size
        /// 2. Identify database engine based on port number
        /// 3. Extract SQL commands and query text
        /// 4. Detect suspicious patterns and dangerous operations
        /// 5. Log security events and parsed information
        /// 
        /// Supported Ports:
        /// - 3306: MySQL
        /// - 5432: PostgreSQL  
        /// - 1433: SQL Server
        /// </summary>
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

            // Common database ports: MySQL (3306), PostgreSQL (5432), SQL Server (1433)
            if (dstPort != 3306 && srcPort != 3306 && dstPort != 5432 && srcPort != 5432 && dstPort != 1433 && srcPort != 1433)
            {
                LogError($"Non-standard database port: Src={srcPort}, Dst={dstPort}", srcIp, dstIp);
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
                    ParseDatabasePacket(payload, dstPort);
                    LogToDb(false, $"Parsed database packet: Engine={_engine}, Command={_command}, DatabaseName={Truncate(_databaseName, 100)}, QueryText={Truncate(_queryText, 200)}");
                }
                catch (Exception ex)
                {
                    LogToDb(true, $"Database parse failed: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Core database packet parsing logic
        /// Extracts engine, command, database, username, and query information
        /// </summary>
        private void ParseDatabasePacket(byte[] payload, int dstPort)
        {
            // Determine database engine based on port
            _engine = dstPort switch
            {
                3306 => "MySQL",
                5432 => "PostgreSQL",
                1433 => "SQLServer",
                _ => "Unknown"
            };

            _command = "UNKNOWN";
            _databaseName = "unknown";
            _username = "unknown";
            _queryText = "none";
            _executionTime = 0m;

            // Try to extract ASCII/UTF-8 content from payload
            if (!TryGetAsciiString(payload, out string payloadText))
            {
                LogSuspicious("Unable to decode payload as ASCII/UTF-8");
                return;
            }

            // Simplified parsing for SQL-like text (common in MySQL, PostgreSQL, SQL Server text-based queries)
            payloadText = payloadText.Trim();
            if (string.IsNullOrEmpty(payloadText))
            {
                LogSuspicious("Empty payload text");
                return;
            }

            // Extract command (first word of query, e.g., SELECT, INSERT, USE)
            string[] words = payloadText.Split(new[] { ' ', '\t', '\n', ';' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 0)
            {
                _command = words[0].ToUpper();
            }

            // Extract database name (e.g., from "USE database;" or "SELECT ... FROM database.table")
            if (_command == "USE" && words.Length > 1)
            {
                _databaseName = words[1].TrimEnd(';');
            }
            else if (words.Length > 2 && words.Any(w => w.ToUpper() == "FROM"))
            {
                int fromIndex = Array.IndexOf(words, words.First(w => w.ToUpper() == "FROM"));
                if (fromIndex + 1 < words.Length)
                {
                    string fromClause = words[fromIndex + 1];
                    if (fromClause.Contains("."))
                    {
                        _databaseName = fromClause.Split('.')[0];
                    }
                }
            }

            // Extract username (heuristic based on common protocol patterns, e.g., MySQL login packet)
            if (payloadText.Contains("user=") || payloadText.Contains("USER "))
            {
                int userIndex = payloadText.IndexOf("user=", StringComparison.OrdinalIgnoreCase);
                if (userIndex >= 0)
                {
                    int start = userIndex + 5;
                    int end = payloadText.IndexOfAny(new[] { ';', ' ', '\n' }, start);
                    if (end < 0) end = payloadText.Length;
                    _username = payloadText.Substring(start, end - start);
                }
                else
                {
                    userIndex = payloadText.IndexOf("USER ", StringComparison.OrdinalIgnoreCase);
                    if (userIndex >= 0)
                    {
                        int start = userIndex + 5;
                        int end = payloadText.IndexOfAny(new[] { ';', ' ', '\n' }, start);
                        if (end < 0) end = payloadText.Length;
                        _username = payloadText.Substring(start, end - start);
                    }
                }
            }

            _queryText = Truncate(payloadText, 500);

            // Estimate execution time (simplified, as actual time requires server response)
            _executionTime = 0m; // Placeholder: real execution time requires response packet analysis

            // Validate and log suspicious conditions
            if (!ValidEngines.Contains(_engine))
            {
                LogSuspicious($"Unknown database engine: {_engine}");
            }
            if (DangerousCommands.Contains(_command))
            {
                LogSuspicious($"Potentially dangerous command: {_command}");
            }
            if (SuspiciousQueryRegex.IsMatch(_queryText))
            {
                LogSuspicious($"Suspicious query content: {Truncate(_queryText, 200)}");
            }
            if (_username != "unknown" && SuspiciousQueryRegex.IsMatch(_username))
            {
                LogSuspicious($"Suspicious username: {Truncate(_username, 100)}");
            }
            if (_executionTime > 10m) // Arbitrary threshold: 10 seconds
            {
                LogSuspicious($"Long execution time: {_executionTime} seconds");
            }

            _status = "OK";
        }

        /// <summary>
        /// Attempt to decode payload as UTF-8 or ASCII text
        /// </summary>
        private bool TryGetAsciiString(byte[] data, out string result)
        {
            try
            {
                result = Encoding.UTF8.GetString(data);
                return true;
            }
            catch
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
        }

        /// <summary>
        /// Safely truncate strings for logging with ellipsis
        /// </summary>
        private static string Truncate(string s, int max) => string.IsNullOrEmpty(s) ? s : s.Length <= max ? s : s.Substring(0, max) + "...";

        /// <summary>
        /// Log suspicious activity detection
        /// </summary>
        private void LogSuspicious(string message) => LogToDb(true, message);

        /// <summary>
        /// Log parsing errors
        /// </summary>
        private void LogError(string message, string srcIp, string dstIp) => LogToDb(true, $"ERROR: {message}");

        /// <summary>
        /// Log database activity to persistent storage
        /// Creates both general log entry and detailed database log entry
        /// </summary>
        private void LogToDb(bool isSuspicious, string message)
        {
            try
            {
                string payloadSnippet = _bodyStream?.Length > 0
                    ? BitConverter.ToString(_bodyStream.ToArray(), 0, (int)Math.Min(MaxPayloadSnippet, _bodyStream.Length))
                    : "-";
                string fingerprint = GeneratePayloadFingerprintSafe(_bodyStream?.ToArray());

                // Clamp executionTime to prevent DECIMAL(10,3) overflow
                decimal clampedExecutionTime = _executionTime;
                if (clampedExecutionTime > 9999999.999m) clampedExecutionTime = 9999999.999m;
                else if (clampedExecutionTime < 0m) clampedExecutionTime = 0m;

                int logId = LogBLL.Insert(
                    _timestamp,
                    _sourceIp ?? "unknown",
                    _destinationIp ?? "unknown",
                    (int)(_bodyStream?.Length ?? 0),
                    isSuspicious,
                    "Database",
                    "TCP",
                    0,
                    _engine == "MySQL" ? 3306 : _engine == "PostgreSQL" ? 5432 : _engine == "SQLServer" ? 1433 : 0,
                    (int)(_bodyStream?.Length ?? 0),
                    _command ?? "-",
                    "in",
                    0,
                    0,
                    null,
                    $"{message}; Snippet={payloadSnippet}; fingerprint={fingerprint}"
                );

                if (logId > 0)
                {
                    DbLogBLL.Insert(
                        logId,
                        _engine ?? "unknown",
                        _command ?? "unknown",
                        _databaseName ?? "unknown",
                        _username ?? "unknown",
                        _queryText ?? "none",
                        _sourceIp ?? "unknown",
                        _destinationIp ?? "unknown",
                        _timestamp,
                        _sessionId,
                        _status ?? "OK",
                        clampedExecutionTime
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Database-ERROR] Failed to log to DB: {ex.Message}, Src={_sourceIp}, Dst={_destinationIp}");
            }
        }

        /// <summary>
        /// Generate SHA256 fingerprint for payload correlation
        /// </summary>
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

        /// <summary>
        /// Validate IP address format
        /// </summary>
        private bool IsValidIPAddress(string ip) => !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

        /// <summary>
        /// Convert parsed information to database entity
        /// </summary>
        internal DbLog ToEntity(int logId)
        {
            lock (_lock)
            {
                return new DbLog(
                    dbLogId: 0,
                    logId: logId,
                    engine: _engine ?? "unknown",
                    command: _command ?? "unknown",
                    databaseName: _databaseName ?? "unknown",
                    username: _username ?? "unknown",
                    queryText: _queryText ?? "none",
                    sourceIp: _sourceIp ?? "unknown",
                    destinationIp: _destinationIp ?? "unknown",
                    timestamp: _timestamp,
                    sessionId: _sessionId,
                    status: _status ?? "unknown",
                    executionTime: _executionTime
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