// =============================================
// CLASS SUMMARY: RdpParser
// =============================================
/// <summary>
/// RDP (Remote Desktop Protocol) Protocol Parser - Analyzes RDP traffic for security monitoring
/// Detects RDP connection attempts, authentication patterns, and potential exploitation attempts
/// Uses heuristic analysis to identify suspicious RDP activities and security threats
/// </summary>

using System;
using System.Collections.Generic;
using System.Text;

namespace IDSApp.ProtocolParsing
{
    public class RdpParser
    {
        // =============================================
        // METHOD SUMMARY: Parse() - Main entry point
        // =============================================
        /// <summary>
        /// Main RDP packet parsing method - processes RDP protocol traffic
        /// Analyzes TPKT headers, PDU types, and extracts session information
        /// Performs security checks and heuristic analysis for threat detection
        /// </summary>
        /// <param name="payload">Raw packet bytes to parse</param>
        /// <param name="srcIp">Source IP address (client)</param>
        /// <param name="dstIp">Destination IP address (RDP server)</param>
        /// <param name="srcPort">Source port number</param>
        /// <returns>RdpParseResult containing parsed data and security analysis</returns>
        public RdpParseResult Parse(byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            var result = new RdpParseResult
            {
                ClientIp = srcIp,
                ServerIp = dstIp,
                SessionId = "unknown",
                AuthAttempts = 0,
                IsSuspicious = false,
                SuspicionReasons = new List<string>()
            };

            if (payload == null || payload.Length < 4)
                return result;

            // Basic TPKT header check for RDP (RFC 1006)
            if (payload[0] != 0x03 || payload[1] != 0x00)
                return result;

            try
            {
                // RDP Connection Sequence Detection
                if (payload.Length > 7)
                {
                    // Check for different RDP PDU types
                    byte pduType = payload[7];

                    switch (pduType)
                    {
                        case 0xE0: // Connection Request PDU
                            result.AuthAttempts = 1;
                            ExtractSessionInfo(payload, result);
                            break;
                        case 0x0D: // Client Info PDU (contains authentication data)
                            result.AuthAttempts = 2;
                            ExtractCredentialsInfo(payload, result);
                            break;
                        case 0x13: // Auto-Reconnect Sequence PDU
                            result.AuthAttempts = 1;
                            result.SuspicionReasons.Add("auto_reconnect_attempt");
                            break;
                        default:
                            result.AuthAttempts = 1; // Default auth attempt for any RDP traffic
                            break;
                    }
                }

                // Look for Security Exchange or cookie in payload
                ExtractSessionIdFromPayload(payload, result);

                // IDS heuristic security checks
                PerformSecurityChecks(result);

            }
            catch (Exception ex)
            {
                result.SuspicionReasons.Add($"parse_error: {ex.Message}");
            }

            return result;
        }

        // =============================================
        // METHOD SUMMARY: ExtractSessionInfo()
        // =============================================
        /// <summary>
        /// Extracts session identifiers and connection information from RDP packets
        /// Searches for cookie patterns, session IDs, and connection-specific data
        /// Implements pattern matching for common RDP session identification methods
        /// </summary>
        /// <param name="payload">Raw packet bytes to analyze</param>
        /// <param name="result">RdpParseResult to update with extracted session info</param>
        private void ExtractSessionInfo(byte[] payload, RdpParseResult result)
        {
            try
            {
                // Look for cookie or session identifiers in the payload
                for (int i = 8; i < payload.Length - 4; i++)
                {
                    // Look for common RDP patterns - cookie indicator
                    if (payload[i] == 0x01 && i + 2 < payload.Length) // cookie indicator
                    {
                        int cookieLength = payload[i + 1];
                        if (i + 2 + cookieLength <= payload.Length && cookieLength > 0 && cookieLength < 100)
                        {
                            string sessionId = Encoding.ASCII.GetString(payload, i + 2, cookieLength);
                            if (!string.IsNullOrWhiteSpace(sessionId))
                            {
                                result.SessionId = sessionId;
                                break;
                            }
                        }
                    }

                    // Look for "Cookie: mstshash=" pattern (common RDP client identifier)
                    if (i < payload.Length - 15)
                    {
                        string pattern = "Cookie: mstshash=";
                        bool match = true;
                        for (int j = 0; j < pattern.Length; j++)
                        {
                            if (payload[i + j] != pattern[j])
                            {
                                match = false;
                                break;
                            }
                        }
                        if (match)
                        {
                            int start = i + pattern.Length;
                            int end = start;
                            while (end < payload.Length && payload[end] != 0x0D && payload[end] != 0x00)
                                end++;

                            if (end - start > 0)
                            {
                                result.SessionId = Encoding.ASCII.GetString(payload, start, end - start);
                                break;
                            }
                        }
                    }
                }
            }
            catch
            {
                // If extraction fails, keep default session ID
            }
        }

        // =============================================
        // METHOD SUMMARY: ExtractCredentialsInfo()
        // =============================================
        /// <summary>
        /// Analyzes RDP packets for credential exchange patterns
        /// Detects encrypted credential blocks and security exchange sequences
        /// Identifies authentication-related payload structures
        /// </summary>
        /// <param name="payload">Raw packet bytes to analyze</param>
        /// <param name="result">RdpParseResult to update with credential findings</param>
        private void ExtractCredentialsInfo(byte[] payload, RdpParseResult result)
        {
            try
            {
                // Basic check for encrypted credentials block
                // In real RDP, this would be more complex with proper decryption
                if (payload.Length > 50)
                {
                    // Look for encrypted security blob indicators
                    for (int i = 20; i < Math.Min(payload.Length, 100); i++)
                    {
                        if (payload[i] == 0x01 && payload[i + 1] == 0x00 && payload[i + 2] == 0x00 && payload[i + 3] == 0x00)
                        {
                            result.SuspicionReasons.Add("encrypted_credentials_detected");
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Ignore extraction errors
            }
        }

        // =============================================
        // METHOD SUMMARY: ExtractSessionIdFromPayload()
        // =============================================
        /// <summary>
        /// Alternative session ID extraction using printable string analysis
        /// Scans payload for ASCII strings that may contain session identifiers
        /// Uses pattern matching for common RDP-related keywords
        /// </summary>
        /// <param name="payload">Raw packet bytes to analyze</param>
        /// <param name="result">RdpParseResult to update with session ID findings</param>
        private void ExtractSessionIdFromPayload(byte[] payload, RdpParseResult result)
        {
            try
            {
                // Alternative method to extract session information
                // Look for any printable strings that might be session IDs
                List<byte> sessionBytes = new List<byte>();

                for (int i = 0; i < payload.Length; i++)
                {
                    byte b = payload[i];
                    if (b >= 0x20 && b <= 0x7E) // Printable ASCII
                    {
                        sessionBytes.Add(b);
                        if (sessionBytes.Count > 50) // Limit session ID length
                            break;
                    }
                    else if (sessionBytes.Count > 5)
                    {
                        string potentialId = Encoding.ASCII.GetString(sessionBytes.ToArray());
                        if (potentialId.Contains("mstshash") || potentialId.Contains("SESSION") ||
                            potentialId.Contains("COOKIE") || potentialId.Length > 10)
                        {
                            result.SessionId = potentialId;
                            break;
                        }
                        sessionBytes.Clear();
                    }
                    else
                    {
                        sessionBytes.Clear();
                    }
                }
            }
            catch
            {
                // Keep existing session ID if extraction fails
            }
        }

        // =============================================
        // METHOD SUMMARY: PerformSecurityChecks()
        // =============================================
        /// <summary>
        /// Performs heuristic security analysis on parsed RDP data
        /// Detects brute-force attempts, suspicious patterns, and known exploits
        /// Analyzes network patterns and session characteristics for threats
        /// </summary>
        /// <param name="result">RdpParseResult to analyze and update with security findings</param>
        private void PerformSecurityChecks(RdpParseResult result)
        {
            // Security heuristic checks
            if (result.AuthAttempts > 3)
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("high_auth_attempts");
            }

            if (!string.IsNullOrEmpty(result.SessionId) && result.SessionId.Length > 50)
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("unusually_long_session_id");
            }

            if (result.SessionId.Contains("..") || result.SessionId.Contains("\\") || result.SessionId.Contains("/"))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("suspicious_characters_in_session_id");
            }

            // Check for known RDP exploitation patterns
            if (result.SessionId.ToLower().Contains("bluekeep") ||
                result.SessionId.ToLower().Contains("cve-2019-0708"))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("known_exploit_pattern");
            }

            // Check for internal IP trying RDP to external (potential lateral movement)
            if (IsInternalIp(result.ClientIp) && !IsInternalIp(result.ServerIp))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("internal_to_external_rdp");
            }
        }

        // =============================================
        // METHOD SUMMARY: IsInternalIp()
        // =============================================
        /// <summary>
        /// Determines if an IP address belongs to internal/private IP ranges
        /// Checks against RFC 1918 private address spaces and localhost
        /// Used for detecting potentially suspicious cross-boundary RDP connections
        /// </summary>
        /// <param name="ip">IP address string to check</param>
        /// <returns>True if IP is in private/internal range, false otherwise</returns>
        private bool IsInternalIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;

            return ip.StartsWith("192.168.") ||           // RFC 1918: 192.168.0.0/16
                   ip.StartsWith("10.") ||                // RFC 1918: 10.0.0.0/8
                   ip.StartsWith("172.16.") ||            // RFC 1918: 172.16.0.0/12
                   ip.StartsWith("172.17.") ||
                   ip.StartsWith("172.18.") ||
                   ip.StartsWith("172.19.") ||
                   ip.StartsWith("172.20.") ||
                   ip.StartsWith("172.21.") ||
                   ip.StartsWith("172.22.") ||
                   ip.StartsWith("172.23.") ||
                   ip.StartsWith("172.24.") ||
                   ip.StartsWith("172.25.") ||
                   ip.StartsWith("172.26.") ||
                   ip.StartsWith("172.27.") ||
                   ip.StartsWith("172.28.") ||
                   ip.StartsWith("172.29.") ||
                   ip.StartsWith("172.30.") ||
                   ip.StartsWith("172.31.") ||
                   ip == "127.0.0.1";                    // Localhost
        }
    }

    // =============================================
    // CLASS SUMMARY: RdpParseResult
    // =============================================
    /// <summary>
    /// Result container for RDP parsing operations
    /// Stores extracted RDP session data, authentication information, and security analysis results
    /// Provides utility methods for result validation and formatting
    /// </summary>
    public class RdpParseResult
    {
        // =============================================
        // PROPERTY SUMMARY: SessionId
        // =============================================
        /// <summary>
        /// Extracted RDP session identifier or connection cookie
        /// Typically contains mstshash values or custom session identifiers
        /// Default value: "unknown"
        /// </summary>
        public string SessionId { get; set; } = "unknown";

        // =============================================
        // PROPERTY SUMMARY: AuthAttempts
        // =============================================
        /// <summary>
        /// Counter for authentication attempts detected in RDP traffic
        /// Used for brute-force attack detection and connection sequence analysis
        /// Default value: 0
        /// </summary>
        public int AuthAttempts { get; set; } = 0;

        // =============================================
        // PROPERTY SUMMARY: ServerIp
        // =============================================
        /// <summary>
        /// RDP server IP address (destination)
        /// Used for connection tracking and network path analysis
        /// </summary>
        public string ServerIp { get; set; } = "";

        // =============================================
        // PROPERTY SUMMARY: ClientIp
        // =============================================
        /// <summary>
        /// RDP client IP address (source)
        /// Used for connection tracking and client identification
        /// </summary>
        public string ClientIp { get; set; } = "";

        // =============================================
        // PROPERTY SUMMARY: IsSuspicious
        // =============================================
        /// <summary>
        /// Flag indicating whether security heuristics detected suspicious activity
        /// Set to true when one or more security checks trigger
        /// Default value: false
        /// </summary>
        public bool IsSuspicious { get; set; } = false;

        // =============================================
        // PROPERTY SUMMARY: SuspicionReasons
        // =============================================
        /// <summary>
        /// List of reasons why the RDP traffic was flagged as suspicious
        /// Contains specific security alerts and detection rationale
        /// </summary>
        public List<string> SuspicionReasons { get; set; } = new List<string>();

        // =============================================
        // METHOD SUMMARY: ToString()
        // =============================================
        /// <summary>
        /// Provides formatted string representation of RDP parse results
        /// Includes all key properties and security findings for logging and display
        /// </summary>
        /// <returns>Formatted string containing RDP analysis results</returns>
        public override string ToString()
        {
            return $"RDP[SessionId={SessionId}, AuthAttempts={AuthAttempts}, Client={ClientIp}, Server={ServerIp}, Suspicious={IsSuspicious}, Reasons=[{string.Join(',', SuspicionReasons)}]]";
        }

        // =============================================
        // METHOD SUMMARY: HasMeaningfulData()
        // =============================================
        /// <summary>
        /// Determines if the parse result contains meaningful RDP data
        /// Checks for valid session IDs and authentication activity
        /// Used to filter out incomplete or irrelevant parsing results
        /// </summary>
        /// <returns>True if result contains valid RDP session data, false otherwise</returns>
        public bool HasMeaningfulData()
        {
            return !string.IsNullOrEmpty(SessionId) &&
                   SessionId != "unknown" &&
                   AuthAttempts > 0;
        }
    }
}