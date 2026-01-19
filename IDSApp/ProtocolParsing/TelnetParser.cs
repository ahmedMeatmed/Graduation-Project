// =============================================
// CLASS SUMMARY: TelnetParser
// =============================================
/// <summary>
/// Telnet Protocol Parser - Analyzes Telnet protocol traffic for security monitoring
/// Extracts clear-text commands, detects authentication attempts, and identifies suspicious activities
/// Removes Telnet control sequences to focus on actual user commands and data
/// </summary>

using System;
using System.Buffers;
using System.Text;

namespace IDSApp.ProtocolParsing
{
    public class TelnetParser
    {
        // =============================================
        // METHOD SUMMARY: Parse() - Main entry point
        // =============================================
        /// <summary>
        /// Main Telnet packet parsing method - processes Telnet protocol traffic
        /// Filters out Telnet control sequences and extracts clear-text commands
        /// Detects authentication attempts and suspicious command patterns
        /// </summary>
        /// <param name="payload">Raw Telnet packet bytes to parse</param>
        /// <param name="srcIp">Source IP address of Telnet traffic</param>
        /// <param name="dstIp">Destination IP address (Telnet server)</param>
        /// <param name="srcPort">Source port number for direction analysis</param>
        /// <returns>TelnetParseResult containing extracted commands and security analysis</returns>
        public TelnetParseResult Parse(byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            var result = new TelnetParseResult
            {
                ClientIp = srcIp,
                ServerIp = dstIp,
                Command = "none",
                AuthAttempts = 0
            };

            try
            {
                if (payload == null || payload.Length == 0)
                    return result;

                // تحديد اتجاه الاتصال - Analyze connection direction
                bool isClientToServer = IsClientToServer(srcIp, dstIp, 23, srcPort);
                if (!isClientToServer)
                {
                    // تجاهل حركة المرور من الخادم إلى العميل - Ignore server→client traffic
                    return result;
                }

                // استخدام ArrayPool للأداء - Use ArrayPool for better performance
                var buffer = ArrayPool<byte>.Shared.Rent(payload.Length);
                int dataLength = 0;

                // إزالة أوامر Telnet (التي تبدأ بـ 0xFF) - Remove Telnet commands (start with 0xFF)
                for (int i = 0; i < payload.Length; i++)
                {
                    if (payload[i] == 0xFF && i + 1 < payload.Length)
                    {
                        i++; // تخطي byte الأمر - Skip command byte
                        continue;
                    }
                    buffer[dataLength++] = payload[i];
                }

                if (dataLength > 0)
                {
                    string text = Encoding.ASCII.GetString(buffer, 0, dataLength).Trim();
                    if (!string.IsNullOrEmpty(text))
                    {
                        result.Command = text.Length > 255 ? text.Substring(0, 255) : text;

                        // Detect login attempts - اكتشاف محاولات تسجيل الدخول
                        DetectAuthenticationAttempts(text, result);

                        // Detect suspicious commands - اكتشاف الأوامر المشبوهة
                        DetectSuspiciousCommands(text, result);
                    }
                }

                ArrayPool<byte>.Shared.Return(buffer);
                return result;
            }
            catch (Exception ex)
            {
                result.Command = $"error: {ex.Message}";
                return result;
            }
        }

        // =============================================
        // METHOD SUMMARY: DetectAuthenticationAttempts()
        // =============================================
        /// <summary>
        /// Detects Telnet authentication patterns in extracted text
        /// Identifies login sequences, username/password prompts, and credential submission
        /// </summary>
        /// <param name="text">Cleaned Telnet command text</param>
        /// <param name="result">TelnetParseResult to update with authentication findings</param>
        private void DetectAuthenticationAttempts(string text, TelnetParseResult result)
        {
            if (text.ToLower().Contains("login") ||
                text.ToLower().Contains("password") ||
                text.StartsWith("USER", StringComparison.OrdinalIgnoreCase) ||
                text.StartsWith("PASS", StringComparison.OrdinalIgnoreCase) ||
                text.ToLower().Contains("username"))
            {
                result.AuthAttempts = 1;
            }
        }

        // =============================================
        // METHOD SUMMARY: DetectSuspiciousCommands()
        // =============================================
        /// <summary>
        /// Detects potentially malicious commands in Telnet traffic
        /// Identifies shell access attempts, file downloads, and dangerous system commands
        /// </summary>
        /// <param name="text">Cleaned Telnet command text</param>
        /// <param name="result">TelnetParseResult to update with security findings</param>
        private void DetectSuspiciousCommands(string text, TelnetParseResult result)
        {
            if (text.ToLower().Contains("/bin/sh") ||
                text.ToLower().Contains("cmd.exe") ||
                text.ToLower().Contains("wget") ||
                text.ToLower().Contains("curl") ||
                text.ToLower().Contains("chmod") ||
                text.ToLower().Contains("rm -rf"))
            {
                result.AuthAttempts = 2; // علامة على نشاط مشبوه - Flag for suspicious activity
            }
        }

        // =============================================
        // METHOD SUMMARY: IsClientToServer()
        // =============================================
        /// <summary>
        /// Determines Telnet traffic direction based on port numbers
        /// Identifies client-to-server traffic for command analysis
        /// </summary>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        /// <param name="servicePort">Standard Telnet service port (23)</param>
        /// <param name="srcPort">Actual source port from packet</param>
        /// <returns>True if traffic is from client to server, false otherwise</returns>
        private bool IsClientToServer(string srcIp, string dstIp, int servicePort, int srcPort)
        {
            // Client to Server: عندما المنفذ المصدر ليس 23 (منفذ Telnet)
            // Client to Server: When source port is not 23 (Telnet port)
            return srcPort != servicePort && !string.IsNullOrEmpty(srcIp) && !string.IsNullOrEmpty(dstIp);
        }
    }

    // =============================================
    // CLASS SUMMARY: TelnetParseResult
    // =============================================
    /// <summary>
    /// Result container for Telnet parsing operations
    /// Stores extracted Telnet commands, connection information, and security analysis results
    /// Provides utility methods for result validation and formatted output
    /// </summary>
    public class TelnetParseResult
    {
        // =============================================
        // PROPERTY SUMMARY: Command
        // =============================================
        /// <summary>
        /// Extracted Telnet command text after removing control sequences
        /// Contains clear-text user commands and data entered in Telnet session
        /// Default value: empty string
        /// </summary>
        public string Command { get; set; } = "";

        // =============================================
        // PROPERTY SUMMARY: ClientIp
        // =============================================
        /// <summary>
        /// Source IP address of Telnet client
        /// Used for connection tracking and client identification
        /// </summary>
        public string ClientIp { get; set; } = "";

        // =============================================
        // PROPERTY SUMMARY: ServerIp
        // =============================================
        /// <summary>
        /// Destination IP address of Telnet server
        /// Used for connection tracking and server identification
        /// </summary>
        public string ServerIp { get; set; } = "";

        // =============================================
        // PROPERTY SUMMARY: AuthAttempts
        // =============================================
        /// <summary>
        /// Counter for authentication attempts and suspicious activity levels
        /// - 0: No authentication detected
        /// - 1: Authentication patterns detected (login/password)
        /// - 2: Suspicious commands detected (shell access, file operations)
        /// Default value: 0
        /// </summary>
        public int AuthAttempts { get; set; } = 0;

        // =============================================
        // METHOD SUMMARY: ToString()
        // =============================================
        /// <summary>
        /// Provides formatted string representation of Telnet parse results
        /// Includes all key properties for logging and display purposes
        /// </summary>
        /// <returns>Formatted string containing Telnet analysis results</returns>
        public override string ToString()
        {
            return $"Telnet[Command={Command}, ClientIp={ClientIp}, ServerIp={ServerIp}, AuthAttempts={AuthAttempts}]";
        }

        // =============================================
        // METHOD SUMMARY: HasMeaningfulData()
        // =============================================
        /// <summary>
        /// Determines if the parse result contains meaningful Telnet data
        /// Checks for valid commands and filters out errors or empty results
        /// </summary>
        /// <returns>True if result contains valid Telnet command data, false otherwise</returns>
        public bool HasMeaningfulData()
        {
            return !string.IsNullOrEmpty(Command) &&
                   Command != "none" &&
                   !Command.StartsWith("error");
        }
    }
}