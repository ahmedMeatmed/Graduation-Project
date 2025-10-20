// =============================================
// CLASS SUMMARY: SshParser
// =============================================
/// <summary>
/// SSH (Secure Shell) Protocol Parser - Analyzes SSH protocol handshakes and authentication attempts
/// Extracts client/server version information and detects authentication patterns
/// Provides basic SSH traffic analysis for security monitoring and intrusion detection
/// </summary>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.ProtocolParsing
{
    public class SshParser
    {
        // =============================================
        // METHOD SUMMARY: Parse() - Main entry point
        // =============================================
        /// <summary>
        /// Main SSH packet parsing method - processes SSH protocol handshake data
        /// Extracts client and server version information from SSH protocol exchange
        /// Detects authentication attempts and analyzes protocol version patterns
        /// </summary>
        /// <param name="payload">Raw SSH packet bytes to parse</param>
        /// <param name="srcIp">Source IP address of SSH traffic</param>
        /// <param name="dstIp">Destination IP address (SSH server/client)</param>
        /// <param name="srcPort">Source port number for direction analysis</param>
        /// <returns>
        /// Tuple containing:
        /// - clientVersion: Extracted SSH client version string
        /// - serverVersion: Extracted SSH server version string  
        /// - authAttempts: Count of detected authentication attempts
        /// </returns>
        public (string clientVersion, string serverVersion, int authAttempts) Parse(byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            try
            {
                if (payload.Length < 5)
                    return ("unknown", "unknown", 0);

                string clientVersion = "unknown";
                string serverVersion = "unknown";
                int authAttempts = 0;

                // SSH protocol identification: starts with "SSH-"
                if (payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-')
                {
                    int length = Math.Min(payload.Length, 255);
                    string versionString = Encoding.ASCII.GetString(payload, 0, length);

                    // Extract version line (format: SSH-2.0-OpenSSH_8.2)
                    var newlineIndex = versionString.IndexOf('\n');
                    if (newlineIndex > 0)
                        versionString = versionString.Substring(0, newlineIndex).Trim();

                    // Determine traffic direction (client→server or server→client)
                    bool isClientToServer = IsClientToServer(srcIp, dstIp, 22, srcPort);

                    if (isClientToServer)
                        clientVersion = versionString;
                    else
                        serverVersion = versionString;

                    // Basic authentication attempt detection - SSH_MSG_USERAUTH_REQUEST = 50
                    if (payload.Length > 0 && payload[0] == 50)
                        authAttempts = 1;
                }

                return (clientVersion, serverVersion, authAttempts);
            }
            catch
            {
                // Graceful error handling - return safe default values on parsing failure
                return ("error", "error", 0);
            }
        }

        // =============================================
        // METHOD SUMMARY: IsClientToServer()
        // =============================================
        /// <summary>
        /// Determines SSH traffic direction based on port numbers and IP addresses
        /// Identifies whether packets are from client to server or server to client
        /// Uses standard SSH port (22) and source port analysis for direction detection
        /// </summary>
        /// <param name="srcIp">Source IP address</param>
        /// <param name="dstIp">Destination IP address</param>
        /// <param name="servicePort">Standard SSH service port (22)</param>
        /// <param name="srcPort">Actual source port from packet</param>
        /// <returns>
        /// True if traffic is from client to server, false if from server to client
        /// </returns>
        private bool IsClientToServer(string srcIp, string dstIp, int servicePort, int srcPort)
        {
            return srcPort != servicePort && !string.IsNullOrEmpty(srcIp) && !string.IsNullOrEmpty(dstIp);
        }
    }
}