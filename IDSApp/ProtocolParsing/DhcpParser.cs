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
    public class DhcpParser : IDisposable
    {
        // DHCP protocol fields
        private string _messageType;
        private string _transactionId;
        private string _clientIp;
        private string _offeredIp;
        private string _serverIp;
        private string _sourceIp;
        private string _destinationIp;
        private DateTime _timestamp;
        private string _sessionId;
        private string _status;
        private int _leaseDuration;
        private int _sourcePort;
        private int _destinationPort;

        // Payload handling and synchronization
        private MemoryStream _bodyStream;
        private readonly object _lock = new object();
        private bool _disposed;

        // Constants
        private const int MaxPayloadSnippet = 128;
        private const int MaxPayloadSize = 1024 * 1024;

        public DhcpParser()
        {
            _bodyStream = new MemoryStream();
            Reset();
        }

        /// <summary>
        /// Reset parser state for processing new DHCP packet
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                _messageType = "Unknown";
                _transactionId = "N/A";
                _clientIp = "0.0.0.0";
                _offeredIp = "N/A";
                _serverIp = "0.0.0.0";
                _sourceIp = null;
                _destinationIp = null;
                _timestamp = DateTime.UtcNow;
                _sessionId = null;
                _status = "Processing";
                _leaseDuration = 0;
                _sourcePort = 0;
                _destinationPort = 0;
                _bodyStream?.SetLength(0);
            }
        }

        /// <summary>
        /// Parse DHCP protocol packet and extract security-relevant information
        /// </summary>
        public DhcpParserResult Parse(byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            var result = new DhcpParserResult();

            if (payload == null || payload.Length == 0)
            {
                result.Notes = "Empty or null payload";
                result.IsSuspicious = true;
                return result;
            }

            lock (_lock)
            {
                try
                {
                    _sourceIp = srcIp;
                    _destinationIp = dstIp;
                    _sourcePort = srcPort;
                    _destinationPort = dstPort;
                    _timestamp = DateTime.UtcNow;
                    _sessionId = $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";
                    _bodyStream.SetLength(0);
                    _bodyStream.Write(payload, 0, payload.Length);

                    // Parse with detailed debugging
                    var parseResult = ParseDhcpPacketWithDebug(payload);

                    result.MessageType = parseResult.MessageType;
                    result.TransactionId = parseResult.TransactionId;
                    result.ClientIp = parseResult.ClientIp;
                    result.OfferedIp = parseResult.OfferedIp;
                    result.ServerIp = parseResult.ServerIp;
                    result.LeaseTime = parseResult.LeaseTime;
                    result.IsSuspicious = parseResult.IsSuspicious;
                    result.Notes = parseResult.Notes;

                    return result;
                }
                catch (Exception ex)
                {
                    result.Notes = $"DHCP parse failed: {ex.Message}";
                    result.IsSuspicious = true;
                    return result;
                }
            }
        }

        /// <summary>
        /// Comprehensive DHCP parsing with detailed debugging
        /// </summary>
        private DhcpParserResult ParseDhcpPacketWithDebug(byte[] payload)
        {
            var result = new DhcpParserResult();
            var debugInfo = new List<string>();

            try
            {
                debugInfo.Add($"Payload length: {payload.Length} bytes");
                debugInfo.Add($"Source: {_sourceIp}:{_sourcePort}, Dest: {_destinationIp}:{_destinationPort}");

                // Basic DHCP packet validation
                if (payload.Length < 240)
                {
                    result.Notes = $"Packet too short: {payload.Length} bytes";
                    result.IsSuspicious = true;
                    debugInfo.Add($"FAIL: Packet too short");
                    return result;
                }

                // 1. Parse fixed DHCP header (first 240 bytes)
                ParseDhcpHeader(payload, result, debugInfo);

                // 2. Parse DHCP options
                ParseDhcpOptions(payload, result, debugInfo);

                // 3. Final validation and inference
                ValidateAndInfer(result, debugInfo);

                result.Notes = string.Join("; ", debugInfo);
                return result;
            }
            catch (Exception ex)
            {
                result.Notes = $"Parse error: {ex.Message}. Debug: {string.Join("; ", debugInfo)}";
                result.IsSuspicious = true;
                return result;
            }
        }

        /// <summary>
        /// Parse the fixed portion of DHCP packet (first 240 bytes)
        /// </summary>
        private void ParseDhcpHeader(byte[] payload, DhcpParserResult result, List<string> debugInfo)
        {
            // Operation Code (byte 0)
            byte opCode = payload[0];
            debugInfo.Add($"OpCode: {opCode} ({(opCode == 1 ? "REQUEST" : opCode == 2 ? "REPLY" : "UNKNOWN")})");

            // Transaction ID (bytes 4-7) - Big Endian
            if (payload.Length >= 8)
            {
                result.TransactionId = BitConverter.ToString(payload, 4, 4).Replace("-", "").ToLowerInvariant();
                debugInfo.Add($"TransactionID: {result.TransactionId}");
            }

            // Client IP Address (ciaddr) - bytes 12-15
            result.ClientIp = ExtractIPv4Address(payload, 12);
            debugInfo.Add($"ClientIP: {result.ClientIp}");

            // Your IP Address (yiaddr) - bytes 16-19 - Offered IP
            result.OfferedIp = ExtractIPv4Address(payload, 16);
            debugInfo.Add($"OfferedIP: {result.OfferedIp}");

            // Server IP Address (siaddr) - bytes 20-23
            result.ServerIp = ExtractIPv4Address(payload, 20);
            debugInfo.Add($"ServerIP: {result.ServerIp}");

            // Client Hardware Address (chaddr) - bytes 28-43
            if (payload.Length >= 44)
            {
                string macAddress = ExtractMacAddress(payload, 28);
                if (macAddress != "00:00:00:00:00:00")
                {
                    result.ClientMac = macAddress;
                    debugInfo.Add($"ClientMAC: {macAddress}");
                }
            }
        }

        /// <summary>
        /// Parse DHCP options with multiple detection methods
        /// </summary>
        private void ParseDhcpOptions(byte[] payload, DhcpParserResult result, List<string> debugInfo)
        {
            bool messageTypeFound = false;
            bool leaseTimeFound = false;

            // Method 1: Standard DHCP options at offset 240
            if (payload.Length > 240)
            {
                debugInfo.Add("Method1: Standard options at 240");
                if (ParseOptionsStandard(payload, 240, result, ref messageTypeFound, ref leaseTimeFound, debugInfo))
                {
                    debugInfo.Add("Method1: Success");
                    return;
                }
            }

            // Method 2: Look for magic cookie (99.130.83.99) anywhere in packet
            int magicOffset = FindMagicCookie(payload);
            if (magicOffset != -1 && magicOffset + 4 < payload.Length)
            {
                debugInfo.Add($"Method2: Magic cookie at {magicOffset}");
                if (ParseOptionsStandard(payload, magicOffset + 4, result, ref messageTypeFound, ref leaseTimeFound, debugInfo))
                {
                    debugInfo.Add("Method2: Success");
                    return;
                }
            }

            // Method 3: Brute force search for option 53
            if (!messageTypeFound)
            {
                debugInfo.Add("Method3: Brute force search");
                BruteForceOptionSearch(payload, result, ref messageTypeFound, ref leaseTimeFound, debugInfo);
            }

            // Set defaults if not found
            if (!leaseTimeFound)
            {
                result.LeaseTime = 3600; // Default 1 hour
                debugInfo.Add("LeaseTime: Using default 3600");
            }
        }

        /// <summary>
        /// Parse DHCP options using standard format
        /// </summary>
        private bool ParseOptionsStandard(byte[] payload, int startOffset, DhcpParserResult result,
            ref bool messageTypeFound, ref bool leaseTimeFound, List<string> debugInfo)
        {
            int offset = startOffset;
            int optionsParsed = 0;

            while (offset < payload.Length && offset >= 0)
            {
                byte optionCode = payload[offset++];

                if (optionCode == 255) // End option
                    break;

                if (optionCode == 0) // Pad option
                    continue;

                if (offset >= payload.Length) break;

                byte optionLength = payload[offset++];
                if (offset + optionLength > payload.Length) break;

                optionsParsed++;

                // DHCP Message Type (Option 53)
                if (optionCode == 53 && optionLength == 1)
                {
                    result.MessageType = GetDhcpMessageType(payload[offset]);
                    messageTypeFound = true;
                    debugInfo.Add($"Found MessageType: {result.MessageType} at offset {offset}");
                }
                // IP Address Lease Time (Option 51)
                else if (optionCode == 51 && optionLength == 4)
                {
                    result.LeaseTime = BitConverter.ToInt32(new byte[]
                    {
                        payload[offset + 3],
                        payload[offset + 2],
                        payload[offset + 1],
                        payload[offset]
                    }, 0);
                    leaseTimeFound = true;
                    debugInfo.Add($"Found LeaseTime: {result.LeaseTime} at offset {offset}");
                }

                offset += optionLength;
            }

            debugInfo.Add($"Parsed {optionsParsed} options");
            return messageTypeFound || leaseTimeFound;
        }

        /// <summary>
        /// Find DHCP magic cookie in packet
        /// </summary>
        private int FindMagicCookie(byte[] payload)
        {
            byte[] magicCookie = { 99, 130, 83, 99 };

            // Search from typical locations first
            int[] searchStarts = { 236, 240, 244, 248, 232 };

            foreach (int start in searchStarts)
            {
                if (start + 4 <= payload.Length)
                {
                    if (payload[start] == magicCookie[0] &&
                        payload[start + 1] == magicCookie[1] &&
                        payload[start + 2] == magicCookie[2] &&
                        payload[start + 3] == magicCookie[3])
                    {
                        return start;
                    }
                }
            }

            // Brute force search if not found in typical locations
            for (int i = 0; i <= payload.Length - 4; i++)
            {
                if (payload[i] == magicCookie[0] &&
                    payload[i + 1] == magicCookie[1] &&
                    payload[i + 2] == magicCookie[2] &&
                    payload[i + 3] == magicCookie[3])
                {
                    return i;
                }
            }

            return -1;
        }

        /// <summary>
        /// Brute force search for DHCP options
        /// </summary>
        private void BruteForceOptionSearch(byte[] payload, DhcpParserResult result,
            ref bool messageTypeFound, ref bool leaseTimeFound, List<string> debugInfo)
        {
            // Look for option 53 (Message Type) pattern: 0x35 0x01 [message-type]
            for (int i = 240; i < payload.Length - 2; i++)
            {
                if (payload[i] == 0x35 && payload[i + 1] == 0x01) // Option 53, Length 1
                {
                    result.MessageType = GetDhcpMessageType(payload[i + 2]);
                    messageTypeFound = true;
                    debugInfo.Add($"BruteForce: Found MessageType {result.MessageType} at offset {i}");
                    break;
                }
            }

            // Look for option 51 (Lease Time) pattern: 0x33 0x04 [4-byte lease time]
            if (!leaseTimeFound)
            {
                for (int i = 240; i < payload.Length - 6; i++)
                {
                    if (payload[i] == 0x33 && payload[i + 1] == 0x04) // Option 51, Length 4
                    {
                        result.LeaseTime = BitConverter.ToInt32(new byte[]
                        {
                            payload[i + 5],
                            payload[i + 4],
                            payload[i + 3],
                            payload[i + 2]
                        }, 0);
                        leaseTimeFound = true;
                        debugInfo.Add($"BruteForce: Found LeaseTime {result.LeaseTime} at offset {i}");
                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Final validation and inference
        /// </summary>
        private void ValidateAndInfer(DhcpParserResult result, List<string> debugInfo)
        {
            // If message type still not found, infer from ports
            if (result.MessageType == "Unknown")
            {
                result.MessageType = InferMessageTypeFromPorts();
                debugInfo.Add($"Inferred MessageType: {result.MessageType} from ports");
            }

            // Check for suspicious conditions
            var warnings = new List<string>();

            if (result.LeaseTime < 0 || result.LeaseTime > 604800) // > 7 days
            {
                warnings.Add($"Suspicious lease: {result.LeaseTime}s");
            }

            if (result.ClientIp != "0.0.0.0" && result.ClientIp != _sourceIp)
            {
                warnings.Add($"IP mismatch: Client={result.ClientIp}, Source={_sourceIp}");
            }

            if (warnings.Count > 0)
            {
                result.IsSuspicious = true;
                result.Notes += "; " + string.Join("; ", warnings);
            }
        }

        /// <summary>
        /// Extract IPv4 address from byte array
        /// </summary>
        private string ExtractIPv4Address(byte[] data, int offset)
        {
            if (offset + 4 > data.Length)
                return "0.0.0.0";

            try
            {
                return $"{data[offset]}.{data[offset + 1]}.{data[offset + 2]}.{data[offset + 3]}";
            }
            catch
            {
                return "0.0.0.0";
            }
        }

        /// <summary>
        /// Extract MAC address from byte array
        /// </summary>
        private string ExtractMacAddress(byte[] data, int offset)
        {
            if (offset + 6 > data.Length)
                return "00:00:00:00:00:00";

            try
            {
                return BitConverter.ToString(data, offset, 6).Replace("-", ":");
            }
            catch
            {
                return "00:00:00:00:00:00";
            }
        }

        /// <summary>
        /// Convert DHCP message type code to string
        /// </summary>
        private string GetDhcpMessageType(byte messageTypeValue)
        {
            return messageTypeValue switch
            {
                1 => "DISCOVER",
                2 => "OFFER",
                3 => "REQUEST",
                4 => "DECLINE",
                5 => "ACK",
                6 => "NAK",
                7 => "RELEASE",
                8 => "INFORM",
                _ => $"Unknown({messageTypeValue})"
            };
        }

        /// <summary>
        /// Infer message type from source/destination ports
        /// </summary>
        private string InferMessageTypeFromPorts()
        {
            // Port 67 = DHCP Server, Port 68 = DHCP Client
            if (_sourcePort == 67 && _destinationPort == 68)
                return "OFFER";
            if (_sourcePort == 67)
                return "SERVER_RESPONSE";
            if (_sourcePort == 68 && _destinationPort == 67)
                return "REQUEST";
            if (_sourcePort == 68)
                return "CLIENT_REQUEST";
            return "UNKNOWN";
        }

        /// <summary>
        /// Get detailed hex dump for debugging
        /// </summary>
        public string GetDetailedHexDump(byte[] payload, int maxBytes = 256)
        {
            if (payload == null || payload.Length == 0)
                return "Empty payload";

            int length = Math.Min(payload.Length, maxBytes);
            var hex = new StringBuilder();
            var ascii = new StringBuilder();

            for (int i = 0; i < length; i++)
            {
                hex.Append(payload[i].ToString("X2") + " ");

                // Show ASCII for printable characters
                ascii.Append(payload[i] >= 32 && payload[i] <= 126 ?
                    ((char)payload[i]).ToString() : ".");

                // Format for readability
                if ((i + 1) % 16 == 0)
                {
                    hex.Append("  " + ascii.ToString());
                    hex.AppendLine();
                    ascii.Clear();
                }
                else if ((i + 1) % 8 == 0)
                {
                    hex.Append(" ");
                }
            }

            // Add remaining ASCII if any
            if (ascii.Length > 0)
            {
                hex.Append(new string(' ', (16 - ascii.Length) * 3 + 2));
                hex.Append(ascii.ToString());
            }

            return hex.ToString();
        }

        /// <summary>
        /// Validate IP address format
        /// </summary>
        private bool IsValidIPAddress(string ip) =>
            !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

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

    public class DhcpParserResult
    {
        public string MessageType { get; set; } = "Unknown";
        public string TransactionId { get; set; } = "N/A";
        public string ClientIp { get; set; } = "0.0.0.0";
        public string OfferedIp { get; set; } = "N/A";
        public string ServerIp { get; set; } = "0.0.0.0";
        public string ClientMac { get; set; } = "-";
        public int LeaseTime { get; set; } = 0;
        public bool IsSuspicious { get; set; } = false;
        public string Notes { get; set; } = "";
    }
}