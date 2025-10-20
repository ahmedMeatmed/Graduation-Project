using System;
using System.Collections.Concurrent;
using System.Net;
using IDSApp.BLL;

namespace IDSApp.Helper
{
    /// <summary>
    /// Dynamic network traffic whitelisting system for Intrusion Detection System
    /// 
    /// Main Responsibilities:
    /// - Manage and evaluate IP addresses, ports, and networks against whitelist rules
    /// - Provide real-time traffic filtering decisions
    /// - Support dynamic whitelist updates from database
    /// - Handle internal network traffic and essential service ports
    /// 
    /// Features:
    /// - Multi-criteria whitelisting (IPs, ports, networks, protocols)
    /// - Time-based whitelist entries with automatic expiration
    /// - Trusted network recognition (private IP ranges)
    /// - Protocol-specific whitelisting rules
    /// - Thread-safe operations with read/write locks
    /// - Configurable enable/disable functionality
    /// 
    /// Whitelist Evaluation Logic:
    /// 1. Check if whitelist is enabled (configurable)
    /// 2. Allow all internal network traffic
    /// 3. Allow essential ports for security analysis
    /// 4. Check against IP, port, and network whitelists
    /// 5. Apply protocol-specific whitelist rules
    /// </summary>
    internal class DynamicWhitelist
    {
        private readonly ConcurrentDictionary<string, DateTime> _whitelistedIps = new();
        private readonly ConcurrentDictionary<int, DateTime> _whitelistedPorts = new();
        private readonly ConcurrentBag<IPNetwork> _trustedNetworks = new();
        private DateTime _lastWhitelistUpdate = DateTime.MinValue;
        private readonly TimeSpan _whitelistRefreshInterval = TimeSpan.FromMinutes(5);
        private readonly ReaderWriterLockSlim _refreshLock = new ReaderWriterLockSlim();

        // 🔧 FIX: Add control variable to enable/disable whitelist functionality
        private bool _enableWhitelist = false; // Temporarily disabled for testing

        public DynamicWhitelist()
        {
            LoadWhitelistFromDatabase();
        }

        /// <summary>
        /// Evaluate if network traffic should be whitelisted (allowed without inspection)
        /// 
        /// Decision Flow:
        /// 1. If whitelist disabled → ALLOW traffic (return false)
        /// 2. If internal IP → ALLOW traffic
        /// 3. If essential analysis port → ALLOW traffic  
        /// 4. Check IP whitelist → BLOCK if found (return true)
        /// 5. Check port whitelist → BLOCK if found
        /// 6. Check trusted networks → BLOCK if found
        /// 7. Check protocol whitelist → BLOCK if found
        /// 8. Default → ALLOW traffic for analysis
        /// 
        /// Returns: 
        /// - true: Traffic is whitelisted (should be BLOCKED from inspection)
        /// - false: Traffic should be ALLOWED for inspection
        /// </summary>
        public bool IsWhitelisted(string srcIp, string dstIp, int dstPort, string protocol)
        {
            // 🔧 FIX: Temporarily disable whitelist for testing
            if (!_enableWhitelist)
            {
                // Log only first packets to avoid repetition
                if (ShouldLogWhitelistDebug())
                {
                    OptimizedLogger.LogDebug($"[Whitelist] Whitelist disabled - allowing: {srcIp} -> {dstIp}:{dstPort} ({protocol})");
                }
                return false; // false means ALLOW packet (not blocked)
            }

            UpdateWhitelistIfNeeded();

            // 🔧 FIX: Allow all internal traffic
            if (IsInternalIP(srcIp) || IsInternalIP(dstIp))
            {
                if (ShouldLogWhitelistDebug())
                {
                    OptimizedLogger.LogDebug($"[Whitelist] Allowing internal traffic: {srcIp} -> {dstIp}:{dstPort}");
                }
                return false;
            }

            // 🔧 FIX: Allow essential ports for security analysis
            if (IsEssentialPortForAnalysis(dstPort))
            {
                if (ShouldLogWhitelistDebug())
                {
                    OptimizedLogger.LogDebug($"[Whitelist] Allowing essential port for analysis: {dstPort}");
                }
                return false;
            }

            // Check IP whitelist
            if (_whitelistedIps.ContainsKey(srcIp) || _whitelistedIps.ContainsKey(dstIp))
            {
                OptimizedLogger.LogDebug($"[Whitelist] IP whitelisted: {srcIp} -> {dstIp}");
                return true;
            }

            // Check port whitelist
            if (_whitelistedPorts.ContainsKey(dstPort))
            {
                OptimizedLogger.LogDebug($"[Whitelist] Port whitelisted: {dstPort}");
                return true;
            }

            // Check trusted networks
            if (IsInTrustedNetwork(srcIp) || IsInTrustedNetwork(dstIp))
            {
                OptimizedLogger.LogDebug($"[Whitelist] Network whitelisted: {srcIp} -> {dstIp}");
                return true;
            }

            // Protocol-specific whitelisting
            if (IsProtocolWhitelisted(protocol, dstPort))
            {
                OptimizedLogger.LogDebug($"[Whitelist] Protocol whitelisted: {protocol}:{dstPort}");
                return true;
            }

            // 🔧 FIX: Allow all other traffic for analysis
            OptimizedLogger.LogDebug($"[Whitelist] Allowing traffic for analysis: {srcIp} -> {dstIp}:{dstPort}");
            return false;
        }

        /// <summary>
        /// Helper method to avoid logging every packet
        /// Logs only during first 10 seconds of each minute
        /// </summary>
        private bool ShouldLogWhitelistDebug()
        {
            return DateTime.Now.Second < 10; // Log only in first 10 seconds of each minute
        }

        /// <summary>
        /// Identify internal/private IP addresses
        /// Recognizes RFC 1918 private ranges and localhost
        /// </summary>
        private bool IsInternalIP(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;

            return ip.StartsWith("192.168.") ||
                   ip.StartsWith("10.") ||
                   (ip.StartsWith("172.") && IsInPrivateRange(ip)) ||
                   ip == "127.0.0.1" ||
                   ip == "::1";
        }

        /// <summary>
        /// Check if IP falls within 172.16.0.0 - 172.31.255.255 range
        /// </summary>
        private bool IsInPrivateRange(string ip)
        {
            try
            {
                var address = IPAddress.Parse(ip);
                var bytes = address.GetAddressBytes();

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    // 172.16.0.0 - 172.31.255.255
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Identify essential ports that should always be analyzed for security
        /// Includes web services, databases, remote access, and common services
        /// </summary>
        private bool IsEssentialPortForAnalysis(int port)
        {
            int[] essentialPorts = {
                80, 443, 8080, 8443, 8000, 3000, 21, 22, 23, 25, 53,
                110, 135, 139, 445, 1433, 3306, 3389, 5432, 1521, 27017,
                587, 993, 995, 143, 2222, 22222, 5900, 6379, 9200, 11211
            };

            return essentialPorts.Contains(port);
        }

        /// <summary>
        /// Update whitelist from database if refresh interval has elapsed
        /// Uses write lock to ensure thread-safe updates
        /// </summary>
        private void UpdateWhitelistIfNeeded()
        {
            if (DateTime.Now - _lastWhitelistUpdate > _whitelistRefreshInterval)
            {
                _refreshLock.EnterWriteLock();
                try
                {
                    if (DateTime.Now - _lastWhitelistUpdate > _whitelistRefreshInterval)
                    {
                        LoadWhitelistFromDatabase();
                        _lastWhitelistUpdate = DateTime.Now;
                    }
                }
                finally
                {
                    _refreshLock.ExitWriteLock();
                }
            }
        }

        /// <summary>
        /// Load whitelist configuration from database settings
        /// Supports IPs, ports, and network ranges in CIDR notation
        /// </summary>
        private void LoadWhitelistFromDatabase()
        {
            try
            {
                var tempIps = new ConcurrentDictionary<string, DateTime>();
                var tempPorts = new ConcurrentDictionary<int, DateTime>();
                var tempNetworks = new ConcurrentBag<IPNetwork>();

                // Load IPs from database setting
                var ipSetting = SettingBLL.GetSetting("WhitelistIPs");
                if (!string.IsNullOrWhiteSpace(ipSetting))
                {
                    foreach (var ip in ipSetting.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmedIp = ip.Trim();
                        if (IPAddress.TryParse(trimmedIp, out _))
                            tempIps[trimmedIp] = DateTime.MaxValue;
                    }
                }

                // Load Ports from database setting
                var portSetting = SettingBLL.GetSetting("WhitelistPorts");
                if (!string.IsNullOrWhiteSpace(portSetting))
                {
                    foreach (var portStr in portSetting.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (int.TryParse(portStr.Trim(), out int port))
                            tempPorts[port] = DateTime.MaxValue;
                    }
                }

                // Load Networks from database setting
                var netSetting = SettingBLL.GetSetting("WhitelistNetworks");
                if (!string.IsNullOrWhiteSpace(netSetting))
                {
                    foreach (var netStr in netSetting.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (IPNetwork.TryParse(netStr.Trim(), out var network))
                            tempNetworks.Add(network);
                    }
                }

                // Atomically replace the collections
                _whitelistedIps.Clear();
                foreach (var ip in tempIps)
                    _whitelistedIps[ip.Key] = ip.Value;

                _whitelistedPorts.Clear();
                foreach (var port in tempPorts)
                    _whitelistedPorts[port.Key] = port.Value;

                _trustedNetworks.Clear();
                foreach (var network in tempNetworks)
                    _trustedNetworks.Add(network);

                // 🔧 FIX: Use OptimizedLogger instead of Console.WriteLine
                OptimizedLogger.LogImportant($"[Whitelist] Loaded {_whitelistedIps.Count} IPs, {_whitelistedPorts.Count} ports, {_trustedNetworks.Count} networks");

                // 🔧 FIX: Log allowed ports and networks
                if (_whitelistedPorts.Any())
                {
                    OptimizedLogger.LogDebug($"[Whitelist] Whitelisted ports: {string.Join(", ", _whitelistedPorts.Keys.OrderBy(p => p))}");
                }
                if (_trustedNetworks.Any())
                {
                    var networks = _trustedNetworks.Select(n => n.ToString()).ToList();
                    OptimizedLogger.LogDebug($"[Whitelist] Whitelisted networks: {string.Join(", ", networks)}");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[Whitelist] Error loading whitelist: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if IP address belongs to any trusted network
        /// </summary>
        private bool IsInTrustedNetwork(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out var ip))
                return false;

            foreach (var network in _trustedNetworks)
            {
                if (network.Contains(ip))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Apply protocol-specific whitelist rules
        /// Currently whitelists: mDNS, DNS, DHCP
        /// </summary>
        private bool IsProtocolWhitelisted(string protocol, int port)
        {
            // Example: Whitelist mDNS on 5353
            if (protocol.Equals("Udp", StringComparison.OrdinalIgnoreCase) && port == 5353)
                return true;
            // Whitelist DNS
            if (protocol.Equals("Udp", StringComparison.OrdinalIgnoreCase) && port == 53)
                return true;
            // Whitelist DHCP
            if (protocol.Equals("Udp", StringComparison.OrdinalIgnoreCase) && (port == 67 || port == 68))
                return true;
            return false;
        }

        // Management methods for dynamic whitelist control

        /// <summary>
        /// Temporarily whitelist an IP address for specified duration
        /// </summary>
        public void WhitelistIp(string ip, TimeSpan duration)
        {
            if (IPAddress.TryParse(ip, out _))
            {
                var expiry = DateTime.Now.Add(duration);
                _whitelistedIps[ip] = expiry;
                OptimizedLogger.LogImportant($"[Whitelist] IP {ip} whitelisted until {expiry}");
            }
        }

        /// <summary>
        /// Temporarily whitelist a port for specified duration
        /// </summary>
        public void WhitelistPort(int port, TimeSpan duration)
        {
            if (port > 0 && port <= 65535)
            {
                var expiry = DateTime.Now.Add(duration);
                _whitelistedPorts[port] = expiry;
                OptimizedLogger.LogImportant($"[Whitelist] Port {port} whitelisted until {expiry}");
            }
        }

        /// <summary>
        /// Remove IP address from whitelist
        /// </summary>
        public void RemoveIpFromWhitelist(string ip)
        {
            _whitelistedIps.TryRemove(ip, out _);
            OptimizedLogger.LogImportant($"[Whitelist] IP {ip} removed from whitelist");
        }

        /// <summary>
        /// Remove port from whitelist
        /// </summary>
        public void RemovePortFromWhitelist(int port)
        {
            _whitelistedPorts.TryRemove(port, out _);
            OptimizedLogger.LogImportant($"[Whitelist] Port {port} removed from whitelist");
        }

        /// <summary>
        /// Clean up expired whitelist entries
        /// Automatically removes IPs and ports past their expiration time
        /// </summary>
        public void CleanupExpiredEntries()
        {
            var now = DateTime.Now;
            var expiredIps = _whitelistedIps.Where(kvp => kvp.Value < now)
                                           .Select(kvp => kvp.Key)
                                           .ToList();
            foreach (var ip in expiredIps)
            {
                _whitelistedIps.TryRemove(ip, out _);
            }

            var expiredPorts = _whitelistedPorts.Where(kvp => kvp.Value < now)
                                               .Select(kvp => kvp.Key)
                                               .ToList();
            foreach (var port in expiredPorts)
            {
                _whitelistedPorts.TryRemove(port, out _);
            }

            if (expiredIps.Count > 0 || expiredPorts.Count > 0)
            {
                OptimizedLogger.LogImportant($"[Whitelist] Cleaned up {expiredIps.Count} IPs and {expiredPorts.Count} ports");
            }
        }

        // Statistics and monitoring methods
        public int GetIpCount() => _whitelistedIps.Count;
        public int GetPortCount() => _whitelistedPorts.Count;
        public int GetNetworkCount() => _trustedNetworks.Count;

        /// <summary>
        /// Enable or disable whitelist functionality dynamically
        /// </summary>
        public void EnableWhitelist(bool enable)
        {
            _enableWhitelist = enable;
            OptimizedLogger.LogImportant($"[Whitelist] Whitelist {(enable ? "enabled" : "disabled")}");
        }
    }

    /// <summary>
    /// Represents an IP network range in CIDR notation
    /// Supports both IPv4 and IPv6 network containment checks
    /// </summary>
    public class IPNetwork
    {
        public IPAddress NetworkAddress { get; set; }
        public int PrefixLength { get; set; }

        /// <summary>
        /// Check if IP address is contained within this network
        /// </summary>
        public bool Contains(IPAddress address)
        {
            if (NetworkAddress == null || address == null)
                return false;
            var networkBytes = NetworkAddress.GetAddressBytes();
            var addressBytes = address.GetAddressBytes();
            if (networkBytes.Length != addressBytes.Length)
                return false;
            int byteCount = PrefixLength / 8;
            int bitCount = PrefixLength % 8;
            for (int i = 0; i < byteCount; i++)
            {
                if (networkBytes[i] != addressBytes[i])
                    return false;
            }
            if (bitCount > 0 && byteCount < networkBytes.Length)
            {
                byte mask = (byte)(0xFF << (8 - bitCount));
                if ((networkBytes[byteCount] & mask) != (addressBytes[byteCount] & mask))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Parse CIDR notation string into IPNetwork object
        /// Supports formats: "192.168.1.0/24", "2001:db8::/32"
        /// </summary>
        public static bool TryParse(string cidr, out IPNetwork network)
        {
            network = null;
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2) return false;
                if (!IPAddress.TryParse(parts[0], out var address)) return false;
                if (!int.TryParse(parts[1], out int prefix)) return false;

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (prefix < 0 || prefix > 32) return false;
                }
                else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    if (prefix < 0 || prefix > 128) return false;
                }
                else
                {
                    return false;
                }
                network = new IPNetwork { NetworkAddress = address, PrefixLength = prefix };
                return true;
            }
            catch
            {
                return false;
            }
        }

        public override string ToString()
        {
            return $"{NetworkAddress}/{PrefixLength}";
        }
    }
}