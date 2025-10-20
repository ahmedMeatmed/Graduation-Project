using IDSApp.BLL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Helper
{
    /// <summary>
    /// Dynamic configuration management system for Intrusion Detection System
    /// 
    /// Main Responsibilities:
    /// - Centralized access to all IDS configuration settings
    /// - Real-time configuration updates without system restart
    /// - Type-safe configuration value retrieval with fallback defaults
    /// - Performance optimization through cached settings
    /// 
    /// Configuration Categories:
    /// - Threat Detection Thresholds (port scanning, deauthentication, DDoS)
    /// - Performance Settings (timeouts, limits, logging)
    /// - Protocol Inspection Toggles (HTTP, TLS, etc.)
    /// - Network Definitions (IP ranges, service ports)
    /// - System Behavior (cleanup intervals, deduplication windows)
    /// 
    /// Features:
    /// - Default value fallback for missing settings
    /// - Automatic type conversion for configuration values
    /// - Cache refresh capability for runtime updates
    /// - Comprehensive coverage of IDS operational parameters
    /// </summary>
    internal class DynamicIDSConfig
    {
        // Threat Detection Thresholds
        /// <summary>
        /// Maximum number of port scan attempts before triggering alert
        /// Used for detecting horizontal and vertical port scanning
        /// </summary>
        public int PortScanThreshold => SettingBLL.GetPortScanThreshold();

        /// <summary>
        /// Maximum deauthentication frames before triggering alert
        /// Detects Wi-Fi deauthentication attacks and rogue access points
        /// </summary>
        public int DeauthThreshold => SettingBLL.GetDeauthThreshold();

        /// <summary>
        /// Minimum HTTP body content length to trigger threat analysis
        /// Filters out small requests to optimize performance
        /// </summary>
        public int HttpBodyThreatThreshold => SettingBLL.GetHttpBodyThreatThreshold();

        /// <summary>
        /// DDoS detection threshold based on bytes per second
        /// Triggers when traffic volume exceeds this byte count threshold
        /// </summary>
        public double DdosByteThreshold => double.Parse(SettingBLL.GetSetting("DdosByteThreshold"));

        /// <summary>
        /// DDoS detection threshold based on packets per second
        /// Triggers when packet rate exceeds this count threshold
        /// </summary>
        public int DdosPacketThreshold => int.Parse(SettingBLL.GetSetting("DdosPacketThreshold"));

        // Performance and Resource Management
        /// <summary>
        /// Interval for automatic cleanup of expired flows and cache entries
        /// Prevents memory leaks and maintains system performance
        /// </summary>
        public TimeSpan CleanupInterval => TimeSpan.FromMinutes(SettingBLL.GetSetting("CleanupIntervalMinutes", 5));

        /// <summary>
        /// Maximum allowed processing time per packet in milliseconds
        /// Ensures real-time performance and prevents system overload
        /// </summary>
        public int MaxPacketProcessingTimeMs => SettingBLL.GetSetting("MaxPacketProcessingTimeMs", 100);

        /// <summary>
        /// Timeout period for network flow tracking and correlation
        /// Determines how long inactive flows are maintained in memory
        /// </summary>
        public int FlowTimeoutMinutes => SettingBLL.GetSetting("FlowTimeoutMinutes", 10);

        /// <summary>
        /// Maximum number of concurrent network flows to track
        /// Prevents memory exhaustion during high traffic periods
        /// </summary>
        public int MaxFlowCount => SettingBLL.GetSetting("MaxFlowCount", 10000);

        // Protocol Inspection Controls
        /// <summary>
        /// Enable/disable deep packet inspection for HTTP traffic
        /// When disabled, only basic HTTP analysis is performed
        /// </summary>
        public bool EnableHttpInspection => SettingBLL.GetSetting("EnableHttpInspection", true);

        /// <summary>
        /// Enable/disable TLS/SSL traffic inspection and analysis
        /// Includes certificate validation and handshake analysis
        /// </summary>
        public bool EnableTlsInspection => SettingBLL.GetSetting("EnableTlsInspection", true);

        // Alert Management
        /// <summary>
        /// Time window for alert deduplication to prevent flooding
        /// Similar alerts within this window are grouped together
        /// </summary>
        public TimeSpan AlertDeduplicationWindow => TimeSpan.FromMinutes(SettingBLL.GetSetting("AlertDeduplicationMinutes", 1));

        // Network Configuration
        /// <summary>
        /// IP address prefix defining internal network boundaries
        /// Used for distinguishing internal vs external traffic
        /// </summary>
        public string InternalIpPrefix => SettingBLL.GetInternalIpPrefix();

        /// <summary>
        /// Comma-separated list of HTTP service ports for inspection
        /// Defines which ports should be treated as HTTP/HTTPS traffic
        /// </summary>
        public string GetHttpPorts => SettingBLL.GetSetting("HTTP_PORTS");

        /// <summary>
        /// Comma-separated list of SIP (VoIP) service ports
        /// Enables Session Initiation Protocol traffic analysis
        /// </summary>
        public string GetSipPorts => SettingBLL.GetSetting("SIP_PORTS");

        /// <summary>
        /// Comma-separated list of authorized DNS servers
        /// Used for detecting DNS hijacking and rogue DNS servers
        /// </summary>
        public string GetDnsServers => SettingBLL.GetSetting("DNS_SERVERS");

        /// <summary>
        /// IP range definition for external/untrusted networks
        /// Used for threat scoring and access control decisions
        /// </summary>
        public string GetExternalNetwork => SettingBLL.GetSetting("EXTERNAL_NET");

        // System Monitoring
        /// <summary>
        /// Enable/disable detailed performance metrics logging
        /// When enabled, logs processing times and resource usage
        /// </summary>
        public bool EnablePerformanceLogging => SettingBLL.GetEnablePerformanceLogging();

        /// <summary>
        /// Force refresh of all configuration settings from data source
        /// Useful for runtime configuration updates without restart
        /// </summary>
        public void RefreshConfig()
        {
            SettingBLL.RefreshSettingsCache();
        }

        // Additional configuration properties can be added here as needed
        // The pattern ensures type safety with fallback default values
    }
}