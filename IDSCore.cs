using IDSApp.BLL;
using IDSApp.Entity;
using IDSApp.Helper;
using IDSApp.ProtocolParsing;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;

namespace IDSApp
{
    /// <summary>
    /// Main Intrusion Detection System core engine
    /// </summary>
    public class IDSCore : IDisposable
    {

        private readonly RuleStatistics _ruleStatistics;
        private bool isRunning = false;
        private bool _disposed = false;
        private ILiveDevice captureDevice;
        private string selectedDeviceName = string.Empty;
        private readonly DynamicIDSConfig _config = new DynamicIDSConfig();
        private readonly PerformanceSettings _perfSettings = PerformanceSettings.LoadFromSettings();
        private readonly ConcurrentDictionary<string, HashSet<int>> ipPortAccess = new();
        private readonly ConcurrentDictionary<string, int> deauthCounters = new();
        private readonly ConcurrentDictionary<string, FlowInfo> flows = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
        // New caches for improved deduplication and flow-aware alert throttling
        private readonly ConcurrentDictionary<string, (DateTime lastAlert, int lastPacketCount)> _recentAlertsFlowCache = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentLogsCache = new();
        private BlockingCollection<PacketCaptureWrapper> _packetQueue;
        private CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly List<Task> _workerTasks = new List<Task>();
        private int _workerCount;
        private readonly EnhancedSignatureRuleEngine _ruleEngine = new EnhancedSignatureRuleEngine();
        private readonly SshParser _sshParser = new SshParser();
        private readonly TelnetParser _telnetParser = new TelnetParser();
        private readonly FtpParser _ftpParser = new FtpParser();
        private readonly TlsParser _tlsParser = new TlsParser();
        private readonly DnsParser _dnsParser = new DnsParser();
        private readonly RdpParser _rdpParser = new RdpParser();
        private readonly SmbParser _smbParser = new SmbParser();
        private LdapParser _ldapParser = new LdapParser();

        private readonly EnhancedSmbParser _enhancedSmbParser = new EnhancedSmbParser();
        private readonly SmbBruteForceDetector _smbBruteForceDetector = new SmbBruteForceDetector();
        private readonly SmbProcessingOptimizations _smbOptimizations = new SmbProcessingOptimizations();
        private readonly IDSApp.ProtocolParsing.HttpParser _httpParser = new IDSApp.ProtocolParsing.HttpParser();
        private readonly NtpParser _ntpParser = new NtpParser();
        private readonly NetbiosParser _netbiosParser = new NetbiosParser();
        private readonly SmtpParser _smtpParser = new SmtpParser();
        private long _totalPacketsProcessed = 0;
        private long _totalProcessingTimeMs = 0;
        private long _errorCount = 0;
        private long _rulesChecked = 0;
        private long _rulesMatched = 0;
        private System.Timers.Timer cleanupTimer;
        private System.Timers.Timer statsTimer;
        private readonly PerformanceMonitor _perfMonitor = new PerformanceMonitor();
        private readonly ConcurrentDictionary<string, DateTime> _recentRuleChecks = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentAlertsCache = new();
        private readonly TimeSpan _alertDedupWindow = TimeSpan.FromSeconds(10);
        private readonly IpReassemblyManager _ipReassemblyManager = new IpReassemblyManager();
        private readonly TcpStreamReassembler _tcpStreamReassembler = new TcpStreamReassembler();

        // Offline / PCAP mode toggle (read from settings in ctor)
        private readonly bool _isOfflineMode;

        // simple skipped packets counter for PCAP analysis reporting
        private long _skippedPackets = 0;

        // Alert deduplication structures
        private readonly ConcurrentDictionary<string, DateTime> _recentDdosAlerts = new();
        private readonly TimeSpan _ddosAlertInterval = TimeSpan.FromMinutes(2);
        private readonly ConcurrentDictionary<string, DateTime> _recentPortScans = new();

        // Deduplication cooldown caches (Snort/Suricata-like behavior)
        private readonly ConcurrentDictionary<string, DateTime> _alertCooldown = new();
        private readonly ConcurrentDictionary<string, DateTime> _logCooldown = new();
        private readonly TimeSpan _alertCooldownTime = TimeSpan.FromSeconds(60); // alert suppression window
        private readonly TimeSpan _logCooldownTime = TimeSpan.FromSeconds(30); // log suppression window
        private readonly System.Timers.Timer _cooldownCleanupTimer;

        private readonly TimeSpan _portScanAlertInterval = TimeSpan.FromMinutes(5);

        // Represents network flow information
        private class FlowInfo
        {
            public DateTime FirstSeen { get; set; }
            public DateTime LastSeen { get; set; }
            public int PacketCount { get; set; }
            public long TotalBytes { get; set; }
        }

        // ALERT deduplication - stable key (no timestamp in key)
        private bool CanInsertAlert(string message, string srcIp, string dstIp)
        {
            try
            {
                // If offline mode (PCAP) is enabled we bypass alert cooldown/dedup to analyze everything
                if (_isOfflineMode) return true;

                string key = $"{message}:{srcIp}->{dstIp}";
                if (_alertCooldown.TryGetValue(key, out var last))
                {
                    if ((DateTime.Now - last) < _alertCooldownTime)
                        return false;
                }

                _alertCooldown[key] = DateTime.Now;
                return true;
            }
            catch
            {
                return true;
            }
        }

        // LOG deduplication - add protocol/direction to avoid false skips
        private bool CanInsertLog(string message, string srcIp, string dstIp, string direction, string protocol)
        {
            try
            {
                // If offline mode (PCAP) is enabled we bypass log cooldown/dedup to analyze everything
                if (_isOfflineMode) return true;

                string key = $"{message}:{srcIp}->{dstIp}:{protocol}:{direction}";
                if (_logCooldown.TryGetValue(key, out var last))
                {
                    if ((DateTime.Now - last) < _logCooldownTime)
                        return false;
                }

                _logCooldown[key] = DateTime.Now;
                return true;
            }
            catch
            {
                return true;
            }
        }

        // Wrapper to centralize Log insertion with cooldown
        private int InsertLogIfAllowed(DateTime timestamp,
     string sourceIp,
     string destinationIp,
     int packetSize,
     bool isMalicious,
     string protocolName,
     string protocol,
     int srcPort,
     int destPort,
     int payloadSize,
     string tcpFlags,
     string flowDirection,
     int packetCount,
     double duration,
     int? matchedSignatureId,
     string info)
        {
            // messageKey uses info if present, otherwise protocolName, otherwise a generic label
            string messageKey = !string.IsNullOrEmpty(info) ? info
                                : !string.IsNullOrEmpty(protocolName) ? protocolName
                                : "GENERIC";

            // Local deduplication to avoid inserting the same packet/log many times in quick succession
            try
            {
                // Build a compact dedup key (include ports and packetCount optionally if you want stronger separation)
                string dedupKey = $"{sourceIp}-{destinationIp}-{protocol}-{srcPort}-{destPort}-{info ?? string.Empty}-{packetCount / 10}";

                // adaptive window: smaller in offline fast mode
                double dedupWindowSeconds = _isOfflineMode ? 0.4 : 0.2;


                if (_recentLogsCache.TryGetValue(dedupKey, out var lastInsertTime))
                {
                    if ((DateTime.Now - lastInsertTime).TotalSeconds < dedupWindowSeconds)
                    {
                        Interlocked.Increment(ref _skippedPackets);
                        OptimizedLogger.LogImportant($"[DEDUP-SKIP] Recent log exists for {dedupKey} (window {dedupWindowSeconds}s)");
                        return -2; // skip duplicate
                    }
                }

                // update the cache with the current time
                _recentLogsCache[dedupKey] = DateTime.Now;
            }
            catch (Exception ex)
            {
                // don't block logging if dedup fails — but record the issue for debugging
                OptimizedLogger.LogError($"[DEDUP-ERROR] InsertLog dedup failed: {ex.Message}");
            }

            // If NOT in offline mode, enforce the existing cooldown/dedup checks (CanInsertLog is assumed to exist)
            if (!_isOfflineMode)
            {
                try
                {
                    if (!CanInsertLog(messageKey, sourceIp, destinationIp, flowDirection, protocol))
                    {
                        Interlocked.Increment(ref _skippedPackets);
                        OptimizedLogger.LogImportant($"[SKIPPED] Log insertion skipped due to cooldown: {sourceIp}->{destinationIp} | {messageKey}");
                        return -2; // -2 indicates log skipped due to deduplication/cooldown
                    }
                }
                catch (Exception ex)
                {
                    // If CanInsertLog throws, log and continue to attempt DB insert (fail-safe)
                    OptimizedLogger.LogError($"[CAN-INSERT-ERROR] CanInsertLog threw an exception: {ex.Message}");
                }
            }

            try
            {
                // Insert log into DB (LogBLL.Insert is expected to return int ID or 0/-1 on error)
                int logId = LogBLL.Insert(
                    timestamp,
                    sourceIp,
                    destinationIp,
                    packetSize,
                    isMalicious,
                    protocolName,
                    protocol,
                    srcPort,
                    destPort,
                    payloadSize,
                    tcpFlags,
                    flowDirection,
                    packetCount,
                    duration,
                    matchedSignatureId,
                    info
                );

                if (logId > 0)
                {
                    OptimizedLogger.LogImportant($"[LOG-INSERTED] Log successfully inserted: {sourceIp}->{destinationIp} | {messageKey} (ID={logId})");
                }
                else if (logId == 0)
                {
                    OptimizedLogger.LogError($"[DB-FAIL] Insert executed but returned no ID (returned 0): {sourceIp}->{destinationIp} | {messageKey}");
                }

                return logId;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[DB-FAIL] InsertLog failed for {sourceIp}->{destinationIp} | Message: {messageKey} | Error: {ex.Message}");
                return -1; // -1 indicates real DB failure
            }
        }


        // Deduplication and logging wrapper for Alerts
        private bool InsertAlertIfAllowed(int logId, string message, string attackType, string severity,
                                          string sourceIp, string destinationIp, string assignedTo,
                                          DateTime timestamp, string status)
        {
            // In offline mode, bypass alert suppression to record all alerts for post-analysis
            if (!_isOfflineMode)
            {
                // Check deduplication cooldown
                if (!CanInsertAlert(message, sourceIp, destinationIp))
                {
                    OptimizedLogger.LogImportant($"[SKIPPED] Alert insertion skipped due to cooldown: {sourceIp}->{destinationIp} | {message}");
                    return false; // alert skipped
                }
            }

            try
            {
                // Insert alert into DB
                bool result = AlertBLL.Insert(logId, message, attackType, severity, sourceIp, destinationIp, assignedTo, timestamp, status);
                if (result)
                    OptimizedLogger.LogImportant($"[ALERT-INSERTED] Alert successfully inserted: {sourceIp}->{destinationIp} | {message}");
                return result;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[DB-FAIL] InsertAlert failed for {sourceIp}->{destinationIp} | Message: {message} | Error: {ex.Message}");
                return false; // DB failure
            }
        }

        /// <summary>
        /// Initializes a new instance of the IDS core
        /// </summary>
        public IDSCore()
        {
            _ruleStatistics = new RuleStatistics();
            _workerCount = _perfSettings.WorkerThreads;
            _packetQueue = new BlockingCollection<PacketCaptureWrapper>(_perfSettings.MaxQueueSize);

            // Read offline mode from settings (fall back to false)
            bool offlineSetting = false;
            try
            {
                var s = SettingBLL.GetSetting("CaptureMode");
                if (!string.IsNullOrEmpty(s) && s.Trim().ToLower() == "pcap") offlineSetting = true;
            }
            catch { /* ignore and use default */ }
            _isOfflineMode = offlineSetting;

            _cooldownCleanupTimer = new System.Timers.Timer(60000); // every minute
            _cooldownCleanupTimer.Elapsed += (s, e) => CleanupCooldownCaches();
            _cooldownCleanupTimer.Start();

            OptimizedLogger.LogImportant($"[CORE] Initialized with {_workerCount} workers, queue size: {_perfSettings.MaxQueueSize}, OfflineMode={_isOfflineMode}");
        }

        /// <summary>
        /// Helper to insert a log and optionally create an alert.
        /// Centralizes LogBLL.Insert and AlertBLL.Insert usage to reduce duplication.
        /// </summary>
        private int InsertLogAndMaybeAlert(DateTime timestamp,
            string src, string dst, int size, bool isAlert, string category, string subcategory,
            int srcPort, int dstPort, int payloadLen, string tcpFlags,
            string direction, int flowCount, double duration, int? matchedSigId, string message,
            bool createAlert = false, string alertTitle = null, string alertType = null, string severity = "Medium")
        {
            try
            {
                int logId = InsertLogIfAllowed(
                    timestamp,
                    src, dst, size, isAlert, category, subcategory,
                    srcPort, dstPort, payloadLen, tcpFlags,
                    direction, flowCount, duration, matchedSigId, message
                );

                if (createAlert && logId > 0)
                {
                    // Provide sensible defaults if not supplied
                    string atitle = alertTitle ?? message ?? category;
                    string atype = alertType ?? subcategory ?? category;
                    InsertAlertIfAllowed(logId, atitle, atype, severity,
                                    src ?? "SYSTEM", dst ?? "SYSTEM", "Administrator", DateTime.Now, "New");
                }
                return logId;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[LOG_HELPER] Failed to insert log/alert: {ex.Message}");
                return 0;
            }
        }

        private void CleanupCooldownCaches()
        {
            DateTime now = DateTime.Now;
            foreach (var kv in _logCooldown.Where(kv => (now - kv.Value) > TimeSpan.FromMinutes(5)).ToList())
                _logCooldown.TryRemove(kv.Key, out _);

            foreach (var kv in _alertCooldown.Where(kv => (now - kv.Value) > TimeSpan.FromMinutes(10)).ToList())
                _alertCooldown.TryRemove(kv.Key, out _);
            // Also cleanup recent log dedup cache and flow-alert cache to avoid unbounded growth
            try
            {
                var expiredLogKeys = _recentLogsCache.Where(kv => (DateTime.Now - kv.Value) > TimeSpan.FromSeconds(10)).Select(kv => kv.Key).ToList();
                foreach (var k in expiredLogKeys)
                    _recentLogsCache.TryRemove(k, out _);

                var expiredFlowAlerts = _recentAlertsFlowCache.Where(kv => (DateTime.Now - kv.Value.lastAlert) > TimeSpan.FromMinutes(5)).Select(kv => kv.Key).ToList();
                foreach (var k in expiredFlowAlerts)
                    _recentAlertsFlowCache.TryRemove(k, out _);
            }
            catch { /* ignore cleanup errors */ }

        }

        /// <summary>
        /// Starts the IDS core system
        /// </summary>
        public void Start()
        {
            if (isRunning)
            {
                OptimizedLogger.LogImportant("[CORE] IDS is already running");
                return;
            }

            isRunning = true;

            // Reinitialize cancellation token and queue for clean startup
            _cts = new CancellationTokenSource();
            _packetQueue = new BlockingCollection<PacketCaptureWrapper>(_perfSettings.MaxQueueSize);

            OptimizedLogger.LogImportant("[CORE] Starting IDS Core...");

            try
            {
                _ruleEngine.LoadRules();
                int ruleCount = _ruleEngine.GetActiveRulesCount();

                int ruleLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    false,
                    "SYSTEM_STARTUP",
                    "CONFIGURATION",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Rule engine initialized with {ruleCount} rules"
                );

                if (ruleCount == 0)
                {
                    int alertLogId = InsertLogAndMaybeAlert(DateTime.Now,
                        "SYSTEM",
                        "SYSTEM",
                        0,
                        true,
                        "CONFIGURATION_ERROR",
                        "SECURITY",
                        0, 0, 0, "",
                        "internal",
                        1, 0.0, null,
                        "CRITICAL: Rule engine has 0 rules - security compromised", false, "No detection rules loaded", "Configuration Error", "Critical");
                    OptimizedLogger.LogError("[CORE] CRITICAL: Rule engine has 0 rules!");
                }
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogAndMaybeAlert(DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    true,
                    "SYSTEM_ERROR",
                    "CONFIGURATION",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Failed to initialize rule engine: {ex.Message}", false, "Rule engine initialization failed", "Configuration Error", "High");
                OptimizedLogger.LogError($"[CORE] Failed to initialize rule engine: {ex.Message}");
            }

            _perfSettings.Refresh();

            // Initialize worker threads for packet processing
            _workerTasks.Clear();
            _workerCount = Math.Max(2, Environment.ProcessorCount / 2);

            for (int i = 0; i < _workerCount; i++)
            {
                _workerTasks.Add(Task.Run(() => ProcessPackets(_cts.Token)));
            }

            OptimizedLogger.LogImportant($"[CORE] Starting with {_workerCount} workers, queue size: {_perfSettings.MaxQueueSize}, OfflineMode={_isOfflineMode}");

            // Start packet capture from configured source
            bool captureStarted = StartPcapCapture();
            if (!captureStarted)
            {
                captureStarted = StartLiveCapture();
            }

            if (!captureStarted)
            {
                int captureLogId = InsertLogAndMaybeAlert(DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    true,
                    "SYSTEM_ERROR",
                    "CAPTURE",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    "Failed to start packet capture - IDS stopped", true, "Packet capture initialization failed", "System Error", "High");

                OptimizedLogger.LogError("[CORE] Failed to start capture - stopping IDS");
                Stop();
                return;
            }

            StartTimers();

            int startLogId = InsertLogAndMaybeAlert(DateTime.Now,
                "SYSTEM",
                "SYSTEM",
                0,
                false,
                "SYSTEM_STARTUP",
                "SYSTEM",
                0, 0, 0, "",
                "internal",
                1, 0.0, null,
                "IDS Core started successfully with packet capture", false, "IDS Core started successfully", "System Startup", "Low");

            OptimizedLogger.LogImportant("[CORE] IDS Core started successfully");
        }

        /// <summary>
        /// Starts background timers for system maintenance
        /// </summary>
        private void StartTimers()
        {
            cleanupTimer = new System.Timers.Timer(60000);
            cleanupTimer.Elapsed += (s, e) => CleanupOldData();
            cleanupTimer.Start();

            statsTimer = new System.Timers.Timer(30000);
            statsTimer.Elapsed += (s, e) => LogStatistics();
            statsTimer.Start();
        }

        /// <summary>
        /// Cleans up old data from internal structures
        /// </summary>
        private void CleanupOldData()
        {
            try
            {
                var now = DateTime.Now;

                // Cleanup TCP stream reassembler
                _tcpStreamReassembler.CleanupOldConnections(TimeSpan.FromMinutes(10));

                // Cleanup SMB optimizations
                _smbOptimizations.CleanupOldSessions();

                var expiredFlows = flows.Where(f => (now - f.Value.LastSeen).TotalMinutes > 30).ToList();
                foreach (var flow in expiredFlows)
                {
                    flows.TryRemove(flow.Key, out _);
                }

                var expiredAlerts = _recentAlerts.Where(a => (now - a.Value) > _config.AlertDeduplicationWindow).ToList();
                foreach (var alert in expiredAlerts)
                {
                    _recentAlerts.TryRemove(alert.Key, out _);
                }

                var expiredRuleChecks = _recentRuleChecks.Where(r => (now - r.Value) > TimeSpan.FromMinutes(5)).ToList();
                foreach (var check in expiredRuleChecks)
                {
                    _recentRuleChecks.TryRemove(check.Key, out _);
                }

                // Cleanup DDoS alert history
                var expiredDdosAlerts = _recentDdosAlerts.Where(a => (now - a.Value) > TimeSpan.FromHours(2)).ToList();
                foreach (var alert in expiredDdosAlerts)
                {
                    _recentDdosAlerts.TryRemove(alert.Key, out _);
                }

                // Cleanup port scan alert history
                var expiredPortScans = _recentPortScans.Where(a => (now - a.Value) > TimeSpan.FromHours(2)).ToList();
                foreach (var scan in expiredPortScans)
                {
                    _recentPortScans.TryRemove(scan.Key, out _);
                }

                // Cleanup deduplication cooldown caches
                var expiredAlertKeys = _alertCooldown.Where(a => (now - a.Value) > _alertCooldownTime).Select(a => a.Key).ToList();
                foreach (var k in expiredAlertKeys)
                {
                    _alertCooldown.TryRemove(k, out _);
                }
                var expiredLogKeys = _logCooldown.Where(a => (now - a.Value) > _logCooldownTime).Select(a => a.Key).ToList();
                foreach (var k in expiredLogKeys)
                {
                    _logCooldown.TryRemove(k, out _);
                }

                if (expiredFlows.Count > 0 || expiredAlerts.Count > 0)
                {
                    int cleanupLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        "SYSTEM",
                        "SYSTEM",
                        0,
                        false,
                        "SYSTEM_MAINTENANCE",
                        "CLEANUP",
                        0, 0, 0, "",
                        "internal",
                        expiredFlows.Count + expiredAlerts.Count, 0.0, null,
                        $"Cleanup removed {expiredFlows.Count} flows, {expiredAlerts.Count} alerts, {expiredRuleChecks.Count} rule checks"
                    );
                }

                OptimizedLogger.LogImportant($"[CLEANUP] Removed {expiredFlows.Count} flows, {expiredAlerts.Count} alerts, {expiredRuleChecks.Count} rule checks");
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    false,
                    "SYSTEM_ERROR",
                    "CLEANUP",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Error during cleanup: {ex.Message}"
                );
                OptimizedLogger.LogError($"[CLEANUP] Error during cleanup: {ex.Message}");
            }
        }

        /// <summary>
        /// Starts packet capture from PCAP file
        /// </summary>
        private bool StartPcapCapture()
        {
            string pcapFile = SettingBLL.GetSetting("PcapFilePath");

            if (string.IsNullOrEmpty(pcapFile) || !File.Exists(pcapFile))
            {
                OptimizedLogger.LogImportant($"PCAP file not found: {pcapFile}");
                return false;
            }

            try
            {
                int pcapStartLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    false,
                    "CAPTURE_START",
                    "PCAP",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Reading packets from PCAP file: {pcapFile}"
                );

                OptimizedLogger.LogImportant($"[PCAP] Reading packets from {pcapFile}");

                var device = new CaptureFileReaderDevice(pcapFile);
                device.Open();

                var packets = new List<RawCapture>();

                PacketCapture packetCapture;
                GetPacketStatus status;

                while ((status = device.GetNextPacket(out packetCapture)) == GetPacketStatus.PacketRead)
                {
                    var rawCapture = packetCapture.GetPacket();
                    if (rawCapture != null)
                    {
                        packets.Add(rawCapture);

                        if (packets.Count >= 100)
                        {
                            foreach (var pkt in packets)
                            {
                                if (!_packetQueue.IsAddingCompleted)
                                {
                                    _packetQueue.Add(new PacketCaptureWrapper(pkt));
                                }
                            }
                            packets.Clear();
                        }
                    }
                }

                // Add remaining packets
                foreach (var pkt in packets)
                {
                    if (!_packetQueue.IsAddingCompleted)
                    {
                        _packetQueue.Add(new PacketCaptureWrapper(pkt));
                    }
                }

                device.Close();

                if (!_packetQueue.IsAddingCompleted)
                {
                    _packetQueue.CompleteAdding();
                }

                int pcapCompleteLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    false,
                    "CAPTURE_COMPLETE",
                    "PCAP",
                    0, 0, 0, "",
                    "internal",
                    packets.Count, 0.0, null,
                    $"PCAP file processing completed. Status: {status}"
                );

                OptimizedLogger.LogImportant($"[PCAP] Loaded all packets into queue. Status: {status}");

                return true;
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogAndMaybeAlert(DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    true,
                    "CAPTURE_ERROR",
                    "PCAP",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Error reading PCAP file: {ex.Message}", true, "PCAP file read error", "Capture Error", "Medium");

                OptimizedLogger.LogError($"[PCAP] Error reading PCAP file: {ex.Message}");

                // Ensure queue is completed even on error
                if (!_packetQueue.IsAddingCompleted)
                {
                    _packetQueue.CompleteAdding();
                }

                return false;
            }
        }

        /// <summary>
        /// Starts live packet capture from network interface
        /// </summary>
        private bool StartLiveCapture()
        {
            selectedDeviceName = SettingBLL.GetSetting("NetworkInterface");
            if (string.IsNullOrEmpty(selectedDeviceName))
            {
                int configLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    true,
                    "CONFIGURATION_ERROR",
                    "CAPTURE",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    "No network interface selected for live capture"
                );
                OptimizedLogger.LogError("No network interface selected for live capture.");
                return false;
            }

            foreach (var dev in CaptureDeviceList.Instance)
            {
                if (dev.Description.Trim().ToLower().Contains(selectedDeviceName.Trim().ToLower()))
                {
                    try
                    {
                        captureDevice = dev;
                        captureDevice.OnPacketArrival += OnPacketArrival;
                        captureDevice.Open(DeviceModes.Promiscuous, 1000);
                        captureDevice.Filter = "ip or tcp or udp or icmp";
                        captureDevice.StartCapture();

                        int liveStartLogId = InsertLogIfAllowed(
                            DateTime.Now,
                            "SYSTEM",
                            "SYSTEM",
                            0,
                            false,
                            "CAPTURE_START",
                            "LIVE",
                            0, 0, 0, "",
                            "internal",
                            1, 0.0, null,
                            $"Started live capture on {dev.Description}"
                        );

                        OptimizedLogger.LogImportant($"Capturing live on {dev.Description}");
                        return true;
                    }
                    catch (Exception ex)
                    {
                        int errorLogId = InsertLogAndMaybeAlert(DateTime.Now,
                            "SYSTEM",
                            "SYSTEM",
                            0,
                            true,
                            "CAPTURE_ERROR",
                            "LIVE",
                            0, 0, 0, "",
                            "internal",
                            1, 0.0, null,
                            $"Error opening live capture on '{dev.Description}': {ex.Message}", true, "Live capture initialization failed", "Capture Error", "High");

                        OptimizedLogger.LogError($"Error opening live capture on '{dev.Description}': {ex.Message}");
                        return false;
                    }
                }
            }

            int deviceLogId = InsertLogIfAllowed(
                DateTime.Now,
                "SYSTEM",
                "SYSTEM",
                0,
                true,
                "CONFIGURATION_ERROR",
                "CAPTURE",
                0, 0, 0, "",
                "internal",
                1, 0.0, null,
                $"Live capture device matching '{selectedDeviceName}' not found"
            );

            OptimizedLogger.LogError($"Live capture device matching '{selectedDeviceName}' not found.");
            return false;
        }

        /// <summary>
        /// Handles packet arrival events from live capture
        /// </summary>
        private void OnPacketArrival(object sender, PacketCapture e)
        {
            if (!isRunning) return;

            try
            {
                var rawCapture = e.GetPacket();
                var wrapper = new PacketCaptureWrapper(rawCapture);

                if (!_packetQueue.TryAdd(wrapper, 50))
                {
                    Interlocked.Increment(ref _errorCount);

                    int dropLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        "UNKNOWN",
                        "UNKNOWN",
                        rawCapture.Data.Length,
                        false,
                        "QUEUE_OVERFLOW",
                        "SYSTEM",
                        0, 0, 0, "",
                        "internal",
                        1, 0.0, null,
                        $"Packet dropped - queue full (Len={rawCapture.Data.Length})"
                    );

                    OptimizedLogger.LogQueue($"Packet dropped - queue full (Len={rawCapture.Data.Length})");
                }
                else
                {
                    OptimizedLogger.LogQueue($"Packet queued (Len={rawCapture.Data.Length})");
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _errorCount);

                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "UNKNOWN",
                    "UNKNOWN",
                    0,
                    false,
                    "PROCESSING_ERROR",
                    "CAPTURE",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Error enqueuing packet: {ex.Message}"
                );

                OptimizedLogger.LogError($"Error enqueuing packet: {ex.Message}");
            }
        }
        /// <summary>
        /// Processes packets from the queue
        /// </summary>
        private async Task ProcessPackets(CancellationToken token)
        {
            OptimizedLogger.LogImportant($"[WORKER-{Thread.CurrentThread.ManagedThreadId}] Starting");

            var stopwatch = new Stopwatch();
            int processedCount = 0;
            long totalProcessingTime = 0;

            while (!token.IsCancellationRequested && !_packetQueue.IsCompleted)
            {
                try
                {
                    var wrapper = _packetQueue.Take(token);

                    stopwatch.Restart();
                    ProcessPacket(wrapper);
                    stopwatch.Stop();

                    processedCount++;
                    totalProcessingTime += stopwatch.ElapsedMilliseconds;

                    // Update global packet counter
                    OptimizedLogger.IncrementPacketCounter();

                    // Log performance periodically
                    if (processedCount % 1000 == 0)
                    {
                        var avgTime = totalProcessingTime / (double)processedCount;

                        int perfLogId = InsertLogIfAllowed(
                            DateTime.Now,
                            "SYSTEM",
                            "SYSTEM",
                            0,
                            false,
                            "PERFORMANCE",
                            "PROCESSING",
                            0, 0, 0, "",
                            "internal",
                            processedCount, avgTime, null,
                            $"Worker {Thread.CurrentThread.ManagedThreadId} processed {processedCount} packets, Avg: {avgTime:F2}ms"
                        );

                        OptimizedLogger.LogPerformance($"[WORKER-{Thread.CurrentThread.ManagedThreadId}] Processed {processedCount} packets, Avg: {avgTime:F2}ms");
                    }

                    // Implement backpressure for queue management
                    if (_packetQueue.Count > _packetQueue.BoundedCapacity * 0.7)
                    {
                        await Task.Delay(1, token);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (InvalidOperationException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _errorCount);

                    int errorLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        "WORKER_THREAD",
                        "SYSTEM",
                        0,
                        false,
                        "PROCESSING_ERROR",
                        "WORKER",
                        0, 0, 0, "",
                        "internal",
                        1, 0.0, null,
                        $"Worker thread error: {ex.Message}"
                    );

                    OptimizedLogger.LogError($"[WORKER-{Thread.CurrentThread.ManagedThreadId}] Error: {ex.Message}");
                    await Task.Delay(100, token);
                }
            }

            int stopLogId = InsertLogIfAllowed(
                DateTime.Now,
                "SYSTEM",
                "SYSTEM",
                0,
                false,
                "WORKER_STOP",
                "SYSTEM",
                0, 0, 0, "",
                "internal",
                processedCount, 0.0, null,
                $"Worker {Thread.CurrentThread.ManagedThreadId} stopped after {processedCount} packets"
            );

            OptimizedLogger.LogImportant($"[WORKER-{Thread.CurrentThread.ManagedThreadId}] Stopped after {processedCount} packets");
        }

        /// <summary>
        /// Processes individual packets
        /// </summary>
        private void ProcessPacket(PacketCaptureWrapper wrapper)
        {
            try
            {
                var packet = PacketDotNet.Packet.ParsePacket(wrapper.LinkLayerType, wrapper.Data);

                switch (wrapper.LinkLayerType)
                {
                    case LinkLayers.Ethernet:
                        if (packet is EthernetPacket ethPacket)
                            ProcessEthernet(ethPacket);
                        break;

                    case LinkLayers.Ieee80211:
                        ProcessWiFi(packet);
                        break;

                    default:
                        // create log for unsupported link layers
                        int unsupportedLogId = InsertLogIfAllowed(
                            DateTime.Now,
                            "UNKNOWN",
                            "UNKNOWN",
                            wrapper.Data.Length,
                            false,
                            "UNSUPPORTED_PROTOCOL",
                            "LINK_LAYER",
                            0, 0, 0, "",
                            "internal",
                            1, 0.0, null,
                            $"Unsupported link layer: {wrapper.LinkLayerType}"
                        );
                        OptimizedLogger.LogImportant($"Unsupported link layer: {wrapper.LinkLayerType}");
                        break;
                }
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "UNKNOWN",
                    "UNKNOWN",
                    wrapper.Data.Length,
                    false,
                    "PARSING_ERROR",
                    "PACKET",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Packet processing error: {ex.Message}"
                );
                OptimizedLogger.LogError($"Packet processing error: {ex.Message}");
            }
        }

        /// <summary>
        /// Stops the IDS core system
        /// </summary>
        public void Stop()
        {
            if (!isRunning) return;
            isRunning = false;

            OptimizedLogger.LogImportant("[STOP] Stopping IDS Core...");

            cleanupTimer?.Stop();
            statsTimer?.Stop();

            if (captureDevice != null)
            {
                try
                {
                    captureDevice.StopCapture();
                    captureDevice.Close();

                    int stopLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        "SYSTEM",
                        "SYSTEM",
                        0,
                        false,
                        "CAPTURE_STOP",
                        "SYSTEM",
                        0, 0, 0, "",
                        "internal",
                        1, 0.0, null,
                        "Capture device stopped successfully"
                    );

                    OptimizedLogger.LogImportant("[STOP] Capture device stopped");
                }
                catch (Exception ex)
                {
                    int errorLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        "SYSTEM",
                        "SYSTEM",
                        0,
                        true,
                        "SYSTEM_ERROR",
                        "CAPTURE",
                        0, 0, 0, "",
                        "internal",
                        1, 0.0, null,
                        $"Error stopping capture device: {ex.Message}"
                    );
                    OptimizedLogger.LogError($"[STOP] Error stopping capture device: {ex.Message}");
                }
            }

            _cts.Cancel();
            _packetQueue.CompleteAdding();

            try
            {
                Task.WaitAll(_workerTasks.ToArray(), TimeSpan.FromSeconds(30));

                int workersLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    false,
                    "SYSTEM_STOP",
                    "WORKERS",
                    0, 0, 0, "",
                    "internal",
                    _workerTasks.Count, 0.0, null,
                    "All worker threads stopped successfully"
                );

                OptimizedLogger.LogImportant("[STOP] All workers stopped");
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    "SYSTEM",
                    "SYSTEM",
                    0,
                    true,
                    "SYSTEM_ERROR",
                    "WORKERS",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Error waiting for workers: {ex.Message}"
                );
                OptimizedLogger.LogError($"[STOP] Error waiting for workers: {ex.Message}");
            }

            if (_config.EnablePerformanceLogging)
            {
                _ruleEngine.PrintPerformanceStats();
                LogStatistics();
            }

            int stopSystemLogId = InsertLogIfAllowed(
                DateTime.Now,
                "SYSTEM",
                "SYSTEM",
                0,
                false,
                "SYSTEM_STOP",
                "SYSTEM",
                0, 0, 0, "",
                "internal",
               (int)_totalPacketsProcessed
                , 0.0, null,
                $"IDS Core stopped successfully. Total packets processed: {_totalPacketsProcessed} | Skipped: {_skippedPackets}"
            );

            OptimizedLogger.LogImportant("[STOP] IDS Core stopped successfully");
        }


        /// <summary>
        /// Releases all resources used by the IDS core
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            Stop();

            _cts?.Dispose();
            cleanupTimer?.Dispose();
            statsTimer?.Dispose();
            captureDevice?.Dispose();
            _perfMonitor?.Dispose();
            _ipReassemblyManager?.Dispose();

            flows.Clear();
            ipPortAccess.Clear();
            deauthCounters.Clear();
            _recentAlerts.Clear();
            _recentDdosAlerts.Clear();
            _recentPortScans.Clear();

            _disposed = true;
            GC.SuppressFinalize(this);

            OptimizedLogger.LogImportant("[DISPOSE] IDS Core disposed successfully");
        }

        /// <summary>
        /// Logs comprehensive system statistics
        /// </summary>
        private void LogStatistics()
        {
            if (!_config.EnablePerformanceLogging) return;

            var avgProcessingTime = _totalPacketsProcessed > 0 ?
                _totalProcessingTimeMs / _totalPacketsProcessed : 0;

            var reassemblyStats = _ipReassemblyManager.GetStats();

            int statsLogId = InsertLogIfAllowed(
                DateTime.Now,
                "SYSTEM",
                "SYSTEM",
                0,
                false,
                "SYSTEM_STATS",
                "PERFORMANCE",
                0, 0, 0, "",
                "internal",
                (int)_totalPacketsProcessed, avgProcessingTime, null,
                $"Packets: {_totalPacketsProcessed} | Rules: {_rulesChecked} checked, {_rulesMatched} matched | Memory: {GC.GetTotalMemory(false) / 1024 / 1024}MB | Queue: {_packetQueue.Count}/{_packetQueue.BoundedCapacity}"
            );

            OptimizedLogger.LogPacketStats($"=== IDS STATISTICS ===");
            OptimizedLogger.LogPacketStats($"Packets: {_totalPacketsProcessed} | Avg Time: {avgProcessingTime}ms");
            OptimizedLogger.LogPacketStats($"Rules: {_rulesChecked} checked, {_rulesMatched} matched");
            OptimizedLogger.LogPacketStats($"Memory: {GC.GetTotalMemory(false) / 1024 / 1024}MB | Queue: {_packetQueue.Count}/{_packetQueue.BoundedCapacity}");
            OptimizedLogger.LogPacketStats($"Active Flows: {flows.Count} | Errors: {_errorCount} | Skipped: {_skippedPackets}");
            OptimizedLogger.LogPacketStats($"Reassembly: {reassemblyStats.ActiveBuffers} buffers, {reassemblyStats.TotalMemoryUsage} bytes");
            OptimizedLogger.LogPacketStats($"=======================");

            // Enhanced rule engine statistics every minute
            if (DateTime.Now.Second % 60 == 0)
            {
                _ruleEngine.PrintEnhancedPerformanceStats();
            }
        }

        /// <summary>
        /// Determines if an alert should be generated (local dedup)
        /// </summary>
        private bool ShouldGenerateAlert(string alertKey)
        {
            var now = DateTime.Now;
            if (_recentAlerts.TryGetValue(alertKey, out var lastAlertTime))
            {
                if (now - lastAlertTime < _config.AlertDeduplicationWindow)
                    return false;
            }
            _recentAlerts[alertKey] = now;
            return true;
        }


        /// <summary>
        /// Processes Ethernet packets
        /// </summary>
        private void ProcessEthernet(EthernetPacket ethPacket)
        {
            var stopwatch = Stopwatch.StartNew();

            try
            {
                _ruleStatistics.RecordProtocolPacket("Ethernet");

                if (ethPacket.PayloadPacket is ArpPacket arp)
                {
                    int arpLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        arp.SenderProtocolAddress.ToString(),
                        arp.TargetProtocolAddress.ToString(),
                        ethPacket.TotalPacketLength,
                        false,
                        "ARP",
                        "ARP",
                        0, 0, 0, "",
                        _ruleEngine.GetDirection(arp.SenderProtocolAddress.ToString(), arp.TargetProtocolAddress.ToString()),
                        1, 0.0, null,
                        $"ARP: {arp.SenderProtocolAddress} -> {arp.TargetProtocolAddress}"
                    );

                    OptimizedLogger.LogImportant($"ARP: {arp.SenderProtocolAddress} -> {arp.TargetProtocolAddress}");
                    return;
                }

                if (ethPacket.PayloadPacket is IPPacket ip)
                {
                    // Handle IP fragment reassembly
                    var reassembledPacket = _ipReassemblyManager.ProcessFragment(ip);
                    if (reassembledPacket != null)
                    {
                        ProcessIPPacket(reassembledPacket);
                    }
                }
            }
            finally
            {
                stopwatch.Stop();
                if (stopwatch.ElapsedMilliseconds > 50)
                {
                    OptimizedLogger.LogPerformance($"ProcessEthernet took {stopwatch.ElapsedMilliseconds}ms");
                }
            }
        }

        /// <summary>
        /// Processes WiFi packets
        /// </summary>
        private void ProcessWiFi(PacketDotNet.Packet packet)
        {
            if (packet is RadioPacket radio && radio.PayloadPacket is MacFrame frame)
            {
                _ruleStatistics.RecordProtocolPacket("WiFi");

                if (frame is ManagementFrame mgmt)
                {
                    _ruleStatistics.RecordProtocolPacket($"WiFi-Management-{mgmt.FrameControl.SubType}");

                    if (mgmt.FrameControl.SubType == FrameControlField.FrameSubTypes.ManagementDeauthentication)
                    {
                        var source = mgmt.SourceAddress?.ToString();
                        var count = deauthCounters.AddOrUpdate(source, 1, (_, old) => old + 1);
                        if (count > _config.DeauthThreshold)
                        {
                            int deauthLogId = CreateDeauthLogEntry(source, count);
                            if (deauthLogId > 0)
                            {
                                OptimizedLogger.LogImportant($"Deauth flood from {source}");
                                GenerateAlert(deauthLogId, source, "Broadcast", count, "Deauth Flood", "Deauth", null, "High");
                            }
                            deauthCounters.TryRemove(source, out _);
                        }
                        else
                        {
                            int deauthLogId = InsertLogIfAllowed(
                                DateTime.Now,
                                source ?? "UNKNOWN",
                                "Broadcast",
                                0,
                                false,
                                "WIFI_DEAUTH",
                                "WIFI",
                                0, 0, 0, "",
                                "outbound",
                                count, 0.0, null,
                                $"Deauthentication frame from {source}"
                            );
                        }
                    }
                }
                if (frame is DataFrame data)
                {
                    if (data.PayloadPacket is IPPacket ipPacket)
                    {
                        // Handle IP fragment reassembly for WiFi packets
                        var reassembledPacket = _ipReassemblyManager.ProcessFragment(ipPacket);

                        if (reassembledPacket != null)
                        {
                            ProcessIPPacket(reassembledPacket);
                        }
                    }
                }
            }
        }
        /// <summary>
        /// Creates log entry for deauthentication flood detection
        /// </summary>
        private int CreateDeauthLogEntry(string srcIp, int deauthCount)
        {
            try
            {
                int logId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    "Broadcast",
                    0,
                    true,
                    "WIFI_ATTACK",
                    "DEAUTH_FLOOD",
                    0, 0, 0, "00",
                    _ruleEngine.GetDirection(srcIp, "Broadcast"),
                    deauthCount, 0.0, null, "Detected Wi-Fi Deauthentication attack"
                );
                if (logId <= 0)
                {
                    int errorLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        "SYSTEM",
                        "SYSTEM",
                        0,
                        true,
                        "DATABASE_ERROR",
                        "SYSTEM",
                        0, 0, 0, "",
                        "internal",
                        1, 0.0, null,
                        $"Failed to insert deauth log entry for {srcIp}"
                    );
                    OptimizedLogger.LogError($"Failed to insert deauth log entry for {srcIp}");
                }
                return logId;
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    "Broadcast",
                    0,
                    true,
                    "PROCESSING_ERROR",
                    "DEAUTH",
                    0, 0, 0, "",
                    "internal",
                    1, 0.0, null,
                    $"Error creating deauth log entry: {ex.Message}"
                );
                OptimizedLogger.LogError($"Error creating deauth log entry: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
                return 0;
            }
        }

        /// <summary>
        /// Processes IP packets
        /// </summary>

        private void ProcessIPPacket(IPPacket ipPacket)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                string srcIp = ipPacket.SourceAddress.ToString();
                string dstIp = ipPacket.DestinationAddress.ToString();

                byte[] payload = Array.Empty<byte>();
                int srcPort = 0, dstPort = 0;
                string tcpFlags = "";
                string protocolName = ipPacket.Protocol.ToString();
                _ruleStatistics.RecordProtocolPacket(protocolName);

                // Handle TCP packets with stream reassembly
                if (ipPacket.PayloadPacket is TcpPacket tcp)
                {
                    srcPort = tcp.SourcePort;
                    dstPort = tcp.DestinationPort;
                    tcpFlags = tcp.Flags.ToString();
                    int logId = InsertLogIfAllowed(
                        DateTime.Now,
                        srcIp,
                        dstIp,
                        tcp.TotalPacketLength,
                        false,
                        "Tcp",
                        "Transport Layer",
                        srcPort, dstPort, payload.Length, tcpFlags,
                        _ruleEngine.GetDirection(srcIp, dstIp),
                        1, 0.0, null,
                        $"Tcp: {srcIp}: {srcPort} -> {dstIp}: {dstPort}"
                    );

                    // Use TCP stream reassembler for stateful protocols
                    var completeMessages = _tcpStreamReassembler.ProcessTcpSegment((IPv4Packet)ipPacket, tcp);

                    if (completeMessages != null && completeMessages.Count > 0)
                    {
                        foreach (var message in completeMessages)
                        {
                            ProcessCompleteTcpMessage(logId, ipPacket, tcp, message, srcIp, dstIp, srcPort, dstPort);
                        }
                        // Don't process individual segments if we have complete messages
                        return;
                    }

                    // Fallback to individual segment processing
                    payload = ExtractTcpPayload(tcp);
                }
                else if (ipPacket.PayloadPacket is UdpPacket udp)
                {
                    srcPort = udp.SourcePort;
                    dstPort = udp.DestinationPort;

                    // Get UDP payload (or try reconstructing it)
                    payload = udp.PayloadData ?? Array.Empty<byte>();

                    if (payload == null || payload.Length == 0)
                    {
                        var reconstructed = TryReconstructUdpPayloadFromIp(ipPacket);
                        if (reconstructed != null && reconstructed.Length > 0)
                        {
                            payload = reconstructed;
                            OptimizedLogger.LogImportant($"[UDP-RECONSTRUCT] Reconstructed payload len={payload.Length} for {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                        }
                        else
                        {
                            payload = Array.Empty<byte>();
                            OptimizedLogger.LogImportant($"[UDP-RECONSTRUCT] No payload available after reconstruction attempt for {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                        }
                    }

                    InsertLogIfAllowed(
                        DateTime.Now,
                        srcIp,
                        dstIp,
                        udp.TotalPacketLength,
                        false,
                        "UDP",
                        "Transport Layer",
                        srcPort, dstPort, payload.Length, "",
                        _ruleEngine.GetDirection(srcIp, dstIp),
                        1, 0.0, null,
                        $"UDP: {srcIp}:{srcPort} -> {dstIp}:{dstPort}"
                    );
                }

                // Continue with existing processing for non-reassembled packets
                ProcessPacketData(ipPacket, payload, srcIp, dstIp, srcPort, dstPort, protocolName, tcpFlags);
            }
            finally
            {
                stopwatch.Stop();
                Interlocked.Add(ref _totalProcessingTimeMs, stopwatch.ElapsedMilliseconds);
            }
        }
     

        /// <summary>
        /// Enhanced SMB protocol processing with security analysis
        /// </summary>
        // Enhanced session management in ProcessEnhancedSmbProtocol
        private void ProcessEnhancedSmbProtocol(int logId, byte[] smbPayload, string srcIp, string dstIp, int srcPort, int dstPort, string tcpFlags)
        {
            try
            {
                // أول حاجة نتأكد إن logId صالح
                if (logId <= 0)
                {
                    OptimizedLogger.LogError($"[SMB-PROTOCOL] Cannot insert SMB log: invalid logId={logId}");
                    return;
                }

                string sessionKey = $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";

                // Enhanced duplicate detection
                if (!_smbOptimizations.ShouldProcessSmbPacket(sessionKey, smbPayload))
                {
                    OptimizedLogger.LogImportant($"[SMB] Skipping duplicate SMB packet from {srcIp}:{srcPort}");
                    return;
                }

                // Parse SMB packet
                var result = _smbParser.ParseSmbPacket(smbPayload, srcIp, dstIp, sessionKey);
                if (result == null) return;

                // تعويض أي قيم فارغة قبل الإدخال
                result.Filename = string.IsNullOrEmpty(result.Filename) ? "none" : result.Filename;
                result.Share = string.IsNullOrEmpty(result.Share) ? "none" : result.Share;
                result.Command = string.IsNullOrEmpty(result.Command) ? "unknown" : result.Command;
                result.Service = string.IsNullOrEmpty(result.Service) ? "none" : result.Service;
                result.Dialect = string.IsNullOrEmpty(result.Dialect) ? "none" : result.Dialect;
                result.Notes = result.Notes ?? new List<string>();
                result.SuspicionReasons = result.SuspicionReasons ?? new List<string>();

                // إدخال سجل SMB فقط إذا لدينا Command صالح
                if (!string.IsNullOrEmpty(result.Command) && result.Command != "unknown")
                {
                    int smbLogId = SmbLogBLL.Insert(
                        logId,
                        result.Command,
                        result.Filename,
                        result.Share,
                        result.Service,
                        result.TreeId,
                        result.SessionId,
                        result.Dialect,
                        result.PayloadSize,
                        tcpFlags,
                        result.IsSuspicious,
                        result.Notes,
                        result.SuspicionReasons
                    );

                    if (smbLogId <= 0)
                    {
                        OptimizedLogger.LogError($"[SMB-PROTOCOL] Failed to insert SMB log for {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                        return;
                    }

                    // Security analysis and alert generation
                    if (result.IsSuspicious)
                    {
                        var securityAnalysis = _enhancedSmbParser.AnalyzeSecurity(result, srcIp, dstIp);
                        bool isBruteForce = _smbBruteForceDetector.DetectBruteForce(srcIp, result);

                        if (securityAnalysis.RiskLevel != "Low" || isBruteForce)
                        {
                            string alertMsg = $"SMB Security Alert: {string.Join("; ", result.SuspicionReasons)}";
                            GenerateAlert(smbLogId, srcIp, dstIp, smbPayload.Length, alertMsg, "SMB_Security", null, "Medium");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[SMB-PROTOCOL] Processing error: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }


        private void ProcessPacketData(IPPacket ipPacket, byte[] payload, string srcIp, string dstIp,
                         int srcPort, int dstPort, string protocolName, string tcpFlags)
        {
            try
            {
                bool isSmbTraffic = (dstPort == 445 || srcPort == 445 || dstPort == 139 || srcPort == 139);
                if (isSmbTraffic)
                {
                    OptimizedLogger.LogImportant($"[SMB-DEBUG] SMB traffic detected: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, PayloadLength: {payload.Length}");
                    if (payload.Length > 0)
                    {
                        OptimizedLogger.LogImportant($"[SMB-DEBUG] SMB payload first 16 bytes: {BitConverter.ToString(payload.Take(16).ToArray())}");
                    }
                }

                int? matchedSigId = null;
                string sigRule = null;
                bool isMalicious = CheckForMaliciousActivity(
                    srcIp, dstIp, payload,
                    out sigRule, out matchedSigId,
                    ipPacket, srcPort, dstPort, protocolName
                );

                bool portScan = DetectPortScan(srcIp, dstIp, ipPacket, tcpFlags);
                bool finalMalicious = isMalicious || portScan;
                string direction = _ruleEngine.GetDirection(srcIp, dstIp);

                var flowKey = $"{srcIp}:{srcPort}->{dstIp}:{dstPort}:{protocolName}";
                var flow = flows.AddOrUpdate(flowKey,
                    _ => new FlowInfo { FirstSeen = DateTime.Now, LastSeen = DateTime.Now, PacketCount = 1, TotalBytes = ipPacket.TotalLength },
                    (_, existing) =>
                    {
                        existing.LastSeen = DateTime.Now;
                        existing.PacketCount++;
                        existing.TotalBytes += ipPacket.TotalLength;
                        return existing;
                    });

                double duration = (DateTime.Now - flow.FirstSeen).TotalSeconds;

                // إدخال السجل الرئيسي فقط بعد التحقق من البيانات
                int logId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    dstIp,
                    ipPacket.TotalLength,
                    finalMalicious,
                    protocolName,
                    protocolName,
                    srcPort,
                    dstPort,
                    payload.Length,
                    tcpFlags,
                    direction,
                    flow.PacketCount,
                    duration,
                    matchedSigId,
                    finalMalicious
                        ? (matchedSigId.HasValue
                            ? $"Matched Signature (ID: {matchedSigId}) - {sigRule}"
                            : (portScan ? "Detected Port Scan activity" : "Detected suspicious behavior"))
                        : "Normal network packet"
                );

                if (logId <= 0)
                {
                    OptimizedLogger.LogError($"[DB-FAIL] Invalid logId ({logId}) for packet {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                    return; // مانع أي إدخالات إضافية تعتمد على logId غير صالح
                }

                _perfMonitor.RecordMetric("PacketsProcessed", 1);

                // إدخال تفاصيل البروتوكولات فقط إذا logId صالح
                InsertProtocolLog(logId, ipPacket, payload, tcpFlags, srcIp, dstIp, isMalicious, sigRule, matchedSigId);

                if (isMalicious && matchedSigId.HasValue)
                {
                    var matchedRule = _ruleEngine.GetRuleById(matchedSigId.Value);
                    if (matchedRule != null && ShouldGenerateAlert($"sig_{matchedRule.SignatureId}_{srcIp}_{dstIp}"))
                    {
                        GenerateEnhancedAlert(logId, matchedRule, srcIp, dstIp, ipPacket.TotalLength);
                    }
                }

                Interlocked.Increment(ref _totalPacketsProcessed);
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    dstIp,
                    payload?.Length ?? 0,
                    true,
                    "PROCESSING_ERROR",
                    protocolName,
                    srcPort, dstPort, payload?.Length ?? 0, tcpFlags,
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    $"Error in ProcessPacketData: {ex.Message}"
                );
                OptimizedLogger.LogError($"Error in ProcessPacketData: {ex.Message}");
            }
        }



        /// <summary>
        /// Enhanced TCP payload extraction for SMB traffic
        /// </summary>
        private byte[] ExtractTcpPayload(TcpPacket tcp)
        {
            try
            {
                // For SMB traffic, use the most reliable method first
                if (tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                {
                    return tcp.PayloadData;
                }

                // Calculate payload from TCP header length
                int dataOffset = (tcp.DataOffset & 0xF0) >> 4;
                int headerLength = dataOffset * 4;

                if (tcp.Bytes != null && tcp.Bytes.Length > headerLength)
                {
                    int payloadLength = tcp.Bytes.Length - headerLength;
                    if (payloadLength > 0)
                    {
                        byte[] payload = new byte[payloadLength];
                        Buffer.BlockCopy(tcp.Bytes, headerLength, payload, 0, payloadLength);
                        return payload;
                    }
                }

                return Array.Empty<byte>();
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[TCP] Payload extraction fallback: {ex.Message}");
                return Array.Empty<byte>();
            }
        }        /// <summary>
                 /// Validate that extracted data looks like real payload
                 /// </summary>
        private bool IsValidPayload(byte[] data)
        {
            if (data == null || data.Length == 0) return false;

            // Check if it's mostly zeros (likely padding)
            int zeroCount = data.Take(Math.Min(16, data.Length)).Count(b => b == 0);
            if (zeroCount > data.Length * 0.8) return false;

            return true;
        }

        /// <summary>
        /// Checks packet payload against malicious patterns
        /// </summary>
        private bool CheckForMaliciousActivity(string srcIp, string dstIp, byte[] payload,
             out string ruleText, out int? sigId, IPPacket ipPacket, int srcPort, int dstPort, string protocolName)
        {
            ruleText = null;
            sigId = null;

            // Always check rules for comprehensive detection
            bool shouldCheckRules = true;

            if (payload == null || payload.Length == 0)
            {
                shouldCheckRules = _ruleEngine.IsSuspiciousEmptyPacket(ipPacket);
            }
            else if (payload.Length < 5)
            {
                shouldCheckRules = _ruleEngine.IsSuspiciousSmallPacket(ipPacket);
            }

            if (shouldCheckRules)
            {
                var matches = _ruleEngine.CheckPacket(ipPacket, payload, srcIp, dstIp, srcPort, dstPort, protocolName);

                if (matches != null && matches.Count > 0)
                {
                    var firstMatch = matches[0];
                    ruleText = firstMatch.AttackName;
                    sigId = firstMatch.SignatureId;

                    // إنشاء log للمطابقة مع التوقيع
                    int matchLogId = InsertLogIfAllowed(
                        DateTime.Now,
                        srcIp,
                        dstIp,
                        payload?.Length ?? 0,
                        true,
                        "SIGNATURE_MATCH",
                        protocolName,
                        srcPort, dstPort, payload?.Length ?? 0, "",
                        _ruleEngine.GetDirection(srcIp, dstIp),
                        1, 0.0, sigId,
                        $"Signature matched: {ruleText} (Rule ID: {sigId})"
                    );

                    OptimizedLogger.LogImportant($"[SIGNATURE_MATCH] Detected: {ruleText} from {srcIp} to {dstIp} (Rule ID: {sigId})");

                    // Log all matches for comprehensive analysis
                    foreach (var match in matches.Take(3))
                    {
                        OptimizedLogger.LogImportant($"[RULE_MATCH_DETAIL] {match.AttackName} (ID: {match.SignatureId})");
                    }

                    return true;
                }
                else
                {
                    // Periodic logging for rule matching analysis
                    if (_totalPacketsProcessed % 1000 == 0)
                    {
                        OptimizedLogger.LogImportant($"[RULES] No rule matches for {protocolName} {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Inserts protocol-specific log entries
        /// </summary>
        private void InsertProtocolLog(int logId, IPPacket ip, byte[] payload, string tcpFlags,
            string srcIp, string dstIp, bool isMalicious, string sigRule, int? matchedSigId)
        {
            if (!_perfSettings.EnableProtocolParsing)
                return;

            int srcPort = 0, dstPort = 0;
            TcpPacket tcp = ip.PayloadPacket as TcpPacket;
            UdpPacket udp = ip.PayloadPacket as UdpPacket;

            if (tcp != null)
            {
                srcPort = tcp.SourcePort;
                dstPort = tcp.DestinationPort;
            }
            else if (udp != null)
            {
                srcPort = udp.SourcePort;
                dstPort = udp.DestinationPort;
            }

            ProcessAllProtocols(logId, ip, payload, srcIp, dstIp, srcPort, dstPort, tcp, udp);
        }

        /// <summary>
        /// Processes all application layer protocols
        /// </summary>
        private void ProcessAllProtocols(int logId, IPPacket ip, byte[] payload, string srcIp, string dstIp,
  int srcPort, int dstPort, TcpPacket tcp, UdpPacket udp)
        {
            OptimizedLogger.LogImportant($"[TRACE] {srcIp}:{srcPort} -> {dstIp}:{dstPort} | Proto={ip.Protocol} | PayloadLen={(payload?.Length ?? 0)}");

            try
            {
                string protocolDetail = "";

                // 1) ICMP
                if (ip.Protocol == ProtocolType.Icmp)
                {
                    protocolDetail = $"ICMP";
                    _ruleStatistics.RecordProtocolPacket("ICMP", payload?.Length ?? 0, protocolDetail);
                    ProcessIcmp(logId, ip, srcIp, dstIp);
                    return;
                }

                // 2) TLS/HTTPS
                if (tcp != null && (dstPort == 443 || srcPort == 443))
                {
                    protocolDetail = $"HTTPS/TLS Port:{(dstPort != 0 ? dstPort : srcPort)}";
                    _ruleStatistics.RecordProtocolPacket("HTTPS", payload?.Length ?? 0, protocolDetail);
                    ProcessTls(logId, payload, srcIp, dstIp, srcPort);
                    return;
                }

                // 3) HTTP
                if (tcp != null && (dstPort == 80 || srcPort == 80))
                {
                    protocolDetail = $"HTTP Port:{(dstPort != 0 ? dstPort : srcPort)}";
                    _ruleStatistics.RecordProtocolPacket("HTTP", payload?.Length ?? 0, protocolDetail);
                    ProcessHttpHttps(logId, payload, srcIp, dstIp, srcPort, dstPort);
                    return;
                }

                // 4) DNS
                if (udp != null && (dstPort == 53 || srcPort == 53))
                {
                    protocolDetail = $"DNS Port:{(dstPort != 0 ? dstPort : srcPort)}";
                    _ruleStatistics.RecordProtocolPacket("DNS", payload?.Length ?? 0, protocolDetail);
                    ProcessDns(logId, udp, srcIp, dstIp);
                    return;
                }

                // 5) NTP
                if (udp != null && (dstPort == 123 || srcPort == 123))
                {
                    _ruleStatistics.RecordProtocolPacket("NTP", payload?.Length ?? 0, $"NTP Port:{dstPort}");
                    ProcessNtp(logId, udp, srcIp, dstIp);
                    return;
                }

                // 6) NETBIOS
                if (udp != null && (dstPort == 137 || dstPort == 138 || srcPort == 137 || srcPort == 138))
                {
                    _ruleStatistics.RecordProtocolPacket("NETBIOS", payload?.Length ?? 0, $"NETBIOS Port:{dstPort}");
                    ProcessNetbios(logId, udp, srcIp, dstIp);
                    return;
                }

                // 7) DHCP
                if (udp != null && (dstPort == 67 || dstPort == 68 || srcPort == 67 || srcPort == 68))
                {
                    protocolDetail = $"DHCP Port:{dstPort}";
                    _ruleStatistics.RecordProtocolPacket("DHCP", payload?.Length ?? 0, protocolDetail);
                    ProcessDhcp(logId, udp, payload, srcIp, dstIp, srcPort, dstPort);
                    return;
                }

                // 8) FTP
                if (tcp != null && (dstPort == 21 || srcPort == 21))
                {
                    protocolDetail = $"FTP Port:{dstPort}";
                    _ruleStatistics.RecordProtocolPacket("FTP", payload?.Length ?? 0, protocolDetail);
                    ProcessFtp(logId, payload, srcIp, dstIp, srcPort);
                    return;
                }

                // 9) SSH
                if (tcp != null && (dstPort == 22 || srcPort == 22))
                {
                    protocolDetail = $"SSH Port:{dstPort}";
                    _ruleStatistics.RecordProtocolPacket("SSH", payload?.Length ?? 0, protocolDetail);
                    ProcessSsh(logId, payload, srcIp, dstIp, srcPort);
                    return;
                }

                // 10) SMTP
                if (tcp != null && (dstPort == 25 || srcPort == 25 ||
                      dstPort == 465 || srcPort == 465 ||
                      dstPort == 587 || srcPort == 587))
                {
                    OptimizedLogger.LogImportant($"[SMTP-DETECT] Potential SMTP session {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                    protocolDetail = $"SMTP Port:{(dstPort != 0 ? dstPort : srcPort)}";
                    _ruleStatistics.RecordProtocolPacket("SMTP", payload?.Length ?? 0, protocolDetail);
                    ProcessSmtp(logId, payload, srcIp, dstIp, srcPort,dstPort);
                    return;
                }

                // 11) TELNET
                if (tcp != null && (dstPort == 23 || srcPort == 23))
                {
                    protocolDetail = $"TELNET Port:{dstPort}";
                    _ruleStatistics.RecordProtocolPacket("TELNET", payload?.Length ?? 0, protocolDetail);
                    ProcessTelnet(logId, payload, srcIp, dstIp, srcPort);
                    return;
                }

                // 12) RDP
                if (tcp != null && (dstPort == 3389 || srcPort == 3389))
                {
                    protocolDetail = $"RDP Port:{dstPort}";
                    _ruleStatistics.RecordProtocolPacket("RDP", payload?.Length ?? 0, protocolDetail);
                    ProcessRdp(logId, payload, srcIp, dstIp, srcPort);
                    return;
                }

                // 13) SMB - Enhanced processing
                if (tcp != null && (dstPort == 445 || srcPort == 445 || dstPort == 139 || srcPort == 139))
                {
                    if (payload == null || payload.Length == 0)
                    {
                        // Log empty SMB payload
                        int emptyLogId = InsertLogIfAllowed(
                            DateTime.Now,
                            srcIp,
                            dstIp,
                            0,
                            false,
                            "SMB",
                            "SMB",
                            srcPort, dstPort, 0, "",
                            _ruleEngine.GetDirection(srcIp, dstIp),
                            1, 0.0, null,
                            "Empty SMB payload on standard ports"
                        );
                        OptimizedLogger.LogImportant($"[SMB] Empty payload for SMB on port {dstPort} from {srcIp}:{srcPort}");
                        return;
                    }

                    // Use enhanced SMB validation
                    if (SmbDetectionHelper.IsValidSmbPacket(payload, srcPort, dstPort) &&
                        SmbDetectionHelper.ValidateSmbStructure(payload))
                    {
                        protocolDetail = $"SMB Port:{dstPort}";
                        _ruleStatistics.RecordProtocolPacket("SMB", payload.Length, protocolDetail);

                        OptimizedLogger.LogImportant($"[SMB] Processing SMB packet: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, Size: {payload.Length}");
                        ProcessEnhancedSmbProtocol(logId, payload, srcIp, dstIp, srcPort, dstPort, tcp.Flags.ToString());
                    }
                    else
                    {
                        // Log non-SMB traffic on SMB ports
                        int nonSmbLogId = InsertLogIfAllowed(
                            DateTime.Now,
                            srcIp,
                            dstIp,
                            payload.Length,
                            false,
                            "NON_SMB_TRAFFIC",
                            "SMB_PORTS",
                            srcPort, dstPort, payload.Length, "",
                            _ruleEngine.GetDirection(srcIp, dstIp),
                            1, 0.0, null,
                            $"Non-SMB traffic on SMB port {dstPort}"
                        );
                        OptimizedLogger.LogImportant($"[SMB] Packet on port {dstPort} doesn't appear to be valid SMB traffic");
                    }
                    return;
                }

                // 14) LDAP - MUCH MORE PERMISSIVE
                if (tcp != null && (dstPort == 389 || srcPort == 389 || dstPort == 636 || srcPort == 636))
                {
                    // Assume it's LDAP if it's on LDAP ports and has some data
                    if (payload != null && payload.Length > 0)
                    {
                        // Always try to process as LDAP on these ports
                        _ruleStatistics.RecordProtocolPacket("LDAP", payload.Length, $"LDAP Port:{dstPort}");
                        ProcessLdap(logId, payload, srcIp, dstIp, srcPort, dstPort);
                    }
                    else
                    {
                        // Log empty payload on LDAP ports
                        int emptyLogId = InsertLogIfAllowed(
                            DateTime.Now,
                            srcIp,
                            dstIp,
                            0,
                            false,
                            "LDAP",
                            "LDAP_PORTS",
                            srcPort, dstPort, 0, "",
                            _ruleEngine.GetDirection(srcIp, dstIp),
                            1, 0.0, null,
                            $"Empty payload on LDAP port {dstPort}"
                        );
                    }
                    return;
                }

                // Default: record generic protocol info
                _ruleStatistics.RecordProtocolPacket(ip.Protocol.ToString(), payload?.Length ?? 0,
                    $"{ip.Protocol} {srcIp}:{srcPort}->{dstIp}:{dstPort}");
            }
            catch (Exception ex)
            {
                // إنشاء log لخطأ في معالجة البروتوكولات
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    dstIp,
                    payload?.Length ?? 0,
                    true,
                    "PROCESSING_ERROR",
                    "PROTOCOL_PARSING",
                    srcPort, dstPort, payload?.Length ?? 0, "",
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    $"Error processing protocols for log {logId}: {ex.Message}"
                );
                OptimizedLogger.LogError($"Error processing protocols for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes HTTP and HTTPS traffic to analyze headers and body for malicious content.
        /// Logs HTTP metadata and triggers alerts if threats are detected.
        /// Now receives complete reassembled payloads for accurate HTTP parsing.
        /// </summary>
        private void ProcessHttpHttps(int logId, byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            try
            {
                if (_httpParser.IsValidHttpPacket(payload))
                {
                    int maxPayload = 1024 * 1024;
                    var safePayload = payload.Length > maxPayload ? payload.Take(maxPayload).ToArray() : payload;
                    var handler = new EnhancedHttpHandler(_httpParser);
                    var parser = new HttpMachine.HttpParser(handler);
                    parser.Execute(new ArraySegment<byte>(safePayload));

                    bool bodyMalicious = false;
                    string bodyDetection = "clean";

                    if (handler.RequestBody?.Length > 0)
                    {
                        bodyMalicious = _httpParser.CheckBodyForThreats(handler.RequestBody, srcIp, dstIp, "request");
                        if (bodyMalicious) bodyDetection = "malicious_request";
                    }

                    if (handler.ResponseBody?.Length > 0)
                    {
                        bool respMalicious = _httpParser.CheckBodyForThreats(handler.ResponseBody, srcIp, dstIp, "response");
                        if (respMalicious)
                        {
                            bodyMalicious = true;
                            bodyDetection = bodyDetection == "malicious_request" ? "malicious_both" : "malicious_response";
                        }
                    }

                    if (HttpLogBLL.Insert(logId, handler.Method, handler.Url, handler.Host,
                        handler.UserAgent, handler.StatusCode, bodyDetection,
                        handler.RequestBody?.Length ?? 0, handler.ResponseBody?.Length ?? 0) <= 0)
                    {
                        OptimizedLogger.LogError($"Failed to insert HTTP log for logId {logId}");
                        Interlocked.Increment(ref _errorCount);
                    }

                    if (bodyMalicious)
                        GenerateAlert(logId, srcIp, dstIp, payload.Length, "HTTP Body Threat", "HTTP_Body", null, "High");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing HTTP protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes DNS traffic for query analysis and response inspection.
        /// Extracts questions and answers from DNS packets and logs them.
        /// Now receives complete reassembled DNS messages for accurate parsing.
        /// </summary>
        private void ProcessDns(int logId, UdpPacket udp, string srcIp, string dstIp)
        {
            try
            {
                string sourceIp = srcIp;
                string destinationIp = dstIp;

                var result = _dnsParser.Parse(
                    udp.PayloadData ?? Array.Empty<byte>(),
                    sourceIp,
                    destinationIp,
                    udp.SourcePort,
                    udp.DestinationPort,
                    $"{sourceIp}:{udp.SourcePort}-{destinationIp}:{udp.DestinationPort}"
                );

                foreach (var q in result.Questions)
                {
                    if (DnsLogBLL.Insert(logId, q.Name, q.Type, q.Response, q.TTL, q.RecordType) <= 0)
                    {
                        OptimizedLogger.LogError($"Failed to insert DNS question log for logId {logId}");
                        Interlocked.Increment(ref _errorCount);
                    }
                }

                foreach (var a in result.Answers)
                {
                    if (DnsLogBLL.Insert(logId, a.Name, a.Type, a.Response, a.TTL, a.RecordType) <= 0)
                    {
                        OptimizedLogger.LogError($"Failed to insert DNS answer log for logId {logId}");
                        Interlocked.Increment(ref _errorCount);
                    }
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing DNS protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes FTP traffic to extract command and filename information.
        /// Logs FTP commands for activity tracking.
        /// Now receives complete reassembled FTP data for accurate parsing.
        /// </summary>
        private void ProcessFtp(int logId, byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            try
            {
                var result = _ftpParser.Parse(payload);
                if (FtpLogBLL.Insert(logId, result.Command, result.Filename) <= 0)
                {
                    OptimizedLogger.LogError($"Failed to insert FTP log for logId {logId}");
                    Interlocked.Increment(ref _errorCount);
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing FTP protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Reconstruct UDP payload manually from raw IP bytes
        /// when UdpPacket.PayloadData is empty.
        /// </summary>
        private byte[] TryReconstructUdpPayloadFromIp(IPPacket ipPacket)
        {
            try
            {
                var raw = ipPacket.Bytes;
                if (raw == null || raw.Length < 20)
                    return Array.Empty<byte>();

                // IPv4 only
                if (!(ipPacket is IPv4Packet))
                    return Array.Empty<byte>();

                int ipHeaderLen = (raw[0] & 0x0F) * 4;
                if (raw.Length < ipHeaderLen + 8)
                    return Array.Empty<byte>();

                int ipTotalLen = (raw[2] << 8) | raw[3];
                if (ipTotalLen <= ipHeaderLen)
                    return Array.Empty<byte>();

                int udpHeaderOffset = ipHeaderLen;
                int udpLen = (raw[udpHeaderOffset + 4] << 8) | raw[udpHeaderOffset + 5];

                int udpPayloadLen = udpLen > 8 ? udpLen - 8 : ipTotalLen - ipHeaderLen - 8;
                if (udpPayloadLen <= 0)
                    return Array.Empty<byte>();

                int udpPayloadOffset = udpHeaderOffset + 8;
                if (udpPayloadOffset + udpPayloadLen > raw.Length)
                    return Array.Empty<byte>();

                var payload = new byte[udpPayloadLen];
                Buffer.BlockCopy(raw, udpPayloadOffset, payload, 0, udpPayloadLen);
                return payload;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }



        /// <summary>
        /// Process LDAP or LDAPS packets detected on port 389 or 636.
        /// Responsible for delegating parsing to LdapParser and recording detection stats.
        /// </summary>

        // ================= ProcessLdap =================

        private void ProcessLdap(int parentLogId, byte[] messageBytes, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            try
            {
                OptimizedLogger.LogImportant($"[LDAP-DEBUG] Processing packet: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, Length: {messageBytes?.Length ?? 0}");

                if (messageBytes == null || messageBytes.Length == 0)
                {
                    OptimizedLogger.LogImportant("[LDAP-DEBUG] Empty payload, skipping parser.");
                    return;
                }

                // Print first 32 bytes for inspection
                int printLength = Math.Min(32, messageBytes.Length);
                OptimizedLogger.LogImportant($"[LDAP-DEBUG] First {printLength} bytes: {BitConverter.ToString(messageBytes, 0, printLength)}");

                // Detect if this looks like LDAP (BER sequence 0x30)
                if (messageBytes[0] != 0x30)
                {
                    OptimizedLogger.LogImportant($"[LDAP-DEBUG] ❌ First byte is 0x{messageBytes[0]:X2}, not LDAP BER sequence.");
                }
                else
                {
                    OptimizedLogger.LogImportant("[LDAP-DEBUG] ✅ Looks like LDAP BER sequence.");
                }

                // Use the parser
                using var parser = new LdapParser();
                var parseResult = parser.Parse(messageBytes);

                OptimizedLogger.LogImportant($"[LDAP-DEBUG] Parser result: Operation={parseResult.Operation}, DN={parseResult.DistinguishedName}, Filter={parseResult.Filter}, ResultCode={parseResult.ResultCode}, Status={parseResult.Status}");

                // Always log the parse result even if parsing failed
                int logId = InsertLogIfAllowed(
                    DateTime.UtcNow,
                    srcIp,
                    dstIp,
                    messageBytes.Length,
                    parseResult.IsSuspicious,
                    "LDAP_DEBUG",
                    "Application",
                    srcPort, dstPort,
                    messageBytes.Length,
                    "",
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    $"LDAP DEBUG: Operation={parseResult.Operation}, DN={parseResult.DistinguishedName}, Filter={parseResult.Filter}, ResultCode={parseResult.ResultCode}, Status={parseResult.Status}"
                );

                // **الحل الجديد: أدخل في LdapLogs لكل العمليات المفيدة**
                if (!parseResult.Operation.StartsWith("parse_error:") &&
                    !parseResult.Operation.StartsWith("error") &&
                    parseResult.Operation != "empty" &&
                    !string.IsNullOrEmpty(parseResult.Operation))
                {
                    // استخدم البيانات المستخرجة بدل القيم الافتراضية
                    string dn = parseResult.DistinguishedName;
                    string status = parseResult.Status;

                    // إذا في attributes، استخدمها لتحسين البيانات
                    if (parseResult.Attributes != null && parseResult.Attributes.Count > 0)
                    {
                        // ابحث عن DN في الـ attributes إذا كان none
                        if (dn == "none" || string.IsNullOrEmpty(dn))
                        {
                            var possibleDn = parseResult.Attributes.FirstOrDefault(a =>
                                a.Key.Contains("DN") || a.Key.Contains("Distinguished") ||
                                a.Value.Contains("CN=") || a.Value.Contains("DC="));

                            if (!string.IsNullOrEmpty(possibleDn.Value))
                                dn = possibleDn.Value.Length > 100 ? possibleDn.Value.Substring(0, 100) + "..." : possibleDn.Value;
                        }

                        // أضف معلومات إضافية للـ status
                        if (parseResult.Attributes.ContainsKey("DS_Strings"))
                        {
                            string dsStrings = parseResult.Attributes["DS_Strings"];
                            if (dsStrings.Length > 50)
                                dsStrings = dsStrings.Substring(0, 50) + "...";
                            status += " | " + dsStrings;
                        }
                    }

                    LdapLogBLL.Insert(
                        logId: logId,
                        operation: parseResult.Operation ?? "unknown",
                        distinguishedName: dn ?? "none",
                        resultCode: parseResult.ResultCode >= 0 ? parseResult.ResultCode.ToString() : "-1",
                        sourceIP: srcIp ?? "unknown",
                        destinationIP: dstIp ?? "unknown",
                        timestamp: DateTime.UtcNow,
                        sessionID: parseResult.SessionId >= 0 ? parseResult.SessionId.ToString() : $"{srcIp}:{srcPort}-{dstIp}:{dstPort}",
                        status: status ?? "unknown"
                    );

                    OptimizedLogger.LogImportant($"[LDAP-DEBUG] LdapLog inserted with REAL data: DN={dn}, Operation={parseResult.Operation}");
                }
                else
                {
                    OptimizedLogger.LogImportant($"[LDAP-DEBUG] Skipping LdapLog insertion for operation: {parseResult.Operation}");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[LDAP-DEBUG] Exception: {ex.Message}");
                InsertLogIfAllowed(
                    DateTime.UtcNow,
                    srcIp,
                    dstIp,
                    messageBytes?.Length ?? 0,
                    true,
                    "LDAP_DEBUG",
                    "ParsingError",
                    srcPort, dstPort,
                    messageBytes?.Length ?? 0,
                    "",
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    $"LDAP parsing exception: {ex.Message}"
                );
            }
        }
        private void ProcessCompleteTcpMessage(int logId, IPPacket ipPacket, TcpPacket tcp, byte[] completeMessage,
                                     string srcIp, string dstIp, int srcPort, int dstPort)
        {
            try
            {
                string protocolName = ipPacket.Protocol.ToString();

                // Add debug logging for LDAP traffic
                if (dstPort == 389 || srcPort == 389)
                {
                    DebugTcpReassembly(ipPacket, tcp, completeMessage, srcIp, dstIp, srcPort, dstPort);
                }

                // Enhanced protocol detection for port 389
                if (dstPort == 389 || srcPort == 389 || dstPort == 636 || srcPort == 636)
                {
                    string detectedProtocol = Port389ProtocolDetector.DetectProtocol(completeMessage);

                    switch (detectedProtocol)
                    {
                        case "ldap":
                            OptimizedLogger.LogImportant($"[TCP-REASSEMBLY] Processing as LDAP: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, Size: {completeMessage.Length}");
                            ProcessLdap(logId, completeMessage, srcIp, dstIp, srcPort, dstPort);
                            return;

                        case "directory_service":
                            OptimizedLogger.LogImportant($"[TCP-REASSEMBLY] Processing as Directory Service: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, Size: {completeMessage.Length}");
                            ProcessDirectoryService(logId, completeMessage, srcIp, dstIp, srcPort, dstPort);
                            return;

                        case "tls":
                            OptimizedLogger.LogImportant($"[TCP-REASSEMBLY] Processing as TLS/Encrypted: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, Size: {completeMessage.Length}");
                            ProcessEncryptedLdap(logId, completeMessage, srcIp, dstIp, srcPort, dstPort);
                            return;

                        default:
                            OptimizedLogger.LogImportant($"[TCP-REASSEMBLY] Unknown protocol on port 389: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, FirstByte: 0x{completeMessage[0]:X2}");
                            ProcessUnknownOnLdapPort(logId, completeMessage, srcIp, dstIp, srcPort, dstPort);
                            return;
                    }
                }

                // Enhanced SMB validation (after LDAP)
                if ((dstPort == 445 || srcPort == 445 || dstPort == 139 || srcPort == 139) &&
                   SmbDetectionHelper.IsValidSmbPacket(completeMessage, srcPort, dstPort))
                {
                    var smbPayload = SmbDetectionHelper.ExtractSmbPayload(completeMessage);
                    if (smbPayload != null && smbPayload.Length > 0)
                    {
                        // Create a dedicated log entry for SMB processing if needed
                        if (logId <= 0)
                        {
                            logId = InsertLogIfAllowed(
                                DateTime.Now,
                                srcIp,
                                dstIp,
                                completeMessage.Length,
                                false,
                                "SMB",
                                "SMB",
                                srcPort,
                                dstPort,
                                completeMessage.Length,
                                tcp.Flags.ToString(),
                                _ruleEngine.GetDirection(srcIp, dstIp),
                                1,
                                0.0,
                                null,
                                "SMB traffic detected"
                            );
                        }

                        ProcessEnhancedSmbProtocol(logId, smbPayload, srcIp, dstIp, srcPort, dstPort, tcp.Flags.ToString());
                        return;
                    }
                }

                // Non-SMB/LDAP traffic fallback
                if (logId > 0)
                {
                    ProcessPacketData(ipPacket, completeMessage, srcIp, dstIp, srcPort, dstPort, protocolName, tcp.Flags.ToString());
                }
            }
            catch (Exception ex)
            {
                int errorLogId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    dstIp,
                    completeMessage.Length,
                    true,
                    "PROCESSING_ERROR",
                    "TCP_REASSEMBLY",
                    srcPort, dstPort, completeMessage.Length, "",
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    $"Error processing complete TCP message: {ex.Message}"
                );
                OptimizedLogger.LogError($"[TCP-MESSAGE] Error processing complete message: {ex.Message}");
            }
        }

        private void ProcessDirectoryService(int logId, byte[] messageBytes, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            try
            {
                var parser = new DirectoryServiceParser();
                var result = parser.Parse(messageBytes);

                string description = $"Directory Service: {result.OperationName}, Length: {result.TotalLength}";

                // استخرج البيانات الحقيقية من الـ Directory Service
                string distinguishedName = "none";
                string operationData = "";

                if (result.Strings.Count > 0)
                {
                    description += $", Data: {string.Join(", ", result.Strings.Take(3))}";

                    // ابحث عن DN حقيقي في الـ strings
                    foreach (var str in result.Strings)
                    {
                        if (str.Contains("CN=") || str.Contains("DC=") || str.Contains("OU="))
                        {
                            distinguishedName = str;
                            break;
                        }
                    }

                    // خذ أول 3 strings كـ operation data
                    operationData = string.Join("; ", result.Strings.Take(3));
                }

                int directoryLogId = InsertLogIfAllowed(
                    DateTime.UtcNow,
                    srcIp,
                    dstIp,
                    messageBytes.Length,
                    false,
                    "DIRECTORY_SERVICE",
                    "Application",
                    srcPort, dstPort, messageBytes.Length, "",
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    description
                );

                // **الحل الجديد: أدخل في LdapLogs أيضاً**
                if (directoryLogId > 0)
                {
                    LdapLogBLL.Insert(
                        logId: directoryLogId,
                        operation: $"DS_{result.OperationName}",
                        distinguishedName: distinguishedName,
                        resultCode: "0", // Directory Service عادة بيكون ناجح
                        sourceIP: srcIp,
                        destinationIP: dstIp,
                        timestamp: DateTime.UtcNow,
                        sessionID: $"{srcIp}:{srcPort}-{dstIp}:{dstPort}",
                        status: $"directory_service | {operationData}"
                    );

                    OptimizedLogger.LogImportant($"[DIRECTORY-SERVICE] LdapLog inserted: Operation=DS_{result.OperationName}, DN={distinguishedName}");
                }

                OptimizedLogger.LogImportant($"[DIRECTORY-SERVICE] Processed: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, {description}");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"ProcessDirectoryService error: {ex.Message}");

                InsertLogIfAllowed(
                    DateTime.UtcNow,
                    srcIp,
                    dstIp,
                    messageBytes.Length,
                    false,
                    "DIRECTORY_SERVICE",
                    "Application",
                    srcPort, dstPort, messageBytes.Length, "",
                    _ruleEngine.GetDirection(srcIp, dstIp),
                    1, 0.0, null,
                    $"Directory Service parsing error: {ex.Message}"
                );
            }
        }
        private void ProcessEncryptedLdap(int logId, byte[] messageBytes, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            string description = dstPort == 636 || srcPort == 636 ?
                "LDAPS Encrypted Traffic" : "LDAP with TLS/StartTLS";

            InsertLogIfAllowed(
                DateTime.UtcNow,
                srcIp,
                dstIp,
                messageBytes.Length,
                false,
                "LDAP_ENCRYPTED",
                "Application",
                srcPort, dstPort, messageBytes.Length, "",
                _ruleEngine.GetDirection(srcIp, dstIp),
                1, 0.0, null,
                description
            );

            OptimizedLogger.LogImportant($"[LDAP-ENCRYPTED] {description}: {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
        }

        private void ProcessUnknownOnLdapPort(int logId, byte[] messageBytes, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            string firstBytes = messageBytes.Length >= 8 ?
                BitConverter.ToString(messageBytes, 0, Math.Min(8, messageBytes.Length)) :
                BitConverter.ToString(messageBytes);

            InsertLogIfAllowed(
                DateTime.UtcNow,
                srcIp,
                dstIp,
                messageBytes.Length,
                false,
                "UNKNOWN_ON_LDAP_PORT",
                "Application",
                srcPort, dstPort, messageBytes.Length, "",
                _ruleEngine.GetDirection(srcIp, dstIp),
                1, 0.0, null,
                $"Unknown protocol on LDAP port, First bytes: {firstBytes}"
            );

            OptimizedLogger.LogImportant($"[UNKNOWN-LDAP] Unknown protocol on port 389: {srcIp}:{srcPort} -> {dstIp}:{dstPort}, First bytes: {firstBytes}");
        }

        // Add diagnostic method to check TCP reassembly
        private void DebugTcpReassembly(IPPacket ipPacket, TcpPacket tcp, byte[] completeMessage, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            try
            {
                OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] Packet: {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] TCP Flags: {tcp.Flags}, Seq: {tcp.SequenceNumber}, Ack: {tcp.AcknowledgmentNumber}");
                OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] Complete message length: {completeMessage?.Length ?? 0}");

                if (completeMessage != null && completeMessage.Length > 0)
                {
                    OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] First 16 bytes: {BitConverter.ToString(completeMessage, 0, Math.Min(16, completeMessage.Length))}");

                    // Check if it looks like LDAP
                    if (completeMessage[0] == 0x30)
                    {
                        OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] ✅ This looks like LDAP (starts with 0x30)");
                    }
                    else
                    {
                        OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] ❌ This doesn't look like LDAP (starts with 0x{completeMessage[0]:X2})");
                    }
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogImportant($"[TCP-REASSEMBLY-DEBUG] Error in debug method: {ex.Message}");
            }
        }



        /// <summary>
        /// Processes SMTP traffic to extract email sender, recipient, and subject.
        /// Logs SMTP transactions for further inspection.
        /// Now receives complete reassembled SMTP messages for accurate parsing.
        /// </summary>
       
        private void ProcessSmtp(int logId, byte[] payload, string srcIp, string dstIp, int srcPort,int dstPort)
        {
            try
            {
                if (payload == null || payload.Length == 0)
                {
                    OptimizedLogger.LogImportant($"[SMTP-DEBUG] Empty payload from {srcIp}:{srcPort} -> {dstIp}");
                    int smtpLogIdEmpty = SmtpLogBLL.Insert(logId, "no-payload", "no-payload", "No payload");
                    if (smtpLogIdEmpty <= 0)
                    {
                        OptimizedLogger.LogError($"[SMTP-DB-FAIL] Insert returned {smtpLogIdEmpty} for empty payload (logId={logId})");
                        Interlocked.Increment(ref _errorCount);
                    }
                    return;
                }

                // === Diagnostic previews ===
                string asciiPreview;
                try { asciiPreview = Encoding.ASCII.GetString(payload.Take(512).ToArray()); }
                catch { asciiPreview = string.Empty; }

                string hexPreview = BitConverter.ToString(payload.Take(64).ToArray());
               

                // === Parse using enhanced parser (handles plain, TLS, STARTTLS, AUTH) ===
                var result = _smtpParser.Parse(payload,srcIp,dstIp,srcPort,dstPort);

              

                // === Authentication Info ===
                if (result.HasAuthAttempt)
                {
                    var credsInfo = result.DecodedCredentials.Count > 0
                        ? string.Join(", ", result.DecodedCredentials.Select(kv => $"{kv.Key}={kv.Value}"))
                        : "none";
                    OptimizedLogger.LogImportant($"[SMTP-AUTH] Detected {result.AuthMethod} authentication | Credentials={credsInfo}");
                }

                if (result.IsStartTls)
                {
                    OptimizedLogger.LogImportant($"[SMTP-TLS] STARTTLS negotiation detected in session {srcIp}:{srcPort} -> {dstIp}");
                }

                // === Insert into DB ===
                string fromTo = string.IsNullOrEmpty(result.FromAddress) ? "unknown" : result.FromAddress;
                string toTo = string.IsNullOrEmpty(result.ToAddress) ? "unknown" : result.ToAddress;
                string subj = string.IsNullOrEmpty(result.Subject) ? "(no-subject)" : result.Subject;

                string extraInfo = subj;
                if (result.IsEncrypted)
                    extraInfo = "[ENCRYPTED] " + subj;
                else if (result.IsStartTls)
                    extraInfo = "[STARTTLS] " + subj;
                else if (result.HasAuthAttempt)
                    extraInfo = $"[AUTH-{result.AuthMethod}] " + subj;

                int smtpLogId = SmtpLogBLL.Insert(logId, fromTo, toTo, extraInfo);

                if (smtpLogId <= 0)
                {
                    OptimizedLogger.LogError($"[SMTP-DB-FAIL] Failed to insert SMTP log (logId={logId}) | From={fromTo}, To={toTo}, SubjectLen={subj?.Length ?? 0} | return={smtpLogId}");
                    OptimizedLogger.LogImportant($"[SMTP-DB-FAIL] ASCII preview: {asciiPreview}");
                    OptimizedLogger.LogImportant($"[SMTP-DB-FAIL] HEX preview: {hexPreview}");
                    Interlocked.Increment(ref _errorCount);
                }
                else
                {
                    OptimizedLogger.LogImportant($"[SMTP-LOG-INSERTED] SMTP log inserted successfully (smtpLogId={smtpLogId}) for logId={logId}");
                }

                // === Suspicious content alert ===
                if (result.IsSuspicious && result.SuspicionReasons.Count > 0)
                {
                    string alertMsg = $"Suspicious Email Detected: {string.Join(", ", result.SuspicionReasons)}";
                    GenerateAlert(logId, srcIp, dstIp, payload.Length, alertMsg, "SMTP_Suspicious_Email", null, "Medium");
                    OptimizedLogger.LogImportant($"[SMTP-ALERT] {alertMsg}");
                }

                // === Credential exposure alert ===
                if (result.HasAuthAttempt && result.DecodedCredentials.Count > 0)
                {
                    string alertMsg = $"SMTP Credentials Exposure Detected ({result.AuthMethod}): {string.Join(", ", result.DecodedCredentials.Keys)} found.";
                    GenerateAlert(logId, srcIp, dstIp, payload.Length, alertMsg, "SMTP_Auth_Exposure", null, "High");
                    OptimizedLogger.LogImportant($"[SMTP-ALERT] {alertMsg}");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[SMTP-ERROR] Error processing SMTP for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes Telnet traffic to extract commands and authentication attempts.
        /// Logs Telnet session activity for security auditing.
        /// Now receives complete reassembled Telnet data for accurate parsing.
        /// </summary>
        private void ProcessTelnet(int logId, byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            try
            {
                var result = _telnetParser.Parse(payload, srcIp, dstIp, srcPort);
                if (TelnetLogBLL.Insert(logId, result.ClientIp, result.ServerIp, result.Command, result.AuthAttempts) <= 0)
                {
                    OptimizedLogger.LogError($"Failed to insert Telnet log for logId {logId}");
                    Interlocked.Increment(ref _errorCount);
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing Telnet protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes RDP traffic to track session IDs and authentication attempts.
        /// Logs RDP session details for monitoring remote connections.
        /// Now receives complete reassembled RDP data for accurate parsing.
        /// </summary>
        private void ProcessRdp(int logId, byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            try
            {
                var result = _rdpParser.Parse(payload, srcIp, dstIp, srcPort);
                if (RdpLogBLL.Insert(logId, result.ClientIp, result.ServerIp, result.SessionId, result.AuthAttempts) <= 0)
                {
                    OptimizedLogger.LogError($"Failed to insert RDP log for logId {logId}");
                    Interlocked.Increment(ref _errorCount);
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing RDP protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes TLS/SSL traffic to extract SNI, version, cipher suite, and certificate information.
        /// Logs TLS handshake details and fingerprints for threat correlation.
        /// Now receives complete reassembled TLS data for accurate parsing.
        /// </summary>
        private void ProcessTls(int logId, byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            try
            {
                // Enhanced TLS detection - look for TLS handshake patterns
                if (payload.Length >= 5 && payload[0] == 0x16) // TLS Handshake
                {
                    var result = _tlsParser.Parse(payload, srcIp);
                    // ... existing processing
                }
                else if (payload.Length >= 3 && payload[0] == 0x17) // TLS Application Data
                {
                    OptimizedLogger.LogImportant($"[TLS] Encrypted application data from {srcIp}:{srcPort}");
                    // Handle encrypted payload differently
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[TLS] Processing error: {ex.Message}");
            }
        }

        /// <summary>
        /// Processes ICMP packets to extract type and code information.
        /// Logs ICMP activity such as Echo Requests and Destination Unreachable messages.
        /// </summary>
        private void ProcessIcmp(int logId, IPPacket ip, string srcIp, string dstIp)
        {
            try
            {
                if (ip.PayloadPacket is IcmpV4Packet icmp)
                {
                    ushort combined = (ushort)icmp.TypeCode;
                    byte icmpType = (byte)(combined >> 8);
                    byte icmpCode = (byte)(combined & 0xFF);

                    if (IcmpLogBLL.Insert(logId, icmpType, icmpCode, srcIp, dstIp) <= 0)
                    {
                        OptimizedLogger.LogError($"Failed to insert ICMP log for logId {logId}");
                        Interlocked.Increment(ref _errorCount);
                    }
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing ICMP protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Processes DHCP traffic to identify message types such as Offer and Request.
        /// Logs DHCP exchanges for IP assignment tracking.
        /// Now receives complete reassembled DHCP messages for accurate parsing.
        /// </summary>
        private void ProcessDhcp(int logId, UdpPacket udp, byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort)

        {
            try
            {
                using (DhcpParser parser = new DhcpParser())
                {
                    // Parse the DHCP packet
                    byte[] dhcpPayload = payload;
                    if (dhcpPayload == null || dhcpPayload.Length == 0)
                        dhcpPayload = udp?.PayloadData ?? Array.Empty<byte>();
                    DhcpParserResult result = parser.Parse(dhcpPayload, srcIp, dstIp, srcPort, dstPort);

                    // Enhanced debugging for problematic packets
                    if (result.MessageType == "Unknown" || result.TransactionId == "N/A")
                    {
                        string hexDump = parser.GetDetailedHexDump(dhcpPayload, 128);
                        OptimizedLogger.LogImportant($"DHCP DEBUG - Problematic Packet Analysis:");
                        OptimizedLogger.LogImportant($"Source: {srcIp}:{srcPort} -> Dest: {dstIp}:{dstPort}");
                        OptimizedLogger.LogImportant($"Payload Length: {dhcpPayload?.Length}");
                        OptimizedLogger.LogImportant($"Parse Result: {result.Notes}");
                        OptimizedLogger.LogImportant($"Hex Dump (first 128 bytes):");
                        OptimizedLogger.LogImportant(hexDump);
                    }

                    // Use the parsed result to insert into database
                    int insertResult = DhcpLogBLL.Insert(
                        logId,
                        result.MessageType,
                        result.TransactionId,
                        result.ClientIp,
                        result.OfferedIp,
                        result.ServerIp,
                        srcIp,
                        dstIp,
                        DateTime.Now,
                        string.Format("{0}:{1}->{2}:{3}", srcIp, srcPort, dstIp, dstPort),
                        result.IsSuspicious ? "Suspicious" : "Processed",
                        result.LeaseTime);

                    if (insertResult <= 0)
                    {
                        OptimizedLogger.LogError($"Failed to insert DHCP log for logId {logId}");
                        Interlocked.Increment(ref _errorCount);
                    }
                    else
                    {
                        // Log success with details
                        if (result.MessageType != "Unknown")
                        {
                            OptimizedLogger.LogImportant($"DHCP: {result.MessageType} from {srcIp}:{srcPort} to {dstIp}:{dstPort}, TXID: {result.TransactionId}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing DHCP protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);

                // Fallback: insert basic DHCP record even on error
                try
                {
                    DhcpLogBLL.Insert(
                        logId, "ERROR", "N/A", srcIp, "N/A", dstIp,
                        srcIp, dstIp, DateTime.Now, "N/A", $"Error: {ex.Message}", 0);
                }
                catch { }
            }
        }
        private void ProcessSsh(int logId, byte[] payload, string srcIp, string dstIp, int srcPort)
        {
            try
            {
                var result = _sshParser.Parse(payload, srcIp, dstIp, srcPort);

                if (SshLogBLL.Insert(logId, result.clientVersion, result.serverVersion, result.authAttempts) <= 0)
                {
                    OptimizedLogger.LogError($"Failed to insert SSH log for logId {logId}");
                    Interlocked.Increment(ref _errorCount);
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing SSH protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        private void ProcessNtp(int logId, UdpPacket udp, string srcIp, string dstIp)
        {
            try
            {
                // 🔧 FIX: Use correct method signature and payload data
                _ntpParser.Parse(
                    udp.PayloadData ?? Array.Empty<byte>(),
                    srcIp,
                    dstIp,
                    udp.SourcePort,
                    udp.DestinationPort
                );

                OptimizedLogger.LogImportant($"[NTP] Processed NTP packet from {srcIp}:{udp.SourcePort} to {dstIp}:{udp.DestinationPort}");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing NTP protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        private void ProcessNetbios(int logId, UdpPacket udp, string srcIp, string dstIp)
        {
            try
            {
                // 🔧 FIX: Add missing port parameters
                _netbiosParser.Parse(
                    udp.PayloadData ?? Array.Empty<byte>(),
                    srcIp,
                    dstIp,
                    udp.SourcePort,
                    udp.DestinationPort
                );

                OptimizedLogger.LogImportant($"[NETBIOS] Processed NETBIOS packet from {srcIp}:{udp.SourcePort} to {dstIp}:{udp.DestinationPort}");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error processing NETBIOS protocol for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }


        /// <summary>
        /// GenerateAlert with cooldown/dedup integration
        /// </summary>
        private void GenerateAlert(int logId, string src, string dst, double size, string sig, string method, int? sigId, string sev)
        {
            // FIX: Validate logId before proceeding
            if (logId <= 0)
            {
                OptimizedLogger.LogImportant($"[ALERT-SKIP] Skipping alert generation for invalid logId: {logId}, Method: {method}, {src}->{dst}");
                return;
            }   
            try
            {
                // Determine type and severity
                string type = sigId.HasValue ? SignatureBLL.GetAttackNameBySignatureId(sigId.Value) : sig;
                string severity = (method == "PortScan" || method == "Deauth")
                    ? sev
                    : (logId > 0 ? SignatureBLL.GetSeverityByLogId(logId) : sev);

                // stable alert key for dedup
                string alertKey = $"{method}:{src}->{dst}:{type}";
                var now = DateTime.Now;

                // offline mode bypass
                if (!_isOfflineMode)
                {
                    // local cache dedup (2 minutes)
                    if (_recentAlertsCache.TryGetValue(alertKey, out var lastAlertTime) &&
                        now - lastAlertTime < TimeSpan.FromMinutes(2))
                    {
                        OptimizedLogger.LogImportant($"[SKIPPED] Duplicate alert suppressed for {method} {src}->{dst} ({type})");
                        return;
                    }

                    _recentAlertsCache[alertKey] = now;

                    // global cooldown via CanInsertAlert
                    if (!CanInsertAlert(sig, src, dst))
                    {
                        OptimizedLogger.LogImportant($"[SKIPPED] Alert suppressed by global cooldown for {method} {src}->{dst}");
                        return;
                    }
                }

                // Insert alert into DB
                bool inserted = InsertAlertIfAllowed(logId, sig, type, severity, src, dst, "", now, "New");

                if (inserted)
                {
                    // Throttle repetitive alerts for output/log noise
                    if (!ShouldThrottleAlert(method, src, dst))
                    {
                        OptimizedLogger.LogImportant($"[ALERT] {method} from {src} to {dst} - {type} ({severity})");
                    }
                }
                else
                {
                    OptimizedLogger.LogError($"[DB-FAIL] Failed to insert alert for {method} ({src}->{dst})");
                    Interlocked.Increment(ref _errorCount);
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[ALERT-EXCEPTION] Error in GenerateAlert for {method}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }


        /// <summary>
        /// Determines if an alert should be throttled
        /// </summary>
        /// <summary>
        /// ShouldThrottleAlert: detailed (src->dst) and global (src) throttling
        /// </summary>
        private bool ShouldThrottleAlert(string method, string src, string dst)
        {
            // Backwards-compatible wrapper: we don't always have packetCount available here
            return ShouldThrottleAlert(method, src, dst, 0);
        }

        /// <summary>
        /// Flow-aware detailed ShouldThrottleAlert overload
        /// </summary>
        private bool ShouldThrottleAlert(string method, string src, string dst, int packetCount)
        {
            try
            {
                var key = $"{method}-{src}-{dst}";
                var now = DateTime.Now;

                if (_recentAlertsFlowCache.TryGetValue(key, out var last))
                {
                    bool isTooSoon = (now - last.lastAlert) < TimeSpan.FromSeconds(2);
                    bool isSameFlow = Math.Abs(packetCount - last.lastPacketCount) < 10; // 10 packets margin
                    if (isTooSoon || isSameFlow)
                        return true;
                }

                _recentAlertsFlowCache[key] = (now, packetCount);
                return false;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[THROTTLE-ERROR] Error in flow-aware ShouldThrottleAlert: {ex.Message}");
                return false;
            }
        }
        /// <summary>
        /// Generates enhanced alerts
        /// </summary>
        private void GenerateEnhancedAlert(int logId, Entity.Signatures rule, string srcIp, string dstIp, int packetSize)
        {
            string alertKey = $"{rule.SignatureId}:{srcIp}:{dstIp}";
            if (!ShouldGenerateAlert(alertKey))
                return;

            if (logId <= 0)
            {
                OptimizedLogger.LogError($"Cannot create alert: Invalid log ID {logId} for rule {rule.SignatureId}");
                Interlocked.Increment(ref _errorCount);
                return;
            }

            try
            {
                string alertMessage = $"{rule.Engine} Detection: {rule.AttackName}";
                string alertType = SignatureBLL.GetAttackNameBySignatureId(rule.SignatureId);
                string severity = rule.Severity;

                var enhancedAlertKey = $"enhanced-{rule.SignatureId}-{srcIp}-{dstIp}";
                if (_recentAlertsCache.TryGetValue(enhancedAlertKey, out var lastAlertTime) &&
                    DateTime.Now - lastAlertTime < _alertDedupWindow)
                {
                    OptimizedLogger.LogImportant($"Skipping duplicate enhanced alert: {enhancedAlertKey}");
                    return;
                }

                _recentAlertsCache[enhancedAlertKey] = DateTime.Now;

                if (InsertAlertIfAllowed(logId, alertMessage, alertType, severity, srcIp, dstIp, "", DateTime.Now, "New"))
                {
                    OptimizedLogger.LogImportant($"Enhanced alert generated: {rule.AttackName} from {srcIp} to {dstIp}");
                }
                else
                {
                    OptimizedLogger.LogError($"Failed to insert alert for logId {logId}");
                    Interlocked.Increment(ref _errorCount);
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"Error creating alert for log {logId}: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
            }
        }

        /// <summary>
        /// Creates a port scan log entry with local dedup protection and uses InsertLogIfAllowed
        /// </summary>
        private int CreatePortScanLogEntry(
            string srcIp,
            string destIp,
            int srcPort,
            int destPort,
            string tcpFlags,
            double duration,
            int portCount,
            int packetSize)
        {
            try
            {
                // descriptive info
                string info = $"Detected Port Scan: {portCount} unique destination ports scanned from {srcIp}";

                // In offline mode we let InsertLogIfAllowed handle everything; in live mode apply a quick per-src cooldown key
                string messageKey = $"PortScan:{srcIp}->{destIp}";
                if (!_isOfflineMode)
                {
                    if (_logCooldown.TryGetValue(messageKey, out var last) && (DateTime.Now - last) < _logCooldownTime)
                    {
                        OptimizedLogger.LogImportant($"[PortScan] Skipped duplicate log for {srcIp} (cooldown active)");
                        return -2;
                    }
                    _logCooldown[messageKey] = DateTime.Now;
                }

                int logId = InsertLogIfAllowed(
                    DateTime.Now,
                    srcIp,
                    destIp,
                    packetSize,
                    true,
                    "PortScan",
                    "PortScan",
                    srcPort,
                    destPort,
                    0,
                    tcpFlags,
                    _ruleEngine.GetDirection(srcIp, destIp),
                    portCount,
                    duration,
                    null,
                    info
                );

                if (logId > 0)
                {
                    OptimizedLogger.LogImportant($"[PortScan] Log entry inserted successfully for {srcIp} with ID={logId}");
                }
                else if (logId == -2)
                {
                    OptimizedLogger.LogImportant($"[PortScan] Log skipped for {srcIp} due to deduplication logic");
                }
                else
                {
                    OptimizedLogger.LogError($"[PortScan] Failed to insert log entry for {srcIp} (return code {logId})");
                    Interlocked.Increment(ref _errorCount);
                }

                return logId;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[PortScan] Error creating log entry: {ex.Message}");
                Interlocked.Increment(ref _errorCount);
                return 0;
            }
        }


        /// <summary>
        /// Port scan detection (uses ipPortAccess map and produces Log + Alert once per scan per src)
        /// </summary>
        private bool DetectPortScan(string srcIp, string destIp, IPPacket ip, string tcpFlags)
        {
            try
            {
                // If offline mode, still detect port scans but avoid dedup/cooldown suppression
                int port = 0;
                if (ip.PayloadPacket is TcpPacket tcp) port = tcp.DestinationPort;
                if (ip.PayloadPacket is UdpPacket udp) port = udp.DestinationPort;
                if (port == 0) return false;

                int[] benignPorts = { 80, 443, 53 };
                if (benignPorts.Contains(port))
                    return false;

                var ports = ipPortAccess.GetOrAdd(srcIp, _ => new HashSet<int>());
                bool isPortScan;
                lock (ports)
                {
                    ports.Add(port);
                    isPortScan = ports.Count > _config.PortScanThreshold;
                }

                if (!isPortScan) return false;

                var scanKey = $"{srcIp}-portscan";
                var now = DateTime.Now;

                if (!_isOfflineMode)
                {
                    if (_recentPortScans.TryGetValue(scanKey, out var lastAlertTime))
                    {
                        if (now - lastAlertTime < _portScanAlertInterval)
                        {
                            OptimizedLogger.LogImportant($"Skipping duplicate port scan alert for {srcIp}");
                            // remove tracked ports to avoid repeating quickly
                            ipPortAccess.TryRemove(srcIp, out _);
                            return true;
                        }
                    }
                }

                _recentPortScans[scanKey] = now;

                // Cleanup old scan alerts occasionally
                if (_recentPortScans.Count > 1000)
                {
                    var oldScans = _recentPortScans.Where(kv => now - kv.Value > TimeSpan.FromHours(2))
                                                  .Select(kv => kv.Key)
                                                  .Take(100)
                                                  .ToList();
                    foreach (var key in oldScans)
                        _recentPortScans.TryRemove(key, out _);
                }

                int portScanLogId = CreatePortScanLogEntry(
                    srcIp,
                    destIp,
                    0,
                    port,
                    tcpFlags,
                    0.0,
                    ports.Count,
                    ip.Bytes.Length
                );

                if (portScanLogId > 0)
                {
                    GenerateAlert(
                        portScanLogId,
                        srcIp,
                        destIp,
                        ports.Count,
                        "Port Scan",
                        "PortScan",
                        null, "Low"
                    );
                    OptimizedLogger.LogImportant($"[PortScan] Detected from {srcIp} -> {ports.Count} unique ports");
                }
                else
                {
                    OptimizedLogger.LogError($"[PortScan] Failed to create log entry for {srcIp}");
                }

                // reset the ports for this source after detecting a scan
                ipPortAccess.TryRemove(srcIp, out _);

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[PortScan] Detection error for {srcIp}->{destIp}: {ex.Message}");
                return false;
            }
        }



        /// <summary>
        /// Determines if traffic between two IP addresses is internal network traffic
        /// </summary>
        public bool IsInternalTraffic(string srcIp, string dstIp)
        {
            if (string.IsNullOrEmpty(srcIp) || string.IsNullOrEmpty(dstIp))
                return false;

            string[] internalRanges = {
            "192.168.", "10.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
            "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "127.0.0.1", "::1"
        };

            bool srcInternal = internalRanges.Any(range => srcIp.StartsWith(range));
            bool dstInternal = internalRanges.Any(range => dstIp.StartsWith(range));

            return srcInternal && dstInternal;
        }

        /// <summary>
        /// Gets current system status
        /// </summary>
        public string GetStatus()
        {
            return isRunning ?
                $"Running - Packets: {_totalPacketsProcessed}, Queue: {_packetQueue.Count}/{_packetQueue.BoundedCapacity}" :
                "Stopped";
        }

        /// <summary>
        /// Gets comprehensive system metrics
        /// </summary>
        public Dictionary<string, object> GetMetrics()
        {
            var reassemblyStats = _ipReassemblyManager.GetStats();

            return new Dictionary<string, object>
            {
                ["IsRunning"] = isRunning,
                ["TotalPacketsProcessed"] = _totalPacketsProcessed,
                ["TotalProcessingTimeMs"] = _totalProcessingTimeMs,
                ["RulesChecked"] = _rulesChecked,
                ["RulesMatched"] = _rulesMatched,
                ["ErrorCount"] = _errorCount,
                ["ActiveFlows"] = flows.Count,
                ["QueueSize"] = _packetQueue.Count,
                ["QueueCapacity"] = _packetQueue.BoundedCapacity,
                ["ActiveWorkers"] = _workerTasks.Count(t => !t.IsCompleted),
                ["TotalWorkers"] = _workerCount,
                ["MemoryUsageMB"] = GC.GetTotalMemory(false) / 1024 / 1024,
                ["ReassemblyBuffers"] = reassemblyStats.ActiveBuffers,
                ["ReassemblyMemoryUsage"] = reassemblyStats.TotalMemoryUsage
            };
        }
    }

    /// <summary>
    /// Wrapper class for packet capture data
    /// </summary>
    public class PacketCaptureWrapper
    {
        public byte[] Data { get; }
        public LinkLayers LinkLayerType { get; }
        public DateTime Timestamp { get; }

        /// <summary>
        /// Initializes a new packet capture wrapper
        /// </summary>
        public PacketCaptureWrapper(RawCapture raw)
        {
            Data = raw.Data;
            LinkLayerType = raw.LinkLayerType;
            Timestamp = raw.Timeval.Date;
        }
    }
}
