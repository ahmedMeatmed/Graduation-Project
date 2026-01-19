using IDSApp.BLL;
using IDSApp.Helper;

/// <summary>
/// Represents performance tuning parameters for the Intrusion Detection System (IDS).
/// Controls how many packets, threads, and rules are processed, optimizing speed and accuracy.
/// </summary>
public  class PerformanceSettings
{
    /// <summary>
    /// Maximum number of rules analyzed per packet.
    /// </summary>
    public int MaxRulesPerPacket { get; set; } = 50;

    /// <summary>
    /// If true, stops packet analysis after the first matching rule.
    /// </summary>
    public bool StopAfterFirstMatch { get; set; } = false;

    /// <summary>
    /// Number of worker threads used for concurrent packet analysis.
    /// </summary>
    public int WorkerThreads { get; set; } = Math.Max(2, Environment.ProcessorCount / 2);

    /// <summary>
    /// Maximum number of packets allowed in the processing queue.
    /// </summary>
    public int MaxQueueSize { get; set; } = 5000;

    /// <summary>
    /// Enables detailed logging for debugging and in-depth event tracking.
    /// </summary>
    public bool EnableDetailedLogging { get; set; } = false;

    /// <summary>
    /// Enables parsing of network protocols (e.g., TCP, UDP, DNS).
    /// </summary>
    public bool EnableProtocolParsing { get; set; } = true;

    /// <summary>
    /// Maximum number of pattern entries cached in memory for rule matching.
    /// </summary>
    public int MaxPatternCacheSize { get; set; } = 10000;

    /// <summary>
    /// Enables fast path optimization to skip redundant processing steps.
    /// </summary>
    public bool EnableFastPathOptimization { get; set; } = true;

    /// <summary>
    /// Number of packets processed together in one batch to improve throughput.
    /// </summary>
    public int BatchProcessingSize { get; set; } = 1000;

    /// <summary>
    /// Maximum allowed time (in milliseconds) for processing a single packet.
    /// </summary>
    public int MaxPacketProcessingTimeMs { get; set; } = 200;

    /// <summary>
    /// Enables YARA rule scanning for advanced pattern detection.
    /// </summary>
    public bool EnableYaraScanning { get; set; } = false;

    /// <summary>
    /// Maximum number of rules cached for faster matching.
    /// </summary>
    public int RuleCacheSize { get; set; } = 10000;
    public int MaxPortsPerRule { get; set; } = 50;
    public bool EnableMatchAnalysis { get; set; } = true;

    /// <summary>
    /// Enables diagnostic logs to monitor performance and health metrics.
    /// </summary>
    public bool EnableDiagnosticLogging { get; set; } = true;

    /// <summary>
    /// Time interval (in milliseconds) between diagnostic log entries.
    /// </summary>
    public int DiagnosticLogInterval { get; set; } = 5000;

    /// <summary>
    /// Loads performance settings dynamically from the Settings database table.
    /// Returns a fully populated PerformanceSettings object.
    /// </summary>
    /// <returns>A <see cref="PerformanceSettings"/> instance with current configuration values.</returns>
    public static PerformanceSettings LoadFromSettings()
    {
        try
        {
            return new PerformanceSettings
            {
                MaxRulesPerPacket = GetSetting("MaxRulesPerPacket", 50),
                EnableDetailedLogging = GetSetting("EnableDetailedLogging", false),
                EnableProtocolParsing = GetSetting("EnableProtocolParsing", true),
                MaxQueueSize = GetSetting("MaxQueueSize", 5000),
                WorkerThreads = Math.Max(1, GetSetting("WorkerThreads", Math.Max(2, Environment.ProcessorCount / 2))),
                MaxPatternCacheSize = GetSetting("MaxPatternCacheSize", 10000),
                EnableFastPathOptimization = GetSetting("EnableFastPathOptimization", false),
                BatchProcessingSize = GetSetting("BatchProcessingSize", 1000),
                MaxPacketProcessingTimeMs = GetSetting("MaxPacketProcessingTimeMs", 200),
                StopAfterFirstMatch = GetSetting("StopAfterFirstMatch", false),
                EnableYaraScanning = GetSetting("EnableYaraScanning", false),
                RuleCacheSize = GetSetting("RuleCacheSize", 10000),
                EnableDiagnosticLogging = GetSetting("EnableDiagnosticLogging", true),
                DiagnosticLogInterval = GetSetting("DiagnosticLogInterval", 5000),
                  MaxPortsPerRule = GetSetting("MaxPortsPerRule", 50),
                EnableMatchAnalysis = GetSetting("EnableMatchAnalysis", true)
            };
        }
        catch (Exception ex)
        {
            OptimizedLogger.LogError($"Error loading performance settings: {ex.Message}");
            return new PerformanceSettings();
        }
    }

    /// <summary>
    /// Retrieves a specific setting from the database by key, converting it to the desired type.
    /// </summary>
    /// <typeparam name="T">The expected data type of the setting value.</typeparam>
    /// <param name="key">The unique key identifying the setting.</param>
    /// <param name="defaultValue">The default value to return if retrieval fails.</param>
    /// <returns>The setting value if available; otherwise, the default value.</returns>
    private static T GetSetting<T>(string key, T defaultValue)
    {
        try
        {
            var value = SettingBLL.GetSetting(key);
            if (string.IsNullOrEmpty(value))
                return defaultValue;

            return (T)Convert.ChangeType(value, typeof(T));
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Refreshes the current performance settings by reloading from the database
    /// and updating the in-memory configuration values.
    /// </summary>
    public void Refresh()
    {
        var newSettings = LoadFromSettings();
        this.MaxRulesPerPacket = newSettings.MaxRulesPerPacket;
        this.EnableDetailedLogging = newSettings.EnableDetailedLogging;
        this.EnableProtocolParsing = newSettings.EnableProtocolParsing;
        this.MaxQueueSize = newSettings.MaxQueueSize;
        this.WorkerThreads = newSettings.WorkerThreads;
        this.MaxPatternCacheSize = newSettings.MaxPatternCacheSize;
        this.EnableFastPathOptimization = newSettings.EnableFastPathOptimization;
        this.BatchProcessingSize = newSettings.BatchProcessingSize;
        this.MaxPacketProcessingTimeMs = newSettings.MaxPacketProcessingTimeMs;
        this.StopAfterFirstMatch = newSettings.StopAfterFirstMatch;
        this.EnableYaraScanning = newSettings.EnableYaraScanning;
        this.RuleCacheSize = newSettings.RuleCacheSize;
        this.EnableDiagnosticLogging = newSettings.EnableDiagnosticLogging;
        this.DiagnosticLogInterval = newSettings.DiagnosticLogInterval;
    }
}
