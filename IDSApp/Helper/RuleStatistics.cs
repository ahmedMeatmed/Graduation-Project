using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using IDSApp.BLL;
using IDSApp.Entity;

namespace IDSApp.Helper
{
    /// <summary>
    /// Provides real-time collection and analysis of rule and protocol performance statistics.
    /// Periodically saves data to the database for long-term analytics.
    /// </summary>
    public class RuleStatistics
    {
        private readonly ConcurrentDictionary<int, RulePerformance> _rulePerf = new();
        private readonly ConcurrentDictionary<string, ProtocolPerformance> _protocolPerf = new();
        private readonly object _lock = new();
        private long _totalPacketsProcessed = 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="RuleStatistics"/> class.
        /// Starts a background timer to automatically persist statistics every 60 seconds.
        /// </summary>
        public RuleStatistics()
        {
            var timer = new System.Timers.Timer(60000);
            timer.Elapsed += (_, __) => SaveStatsToDatabase();
            timer.AutoReset = true;
            timer.Start();
            OptimizedLogger.LogImportant("[RuleStatistics] Timer started for saving stats every 60 seconds.");
        }

        #region Record Protocol Stats

        /// <summary>
        /// Records a packet occurrence for the specified protocol (legacy overload).
        /// </summary>
        /// <param name="protocol">The protocol name (e.g., TCP, UDP, DNS).</param>
        public void RecordProtocolPacket(string protocol)
        {
            RecordProtocolPacket(protocol, 0, "");
        }

        /// <summary>
        /// Records a packet occurrence and its size for a specific protocol.
        /// </summary>
        /// <param name="protocol">The protocol name.</param>
        /// <param name="packetSize">The size of the captured packet in bytes.</param>
        public void RecordProtocolPacket(string protocol, int packetSize)
        {
            RecordProtocolPacket(protocol, packetSize, "");
        }

        /// <summary>
        /// Records protocol activity with optional additional information.
        /// Updates packet count, total bytes, and logs every 100 packets.
        /// </summary>
        /// <param name="protocol">The protocol name (e.g., TCP, HTTP).</param>
        /// <param name="packetSize">Packet size in bytes.</param>
        /// <param name="additionalInfo">Optional details such as source/destination.</param>
        public void RecordProtocolPacket(string protocol, int packetSize, string additionalInfo)
        {
            if (string.IsNullOrEmpty(protocol))
                protocol = "UNKNOWN";

            var perf = _protocolPerf.GetOrAdd(protocol, p => new ProtocolPerformance
            {
                Protocol = p,
                PacketCount = 0,
                TotalBytes = 0,
                AdditionalInfo = additionalInfo
            });

            perf.PacketCount++;
            perf.TotalBytes += packetSize;
            perf.LastUpdated = DateTime.Now;
            Interlocked.Increment(ref _totalPacketsProcessed);

            if (perf.PacketCount % 100 == 0)
            {
                string info = string.IsNullOrEmpty(additionalInfo) ? "" : $" - {additionalInfo}";
                OptimizedLogger.LogDebug($"[ProtocolStats] {protocol}: {perf.PacketCount} packets, {perf.TotalBytes} bytes{info}");
            }
        }

        #endregion

        #region Record Rule Performance

        /// <summary>
        /// Records the performance result of a rule evaluation including matches, checks, and processing time.
        /// Calculates efficiency and match rate dynamically.
        /// </summary>
        /// <param name="signatureId">Unique ID of the rule signature.</param>
        /// <param name="attackName">Name of the associated attack.</param>
        /// <param name="matched">Whether the rule matched the packet.</param>
        /// <param name="processingTimeMs">Processing time in milliseconds.</param>
        public void RecordRuleHit(int signatureId, string attackName, bool matched, long processingTimeMs)
        {
            var perf = _rulePerf.GetOrAdd(signatureId, id => new RulePerformance
            {
                SignatureId = id,
                AttackName = attackName
            });

            perf.TotalChecks++;
            if (matched) perf.Matches++;
            perf.TotalProcessingTimeMs += processingTimeMs;
            perf.LastChecked = DateTime.Now;
            if (matched) perf.LastMatch = DateTime.Now;

            perf.AvgProcessingTimeMs = perf.TotalChecks > 0
                ? (double)perf.TotalProcessingTimeMs / perf.TotalChecks
                : 0;

            perf.MatchRate = perf.TotalChecks > 0
                ? ((double)perf.Matches / perf.TotalChecks) * 100
                : 0;

            perf.EfficiencyScore = perf.MatchRate / (1 + perf.AvgProcessingTimeMs / 1000.0);

            if (matched)
            {
                OptimizedLogger.LogPerformance($"[RuleMatch] SignatureId={signatureId}, Attack={attackName}, ProcessingTime={processingTimeMs}ms");
            }
        }

        #endregion

        #region Save Statistics

        /// <summary>
        /// Saves collected rule and protocol statistics to the database.
        /// Automatically invoked by the background timer.
        /// </summary>
        public void SaveStatsToDatabase()
        {
            lock (_lock)
            {
                try
                {
                    int ruleStatsSaved = 0;
                    int protocolStatsSaved = 0;

                    foreach (var rule in _rulePerf.Values.Where(r => r.TotalChecks > 0))
                    {
                        int rows = RuleStatsHistoryBLL.Insert(
                            rule.SignatureId,
                            rule.AttackName,
                            rule.TotalChecks,
                            rule.Matches,
                            rule.TotalProcessingTimeMs,
                            rule.MatchRate,
                            rule.AvgProcessingTimeMs,
                            rule.EfficiencyScore,
                            rule.LastChecked,
                            rule.LastMatch,
                            DateTime.Now
                        );
                        if (rows > 0) ruleStatsSaved++;
                    }

                    long totalPackets = _protocolPerf.Values.Sum(p => p.PacketCount);
                    foreach (var proto in _protocolPerf.Values.Where(p => p.PacketCount > 0))
                    {
                        double percentage = totalPackets > 0 ?
                            ((double)proto.PacketCount / totalPackets) * 100 : 0;

                        int rows = ProtocolStatsHistoryBLL.Insert(proto.Protocol, proto.PacketCount, totalPackets, percentage, DateTime.Now);
                        if (rows > 0) protocolStatsSaved++;
                    }

                    OptimizedLogger.LogImportant($"[RuleStatistics] Saved {ruleStatsSaved} rule stats and {protocolStatsSaved} protocol stats to database");
                    CleanupOldStats();
                }
                catch (Exception ex)
                {
                    OptimizedLogger.LogError($"[RuleStatistics] Error saving stats: {ex.Message}");
                }
            }
        }

        #endregion

        #region Cleanup

        /// <summary>
        /// Removes old or inactive statistics from memory to improve performance.
        /// Rules older than 30 minutes and protocols older than 1 hour are purged.
        /// </summary>
        private void CleanupOldStats()
        {
            try
            {
                var ruleCutoffTime = DateTime.Now.AddMinutes(-30);
                var oldRules = _rulePerf.Where(kvp =>
                    kvp.Value.LastChecked < ruleCutoffTime).ToList();

                foreach (var oldRule in oldRules)
                    _rulePerf.TryRemove(oldRule.Key, out _);

                var protocolCutoffTime = DateTime.Now.AddHours(-1);
                var oldProtocols = _protocolPerf.Where(kvp =>
                    kvp.Value.PacketCount == 0 ||
                    (kvp.Value.LastUpdated.HasValue && kvp.Value.LastUpdated < protocolCutoffTime)).ToList();

                foreach (var oldProtocol in oldProtocols)
                    _protocolPerf.TryRemove(oldProtocol.Key, out _);

                if (oldRules.Count > 0 || oldProtocols.Count > 0)
                {
                    OptimizedLogger.LogDebug($"[Cleanup] Removed {oldRules.Count} old rules and {oldProtocols.Count} old protocols");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[Cleanup] Error cleaning old stats: {ex.Message}");
            }
        }

        #endregion

        #region Reporting

        /// <summary>
        /// Prints a detailed performance report for both rule and protocol statistics to the log output.
        /// </summary>
        public void PrintPerformanceReport()
        {
            OptimizedLogger.LogImportant("\n=== Rule Performance Report ===");

            var activeRules = _rulePerf.Values
                .Where(r => r.TotalChecks > 0)
                .OrderByDescending(r => r.EfficiencyScore)
                .ToList();

            foreach (var rule in activeRules)
            {
                OptimizedLogger.LogImportant($"Rule {rule.SignatureId} [{rule.AttackName}] - " +
                    $"Checks: {rule.TotalChecks}, Matches: {rule.Matches}, " +
                    $"AvgTime: {rule.AvgProcessingTimeMs:F2}ms, " +
                    $"MatchRate: {rule.MatchRate:F2}%, " +
                    $"Efficiency: {rule.EfficiencyScore:F2}");
            }

            OptimizedLogger.LogImportant("\n=== Protocol Performance Report ===");

            var activeProtocols = _protocolPerf.Values
                .Where(p => p.PacketCount > 0)
                .OrderByDescending(p => p.PacketCount)
                .ToList();

            long totalPackets = activeProtocols.Sum(p => p.PacketCount);

            foreach (var proto in activeProtocols)
            {
                double percentage = totalPackets > 0 ?
                    ((double)proto.PacketCount / totalPackets) * 100 : 0;

                OptimizedLogger.LogImportant($"Protocol {proto.Protocol} - " +
                    $"Packets: {proto.PacketCount}, " +
                    $"Bytes: {proto.TotalBytes}, " +
                    $"Percentage: {percentage:F2}%");

                if (!string.IsNullOrEmpty(proto.AdditionalInfo))
                {
                    OptimizedLogger.LogImportant($"  Additional Info: {proto.AdditionalInfo}");
                }
            }

            OptimizedLogger.LogImportant($"\n=== Summary ===");
            OptimizedLogger.LogImportant($"Total Packets Processed: {_totalPacketsProcessed}");
            OptimizedLogger.LogImportant($"Active Rules: {activeRules.Count}");
            OptimizedLogger.LogImportant($"Active Protocols: {activeProtocols.Count}");
            OptimizedLogger.LogImportant($"Total Rule Checks: {activeRules.Sum(r => r.TotalChecks)}");
            OptimizedLogger.LogImportant($"Total Rule Matches: {activeRules.Sum(r => r.Matches)}");
        }

        #endregion

        #region Snapshot

        /// <summary>
        /// Generates a quick snapshot summary of current statistics for external monitoring or dashboards.
        /// </summary>
        /// <returns>A <see cref="StatisticsSnapshot"/> object containing key metrics.</returns>
        public StatisticsSnapshot GetCurrentSnapshot()
        {
            return new StatisticsSnapshot
            {
                TotalPackets = _totalPacketsProcessed,
                ActiveRules = _rulePerf.Values.Count(r => r.TotalChecks > 0),
                ActiveProtocols = _protocolPerf.Values.Count(p => p.PacketCount > 0),
                TotalRuleChecks = _rulePerf.Values.Sum(r => r.TotalChecks),
                TotalRuleMatches = _rulePerf.Values.Sum(r => r.Matches),
                Timestamp = DateTime.Now
            };
        }

        #endregion
    }

    /// <summary>
    /// Represents performance statistics for a specific IDS rule.
    /// Tracks total checks, matches, average time, and efficiency.
    /// </summary>
    public class RulePerformance
    {
        public int SignatureId { get; set; }
        public string AttackName { get; set; }
        public long TotalChecks { get; set; }
        public long Matches { get; set; }
        public long TotalProcessingTimeMs { get; set; }
        public double AvgProcessingTimeMs { get; set; }
        public double MatchRate { get; set; }
        public double EfficiencyScore { get; set; }
        public DateTime? LastChecked { get; set; }
        public DateTime? LastMatch { get; set; }
    }

    /// <summary>
    /// Represents performance metrics for a specific network protocol.
    /// Tracks packet counts, total bytes, and last update timestamp.
    /// </summary>
    public class ProtocolPerformance
    {
        public string Protocol { get; set; }
        public long PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public string AdditionalInfo { get; set; } = "";
        public DateTime? LastUpdated { get; set; } = DateTime.Now;
    }

    /// <summary>
    /// Provides a summarized snapshot of the current IDS performance metrics.
    /// Useful for dashboards and monitoring.
    /// </summary>
    public class StatisticsSnapshot
    {
        public long TotalPackets { get; set; }
        public int ActiveRules { get; set; }
        public int ActiveProtocols { get; set; }
        public long TotalRuleChecks { get; set; }
        public long TotalRuleMatches { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
