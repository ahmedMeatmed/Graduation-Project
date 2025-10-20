using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace IDSApp.Helper
{
    /// <summary>
    /// Provides optimized logging functionality for the IDS system with configurable log levels
    /// to reduce console clutter while maintaining essential statistics and critical information.
    /// </summary>
    public static class OptimizedLogger
    {
        // 🔧 REDUCED LOGGING: Disable most verbose logs, keep only essentials
        private static readonly bool EnableRuleLogs = false;      // Reduced: disable rule matching logs
        private static readonly bool EnablePerfLogs = true;       // Keep: performance statistics
        private static readonly bool EnableDebugLogs = true;     // Reduced: disable debug logs
        private static readonly bool EnableNetworkLogs = false;   // Reduced: disable network logs
        private static readonly bool EnableQueueLogs = false;     // Reduced: disable queue logs
        private static readonly bool EnablePacketStats = true;    // Keep: packet statistics

        // 🔧 INCREASED INTERVALS: Log less frequently
        private static readonly int StatsLogInterval = 10000;     // Increased: every 10,000 packets
        private static readonly int PerfLogInterval = 5000;       // Increased: every 5,000 packets
        private static readonly int SlowProcessingThreshold = 200; // Increased: only log >200ms

        private static long _packetCounter = 0;
        private static readonly ConcurrentQueue<string> _logQueue = new ConcurrentQueue<string>();
        private static readonly System.Timers.Timer _flushTimer;
        private static readonly object _lockObject = new object();
        private static bool _isFlushing = false;

        // 🔧 NEW: Log level control
        public enum LogLevel
        {
            ERROR = 0,
            IMPORTANT = 1,
            STATS = 2,
            PERFORMANCE = 3,
            DEBUG = 4
        }

        public static LogLevel CurrentLogLevel { get; set; } = LogLevel.STATS;

        static OptimizedLogger()
        {
            _flushTimer = new System.Timers.Timer(3000); // Increased flush interval
            _flushTimer.Elapsed += (s, e) => FlushLogs();
            _flushTimer.Start();
        }

        /// <summary>
        /// Logs debug information (disabled by default to reduce console output)
        /// </summary>
        public static void LogDebug(string message)
        {
            if (!EnableDebugLogs || CurrentLogLevel < LogLevel.DEBUG) return;
            EnqueueLog($"[DEBUG] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs network-related information (disabled by default)
        /// </summary>
        public static void LogNetwork(string message)
        {
            if (!EnableNetworkLogs || CurrentLogLevel < LogLevel.DEBUG) return;
            EnqueueLog($"[NETWORK] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs queue operations (disabled by default)
        /// </summary>
        public static void LogQueue(string message)
        {
            if (!EnableQueueLogs || CurrentLogLevel < LogLevel.DEBUG) return;
            EnqueueLog($"[QUEUE] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs rule matching events with throttling to prevent spam
        /// </summary>
        public static void LogRuleMatch(string message)
        {
            if (!EnableRuleLogs || CurrentLogLevel < LogLevel.DEBUG) return;

            // 🔧 STRICT THROTTLING: Only log every 100th rule match or important ones
            if (ShouldThrottleLog(message) && GetPacketCount() % 100 != 0) return;

            Console.WriteLine($"[RULE_MATCH] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs performance metrics at configured intervals
        /// </summary>
        public static void LogPerformance(string message)
        {
            if (!EnablePerfLogs || CurrentLogLevel < LogLevel.PERFORMANCE) return;

            // 🔧 FILTER: Only log slow operations or periodic stats
            if (message.Contains("ms"))
            {
                var msValue = ExtractMsValue(message);
                if (msValue < SlowProcessingThreshold && !message.Contains("Avg:")) return;
            }

            if (!ShouldLog("PERF", PerfLogInterval)) return;
            Console.WriteLine($"[PERF] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs rule processing information (reduced frequency)
        /// </summary>
        public static void LogRule(string message)
        {
            if (!EnableRuleLogs || CurrentLogLevel < LogLevel.DEBUG) return;

            // 🔧 REDUCED FREQUENCY: Log only errors or every 1000 packets
            if (!message.Contains("ERROR") && !message.Contains("MATCH") && GetPacketCount() % 1000 != 0) return;

            Console.WriteLine($"[RULE] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs error messages (always enabled for critical issues)
        /// </summary>
        public static void LogError(string message)
        {
            // Errors are always logged regardless of level
            Console.WriteLine($"[ERROR] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs important system events (startup, shutdown, alerts)
        /// </summary>
        public static void LogImportant(string message)
        {
            if (CurrentLogLevel < LogLevel.IMPORTANT) return;
            Console.WriteLine($"[INFO] {DateTime.Now:HH:mm:ss} {message}");
        }

        /// <summary>
        /// Logs packet statistics at configured intervals
        /// </summary>
        public static void LogPacketStats(string message)
        {
            if (!EnablePacketStats || CurrentLogLevel < LogLevel.STATS) return;
            if (!ShouldLog("STATS", StatsLogInterval)) return;
            Console.WriteLine($"[STATS] {DateTime.Now:HH:mm:ss} {message}");
        }

        // ==================== UTILITY METHODS ====================

        /// <summary>
        /// Increments the global packet counter for statistics
        /// </summary>
        public static void IncrementPacketCounter()
        {
            Interlocked.Increment(ref _packetCounter);
        }

        /// <summary>
        /// Gets the current packet count for statistical purposes
        /// </summary>
        public static long GetPacketCount()
        {
            return Interlocked.Read(ref _packetCounter);
        }

        /// <summary>
        /// Determines if logging should occur based on interval and packet count
        /// </summary>
        private static bool ShouldLog(string category, int interval)
        {
            return GetPacketCount() % interval == 0;
        }

        /// <summary>
        /// Throttles repetitive log messages to prevent console spam
        /// </summary>
        private static readonly ConcurrentDictionary<string, DateTime> _lastLogMessages = new();
        private static readonly TimeSpan _logThrottleInterval = TimeSpan.FromSeconds(10); // Increased to 10 seconds

        private static bool ShouldThrottleLog(string message)
        {
            var now = DateTime.Now;
            var key = GetMessageKey(message);

            if (_lastLogMessages.TryGetValue(key, out var lastLogTime))
            {
                if (now - lastLogTime < _logThrottleInterval)
                    return true;
            }

            _lastLogMessages[key] = now;

            // Cleanup old entries periodically
            if (_lastLogMessages.Count > 1000)
            {
                var oldMessages = _lastLogMessages.Where(kv => now - kv.Value > TimeSpan.FromMinutes(5))
                                                .Select(kv => kv.Key)
                                                .Take(100)
                                                .ToList();
                foreach (var oldKey in oldMessages)
                    _lastLogMessages.TryRemove(oldKey, out _);
            }

            return false;
        }

        private static string GetMessageKey(string message)
        {
            // Extract the core part of the message for throttling
            if (message.Contains("ProcessIPPacket")) return "ProcessIPPacket";
            if (message.Contains("ProcessEthernet")) return "ProcessEthernet";
            if (message.Contains("Avg:")) return "WorkerAvg";
            if (message.Contains("RuleMatch")) return "RuleMatch";
            return message.Length > 50 ? message.Substring(0, 50) : message;
        }

        private static double ExtractMsValue(string message)
        {
            try
            {
                var match = Regex.Match(message, @"(\d+)ms");
                if (match.Success && double.TryParse(match.Groups[1].Value, out double ms))
                {
                    return ms;
                }
            }
            catch { }
            return 0;
        }

        private static void EnqueueLog(string logMessage)
        {
            _logQueue.Enqueue(logMessage);

            if (_logQueue.Count > 500) // Reduced queue size
            {
                FlushLogs();
            }
        }

        private static void FlushLogs()
        {
            if (_isFlushing) return;

            lock (_lockObject)
            {
                _isFlushing = true;
                try
                {
                    int count = 0;
                    while (_logQueue.TryDequeue(out var message) && count < 50) // Reduced batch size
                    {
                        Console.WriteLine(message);
                        count++;
                    }
                }
                finally
                {
                    _isFlushing = false;
                }
            }
        }

        /// <summary>
        /// Disposes the logger and flushes any remaining messages
        /// </summary>
        public static void Dispose()
        {
            _flushTimer?.Stop();
            _flushTimer?.Dispose();
            FlushLogs();
        }
    }
}