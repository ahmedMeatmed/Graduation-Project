using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Helper
{
    /// <summary>
    /// Monitors and reports system performance metrics including packet processing statistics,
    /// memory usage, and rule matching performance. Generates periodic performance reports
    /// to help identify bottlenecks and optimize system performance.
    /// </summary>
    public class PerformanceMonitor
    {
        private readonly ConcurrentDictionary<string, long> _metrics = new ConcurrentDictionary<string, long>();
        private readonly System.Timers.Timer _reportTimer;

        /// <summary>
        /// Initializes a new instance of the PerformanceMonitor with default 60-second reporting interval
        /// </summary>
        public PerformanceMonitor()
        {
            _reportTimer = new System.Timers.Timer(60000);
            _reportTimer.Elapsed += (s, e) => GeneratePerformanceReport();
            _reportTimer.Start();
        }

        /// <summary>
        /// Records a performance metric with the specified name and value
        /// </summary>
        /// <param name="metricName">The name of the metric to record</param>
        /// <param name="value">The value to add to the metric counter</param>
        public void RecordMetric(string metricName, long value)
        {
            _metrics.AddOrUpdate(metricName, value, (k, v) => v + value);
        }

        /// <summary>
        /// Generates and logs a comprehensive performance report including key metrics
        /// such as packets processed, memory usage, and rule statistics
        /// </summary>
        public void GeneratePerformanceReport()
        {
            OptimizedLogger.LogImportant($"=== PERFORMANCE {DateTime.Now:HH:mm:ss} ===");

            var importantMetrics = _metrics.Where(m =>
                m.Key.Contains("Packets") ||
                m.Key.Contains("Memory") ||
                m.Key.Contains("Rules") ||
                m.Key.EndsWith("TimeMs"))
                .OrderBy(m => m.Key);

            foreach (var metric in importantMetrics)
            {
                OptimizedLogger.LogImportant($"  {metric.Key}: {metric.Value:N0}");
            }

            OptimizedLogger.LogImportant($"  Memory: {GC.GetTotalMemory(false) / 1024 / 1024}MB");
            OptimizedLogger.LogImportant($"=================================");

            _metrics.Clear();
        }

        /// <summary>
        /// Disposes the performance monitor and stops the reporting timer
        /// </summary>
        public void Dispose()
        {
            _reportTimer?.Stop();
            _reportTimer?.Dispose();
        }
    }

}
