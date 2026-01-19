using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents historical statistics for intrusion detection rule optimization and performance metrics.
    /// Tracks the evolution of rule efficiency, memory usage, and accuracy over time for system tuning and performance monitoring.
    /// </summary>
    internal class RuleOptimizationStatsHistory
    {
        int id;
        int totalFilters;
        int totalRules;
        long memoryUsageBytes;
        double? falsePositiveEstimate;
        DateTime recordedAt;

        /// <summary>Unique identifier for the optimization statistics record</summary>
        public int Id { get => id; set => id = value; }

        /// <summary>Total number of active detection filters in the rule set</summary>
        public int TotalFilters { get => totalFilters; set => totalFilters = value; }

        /// <summary>Total number of active detection rules in the system</summary>
        public int TotalRules { get => totalRules; set => totalRules = value; }

        /// <summary>Memory consumption of the rule set in bytes</summary>
        public long MemoryUsageBytes { get => memoryUsageBytes; set => memoryUsageBytes = value; }

        /// <summary>Estimated false positive rate as a percentage (0-100) or decimal (0-1)</summary>
        public double? FalsePositiveEstimate { get => falsePositiveEstimate; set => falsePositiveEstimate = value; }

        /// <summary>Timestamp when these optimization statistics were recorded</summary>
        public DateTime RecordedAt { get => recordedAt; set => recordedAt = value; }

        /// <summary>
        /// Initializes a new instance of the RuleOptimizationStatsHistory class with specified parameters.
        /// </summary>
        /// <param name="id">Unique identifier for the optimization statistics record</param>
        /// <param name="totalFilters">Total number of active detection filters</param>
        /// <param name="totalRules">Total number of active detection rules</param>
        /// <param name="memoryUsageBytes">Memory consumption of the rule set in bytes</param>
        /// <param name="falsePositiveEstimate">Estimated false positive rate</param>
        /// <param name="recordedAt">When these statistics were recorded</param>
        internal RuleOptimizationStatsHistory(int id, int totalFilters, int totalRules, long memoryUsageBytes, double? falsePositiveEstimate, DateTime recordedAt)
        {
            this.id = id;
            this.totalFilters = totalFilters;
            this.totalRules = totalRules;
            this.memoryUsageBytes = memoryUsageBytes;
            this.falsePositiveEstimate = falsePositiveEstimate;
            this.recordedAt = recordedAt;
        }

        /// <summary>
        /// Initializes a new instance of the RuleOptimizationStatsHistory class as a copy of an existing RuleOptimizationStatsHistory object.
        /// </summary>
        /// <param name="r">Source RuleOptimizationStatsHistory object to copy from</param>
        internal RuleOptimizationStatsHistory(RuleOptimizationStatsHistory r) : this(r.id, r.totalFilters, r.totalRules, r.memoryUsageBytes, r.falsePositiveEstimate, r.recordedAt) { }

        /// <summary>
        /// Creates a deep copy of the current RuleOptimizationStatsHistory instance.
        /// </summary>
        /// <returns>A new RuleOptimizationStatsHistory object that is an exact copy of the current instance</returns>
        public RuleOptimizationStatsHistory Clone() => new RuleOptimizationStatsHistory(this);
    }
}