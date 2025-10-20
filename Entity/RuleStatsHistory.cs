using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents historical performance and effectiveness statistics for individual intrusion detection rules.
    /// Tracks rule efficiency, detection accuracy, and processing performance over time for rule optimization and tuning.
    /// </summary>
    internal class RuleStatsHistory
    {
        int id;
        int signatureId;
        string attackName;
        long totalChecks;
        long matches;
        long totalProcessingTimeMs;
        double matchRate;
        double avgProcessingTimeMs;
        double efficiencyScore;
        DateTime? lastChecked;
        DateTime? lastMatch;
        DateTime recordedAt;

        /// <summary>Unique identifier for the rule statistics record</summary>
        public int Id { get => id; set => id = value; }

        /// <summary>Unique identifier of the detection signature this rule implements</summary>
        public int SignatureId { get => signatureId; set => signatureId = value; }

        /// <summary>Name of the attack or threat this rule detects</summary>
        public string AttackName { get => attackName; set => attackName = value; }

        /// <summary>Total number of times this rule has been evaluated against network traffic</summary>
        public long TotalChecks { get => totalChecks; set => totalChecks = value; }

        /// <summary>Total number of times this rule has successfully matched and triggered alerts</summary>
        public long Matches { get => matches; set => matches = value; }

        /// <summary>Cumulative processing time spent evaluating this rule in milliseconds</summary>
        public long TotalProcessingTimeMs { get => totalProcessingTimeMs; set => totalProcessingTimeMs = value; }

        /// <summary>Rule effectiveness rate calculated as matches divided by total checks (percentage)</summary>
        public double MatchRate { get => matchRate; set => matchRate = value; }

        /// <summary>Average time taken to evaluate this rule against traffic in milliseconds</summary>
        public double AvgProcessingTimeMs { get => avgProcessingTimeMs; set => avgProcessingTimeMs = value; }

        /// <summary>Comprehensive score balancing detection effectiveness and processing efficiency</summary>
        public double EfficiencyScore { get => efficiencyScore; set => efficiencyScore = value; }

        /// <summary>Most recent timestamp when this rule was evaluated against traffic</summary>
        public DateTime? LastChecked { get => lastChecked; set => lastChecked = value; }

        /// <summary>Most recent timestamp when this rule successfully detected a threat</summary>
        public DateTime? LastMatch { get => lastMatch; set => lastMatch = value; }

        /// <summary>Timestamp when these rule statistics were recorded</summary>
        public DateTime RecordedAt { get => recordedAt; set => recordedAt = value; }

        /// <summary>
        /// Initializes a new instance of the RuleStatsHistory class with specified parameters.
        /// </summary>
        /// <param name="id">Unique identifier for the rule statistics record</param>
        /// <param name="signatureId">Unique identifier of the detection signature</param>
        /// <param name="attackName">Name of the attack or threat detected</param>
        /// <param name="totalChecks">Total number of rule evaluations</param>
        /// <param name="matches">Total number of successful detections</param>
        /// <param name="totalProcessingTimeMs">Cumulative processing time in milliseconds</param>
        /// <param name="matchRate">Rule effectiveness rate as percentage</param>
        /// <param name="avgProcessingTimeMs">Average evaluation time in milliseconds</param>
        /// <param name="efficiencyScore">Comprehensive efficiency score</param>
        /// <param name="lastChecked">Most recent evaluation timestamp</param>
        /// <param name="lastMatch">Most recent detection timestamp</param>
        /// <param name="recordedAt">When these statistics were recorded</param>
        internal RuleStatsHistory(int id, int signatureId, string attackName, long totalChecks, long matches,
            long totalProcessingTimeMs, double matchRate, double avgProcessingTimeMs, double efficiencyScore,
            DateTime? lastChecked, DateTime? lastMatch, DateTime recordedAt)
        {
            this.id = id;
            this.signatureId = signatureId;
            this.attackName = attackName;
            this.totalChecks = totalChecks;
            this.matches = matches;
            this.totalProcessingTimeMs = totalProcessingTimeMs;
            this.matchRate = matchRate;
            this.avgProcessingTimeMs = avgProcessingTimeMs;
            this.efficiencyScore = efficiencyScore;
            this.lastChecked = lastChecked;
            this.lastMatch = lastMatch;
            this.recordedAt = recordedAt;
        }

        /// <summary>
        /// Initializes a new instance of the RuleStatsHistory class as a copy of an existing RuleStatsHistory object.
        /// </summary>
        /// <param name="r">Source RuleStatsHistory object to copy from</param>
        internal RuleStatsHistory(RuleStatsHistory r) : this(r.id, r.signatureId, r.attackName, r.totalChecks, r.matches,
            r.totalProcessingTimeMs, r.matchRate, r.avgProcessingTimeMs, r.efficiencyScore,
            r.lastChecked, r.lastMatch, r.recordedAt)
        { }

        /// <summary>
        /// Creates a deep copy of the current RuleStatsHistory instance.
        /// </summary>
        /// <returns>A new RuleStatsHistory object that is an exact copy of the current instance</returns>
        public RuleStatsHistory Clone() => new RuleStatsHistory(this);
    }
}