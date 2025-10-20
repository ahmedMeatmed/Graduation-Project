using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for rule statistics history management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for rule statistics history operations.
    /// </summary>
    internal class RuleStatsHistoryBLL
    {
        /// <summary>
        /// Retrieves all rule statistics history records from the system.
        /// </summary>
        /// <returns>A collection of RuleStatsHistory objects containing all rule statistics history records in the system.</returns>
        public static RuleStatsHistoryCollection GetAll()
        {
            return RuleStatsHistoryDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific rule statistics history record by its unique identifier.
        /// </summary>
        /// <param name="id">The ID of the rule statistics history record to retrieve.</param>
        /// <returns>A RuleStatsHistory object if found; otherwise, null.</returns>
        public static RuleStatsHistory GetById(int id)
        {
            return RuleStatsHistoryDal.GetById(id);
        }

        /// <summary>
        /// Creates a new rule statistics history record in the system.
        /// </summary>
        /// <param name="signatureId">The unique identifier of the detection signature/rule.</param>
        /// <param name="attackName">The name of the attack or threat that the rule detects.</param>
        /// <param name="totalChecks">The total number of times this rule has been evaluated against network traffic.</param>
        /// <param name="matches">The number of times this rule has successfully matched (detected attacks).</param>
        /// <param name="totalProcessingTimeMs">The cumulative processing time spent on this rule in milliseconds.</param>
        /// <param name="matchRate">The success rate of the rule as a percentage (matches divided by total checks).</param>
        /// <param name="avgProcessingTimeMs">The average processing time per rule evaluation in milliseconds.</param>
        /// <param name="efficiencyScore">A calculated efficiency score balancing detection accuracy and performance impact.</param>
        /// <param name="lastChecked">The most recent date and time when this rule was evaluated, if applicable.</param>
        /// <param name="lastMatch">The most recent date and time when this rule successfully detected an attack, if applicable.</param>
        /// <param name="recordedAt">The date and time when these rule statistics were recorded.</param>
        /// <returns>The newly created record ID if successful; otherwise, -1.</returns>
        public static int Insert(int signatureId, string attackName, long totalChecks, long matches,
                                 long totalProcessingTimeMs, double matchRate, double avgProcessingTimeMs,
                                 double efficiencyScore, DateTime? lastChecked, DateTime? lastMatch, DateTime recordedAt)
        {
            return RuleStatsHistoryDal.Insert(signatureId, attackName, totalChecks, matches,
                                              totalProcessingTimeMs, matchRate, avgProcessingTimeMs,
                                              efficiencyScore, lastChecked, lastMatch, recordedAt);
        }

        /// <summary>
        /// Updates an existing rule statistics history record with new information.
        /// </summary>
        /// <param name="id">The ID of the rule statistics history record to update.</param>
        /// <param name="signatureId">The updated signature identifier.</param>
        /// <param name="attackName">The updated attack name.</param>
        /// <param name="totalChecks">The updated total number of rule evaluations.</param>
        /// <param name="matches">The updated number of successful detections.</param>
        /// <param name="totalProcessingTimeMs">The updated cumulative processing time.</param>
        /// <param name="matchRate">The updated match rate percentage.</param>
        /// <param name="avgProcessingTimeMs">The updated average processing time.</param>
        /// <param name="efficiencyScore">The updated efficiency score.</param>
        /// <param name="lastChecked">The updated last checked timestamp.</param>
        /// <param name="lastMatch">The updated last match timestamp.</param>
        /// <param name="recordedAt">The updated recording timestamp.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int id, int signatureId, string attackName, long totalChecks, long matches,
                                  long totalProcessingTimeMs, double matchRate, double avgProcessingTimeMs,
                                  double efficiencyScore, DateTime? lastChecked, DateTime? lastMatch, DateTime recordedAt)
        {
            return RuleStatsHistoryDal.Update(id, signatureId, attackName, totalChecks, matches,
                                              totalProcessingTimeMs, matchRate, avgProcessingTimeMs,
                                              efficiencyScore, lastChecked, lastMatch, recordedAt);
        }

        /// <summary>
        /// Deletes a specific rule statistics history record from the system.
        /// </summary>
        /// <param name="id">The ID of the rule statistics history record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int id)
        {
            return RuleStatsHistoryDal.Delete(id);
        }
    }
}