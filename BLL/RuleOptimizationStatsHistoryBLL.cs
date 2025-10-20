using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for rule optimization statistics history management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for rule optimization statistics history operations.
    /// </summary>
    internal class RuleOptimizationStatsHistoryBLL
    {
        /// <summary>
        /// Retrieves all rule optimization statistics history records from the system.
        /// </summary>
        /// <returns>A collection of RuleOptimizationStatsHistory objects containing all rule optimization statistics history records in the system.</returns>
        public static RuleOptimizationStatsHistoryCollection GetAll()
        {
            return RuleOptimizationStatsHistoryDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific rule optimization statistics history record by its unique identifier.
        /// </summary>
        /// <param name="id">The ID of the rule optimization statistics history record to retrieve.</param>
        /// <returns>A RuleOptimizationStatsHistory object if found; otherwise, null.</returns>
        public static RuleOptimizationStatsHistory GetById(int id)
        {
            return RuleOptimizationStatsHistoryDal.GetById(id);
        }

        /// <summary>
        /// Creates a new rule optimization statistics history record in the system.
        /// </summary>
        /// <param name="totalFilters">The total number of active detection filters in the rule set.</param>
        /// <param name="totalRules">The total number of active detection rules in the system.</param>
        /// <param name="memoryUsage">The memory usage of the rule set in bytes.</param>
        /// <param name="falsePositiveEstimate">The estimated false positive rate as a percentage (0.0 to 100.0).</param>
        /// <param name="recordedAt">The date and time when these optimization statistics were recorded.</param>
        /// <returns>The newly created record ID if successful; otherwise, -1.</returns>
        public static int Insert(int totalFilters, int totalRules, long memoryUsage, double falsePositiveEstimate, DateTime recordedAt)
        {
            return RuleOptimizationStatsHistoryDal.Insert(totalFilters, totalRules, memoryUsage, falsePositiveEstimate, recordedAt);
        }

        /// <summary>
        /// Updates an existing rule optimization statistics history record with new information.
        /// </summary>
        /// <param name="id">The ID of the rule optimization statistics history record to update.</param>
        /// <param name="totalFilters">The updated total number of active detection filters.</param>
        /// <param name="totalRules">The updated total number of active detection rules.</param>
        /// <param name="memoryUsage">The updated memory usage in bytes.</param>
        /// <param name="falsePositiveEstimate">The updated false positive rate estimate.</param>
        /// <param name="recordedAt">The updated recording timestamp.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int id, int totalFilters, int totalRules, long memoryUsage, double falsePositiveEstimate, DateTime recordedAt)
        {
            return RuleOptimizationStatsHistoryDal.Update(id, totalFilters, totalRules, memoryUsage, falsePositiveEstimate, recordedAt);
        }

        /// <summary>
        /// Deletes a specific rule optimization statistics history record from the system.
        /// </summary>
        /// <param name="id">The ID of the rule optimization statistics history record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int id)
        {
            return RuleOptimizationStatsHistoryDal.Delete(id);
        }
    }
}