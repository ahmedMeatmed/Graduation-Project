using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling rule optimization statistics history-related operations
    /// </summary>
    internal class RuleOptimizationStatsHistoryDal
    {
        /// <summary>
        /// Retrieves all rule optimization statistics history records from the database
        /// </summary>
        /// <returns>A RuleOptimizationStatsHistoryCollection containing all historical rule optimization statistics</returns>
        public static RuleOptimizationStatsHistoryCollection GetAll()
        {
            RuleOptimizationStatsHistoryCollection list = new RuleOptimizationStatsHistoryCollection();
            try
            {
                string query = "SELECT * FROM RuleOptimizationStatsHistory";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    RuleOptimizationStatsHistory item = new RuleOptimizationStatsHistory(
                        (int)row["Id"],
                        (int)row["TotalFilters"],
                        (int)row["TotalRules"],
                        (long)row["MemoryUsageBytes"],
                        (double)row["FalsePositiveEstimate"],
                        (DateTime)row["RecordedAt"]

                    );
                    list.Add(item);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RuleOptimizationStatsHistory: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific rule optimization statistics history record by its unique identifier
        /// </summary>
        /// <param name="id">The Id of the rule optimization statistics history record to retrieve</param>
        /// <returns>A RuleOptimizationStatsHistory object if found, otherwise null</returns>
        public static RuleOptimizationStatsHistory GetById(int id)
        {
            RuleOptimizationStatsHistory item = null;
            try
            {
                string query = "SELECT * FROM RuleOptimizationStatsHistory WHERE Id = @Id";
                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    item = new RuleOptimizationStatsHistory(
                        (int)row["Id"],
                        (int)row["TotalFilters"],
                        (int)row["TotalRules"],
                        (long)row["MemoryUsageBytes"],
                         (double)row["FalsePositiveEstimate"],
                        (DateTime)row["RecordedAt"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RuleOptimizationStatsHistory by ID: " + ex.Message);
            }
            return item;
        }

        /// <summary>
        /// Inserts a new rule optimization statistics history record into the database
        /// </summary>
        /// <param name="totalFilters">The total number of active filters in the IDS rule set</param>
        /// <param name="totalRules">The total number of active detection rules</param>
        /// <param name="memoryUsage">The memory usage of the rule set in bytes</param>
        /// <param name="falsePositiveEstimate">The estimated false positive rate as a percentage (0.0 to 1.0 or 0% to 100%)</param>
        /// <param name="recordedAt">The timestamp when these optimization statistics were recorded</param>
        /// <returns>The newly created record Id if successful, otherwise -1</returns>
        public static int Insert(int totalFilters, int totalRules, long memoryUsage, double falsePositiveEstimate, DateTime recordedAt)
        {
            try
            {
                string query = @"INSERT INTO RuleOptimizationStatsHistory
                        (TotalFilters, TotalRules, MemoryUsageBytes, FalsePositiveEstimate, RecordedAt)
                        VALUES (@TotalFilters, @TotalRules, @MemoryUsageBytes, @FalsePositiveEstimate, @RecordedAt);
                        SELECT SCOPE_IDENTITY();";
                SqlParameter[] parameters = {
            new SqlParameter("@TotalFilters", SqlDbType.Int) { Value = totalFilters },
            new SqlParameter("@TotalRules", SqlDbType.Int) { Value = totalRules },
            new SqlParameter("@MemoryUsageBytes", SqlDbType.BigInt) { Value = memoryUsage },
            new SqlParameter("@FalsePositiveEstimate", SqlDbType.Float) { Value = falsePositiveEstimate }, // Fixed to Float
            new SqlParameter("@RecordedAt", SqlDbType.DateTime) { Value = recordedAt }
        };
                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error inserting RuleOptimizationStatsHistory: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing rule optimization statistics history record in the database
        /// </summary>
        /// <param name="id">The unique identifier of the record to update</param>
        /// <param name="totalFilters">The updated total number of active filters</param>
        /// <param name="totalRules">The updated total number of active detection rules</param>
        /// <param name="memoryUsage">The updated memory usage in bytes</param>
        /// <param name="falsePositiveEstimate">The updated false positive rate estimate</param>
        /// <param name="recordedAt">The updated recording timestamp</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int id, int totalFilters, int totalRules, long memoryUsage, double falsePositiveEstimate, DateTime recordedAt)
        {
            try
            {
                string queryStr = @"
                    UPDATE RuleOptimizationStatsHistory
                    SET TotalFilters = @TotalFilters,
                        TotalRules = @TotalRules,
                        MemoryUsageBytes = @MemoryUsageBytes,
                        FalsePositiveEstimate =@falsePositiveEstimate,
                        RecordedAt = @RecordedAt
                    WHERE Id = @Id";

                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id },
                    new SqlParameter("@TotalFilters", SqlDbType.Int) { Value = totalFilters },
                    new SqlParameter("@TotalRules", SqlDbType.Int) { Value = totalRules },
                    new SqlParameter("@MemoryUsageBytes", SqlDbType.BigInt) { Value = memoryUsage },
                    new SqlParameter("@FalsePositiveEstimate", SqlDbType.Float) { Value = falsePositiveEstimate },
                    new SqlParameter("@RecordedAt", SqlDbType.DateTime) { Value = recordedAt }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating RuleOptimizationStatsHistory: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a rule optimization statistics history record from the database
        /// </summary>
        /// <param name="id">The unique identifier of the record to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int id)
        {
            try
            {
                string query = "DELETE FROM RuleOptimizationStatsHistory WHERE Id = @Id";
                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting RuleOptimizationStatsHistory: " + ex.Message);
                return false;
            }
        }
    }
}