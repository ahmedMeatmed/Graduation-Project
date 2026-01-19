using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling rule statistics history-related operations
    /// </summary>
    internal class RuleStatsHistoryDal
    {
        /// <summary>
        /// Retrieves all rule statistics history records from the database
        /// </summary>
        /// <returns>A RuleStatsHistoryCollection containing all historical rule statistics</returns>
        public static RuleStatsHistoryCollection GetAll()
        {
            RuleStatsHistoryCollection list = new RuleStatsHistoryCollection();
            try
            {
                string query = "SELECT * FROM RuleStatsHistory";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    RuleStatsHistory item = new RuleStatsHistory(
                        (int)row["Id"],
                        (int)row["SignatureId"],
                        row["AttackName"].ToString(),
                        (long)row["TotalChecks"],
                        (long)row["Matches"],
                        (long)row["TotalProcessingTimeMs"],
                        Convert.ToDouble(row["MatchRate"]),
                        Convert.ToDouble(row["AvgProcessingTimeMs"]),
                        Convert.ToDouble(row["EfficiencyScore"]),
                        row["LastChecked"] == DBNull.Value ? null : (DateTime?)row["LastChecked"],
                        row["LastMatch"] == DBNull.Value ? null : (DateTime?)row["LastMatch"],
                        (DateTime)row["RecordedAt"]
                    );
                    list.Add(item);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RuleStatsHistory: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific rule statistics history record by its unique identifier
        /// </summary>
        /// <param name="id">The Id of the rule statistics history record to retrieve</param>
        /// <returns>A RuleStatsHistory object if found, otherwise null</returns>
        public static RuleStatsHistory GetById(int id)
        {
            RuleStatsHistory item = null;
            try
            {
                string query = "SELECT * FROM RuleStatsHistory WHERE Id = @Id";
                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    item = new RuleStatsHistory(
                        (int)row["Id"],
                        (int)row["SignatureId"],
                        row["AttackName"].ToString(),
                        (long)row["TotalChecks"],
                        (long)row["Matches"],
                        (long)row["TotalProcessingTimeMs"],
                        Convert.ToDouble(row["MatchRate"]),
                        Convert.ToDouble(row["AvgProcessingTimeMs"]),
                        Convert.ToDouble(row["EfficiencyScore"]),
                        row["LastChecked"] == DBNull.Value ? null : (DateTime?)row["LastChecked"],
                        row["LastMatch"] == DBNull.Value ? null : (DateTime?)row["LastMatch"],
                        (DateTime)row["RecordedAt"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RuleStatsHistory by ID: " + ex.Message);
            }
            return item;
        }

        /// <summary>
        /// Inserts a new rule statistics history record into the database
        /// </summary>
        /// <param name="signatureId">The unique identifier of the detection signature</param>
        /// <param name="attackName">The name of the attack or threat this rule detects</param>
        /// <param name="totalChecks">The total number of times this rule has been checked against traffic</param>
        /// <param name="matches">The total number of times this rule has matched (true positives)</param>
        /// <param name="totalProcessingTimeMs">The cumulative processing time spent on this rule in milliseconds</param>
        /// <param name="matchRate">The match rate as a percentage (matches/totalChecks)</param>
        /// <param name="avgProcessingTimeMs">The average processing time per check in milliseconds</param>
        /// <param name="efficiencyScore">The calculated efficiency score balancing detection rate and performance</param>
        /// <param name="lastChecked">The timestamp when this rule was last checked against traffic</param>
        /// <param name="lastMatch">The timestamp when this rule last matched (detected an attack)</param>
        /// <param name="recordedAt">The timestamp when these statistics were recorded</param>
        /// <returns>The newly created record Id if successful, otherwise -1</returns>
        public static int Insert(int signatureId, string attackName, long totalChecks, long matches,
            long totalProcessingTimeMs, double matchRate, double avgProcessingTimeMs,
            double efficiencyScore, DateTime? lastChecked, DateTime? lastMatch, DateTime recordedAt)
        {
            try
            {
                string query = @"INSERT INTO RuleStatsHistory
                                 (SignatureId, AttackName, TotalChecks, Matches, TotalProcessingTimeMs, MatchRate, AvgProcessingTimeMs, EfficiencyScore, LastChecked, LastMatch, RecordedAt)
                                 VALUES (@SignatureId, @AttackName, @TotalChecks, @Matches, @TotalProcessingTimeMs, @MatchRate, @AvgProcessingTimeMs, @EfficiencyScore, @LastChecked, @LastMatch, @RecordedAt);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@SignatureId", SqlDbType.Int) { Value = signatureId },
                    new SqlParameter("@AttackName", SqlDbType.NVarChar, 255) { Value = attackName },
                    new SqlParameter("@TotalChecks", SqlDbType.BigInt) { Value = totalChecks },
                    new SqlParameter("@Matches", SqlDbType.BigInt) { Value = matches },
                    new SqlParameter("@TotalProcessingTimeMs", SqlDbType.BigInt) { Value = totalProcessingTimeMs },
                    new SqlParameter("@MatchRate", SqlDbType.Float) { Value = matchRate },
                    new SqlParameter("@AvgProcessingTimeMs", SqlDbType.Float) { Value = avgProcessingTimeMs },
                    new SqlParameter("@EfficiencyScore", SqlDbType.Float) { Value = efficiencyScore },
                    new SqlParameter("@LastChecked", SqlDbType.DateTime) { Value = (object)lastChecked ?? DBNull.Value },
                    new SqlParameter("@LastMatch", SqlDbType.DateTime) { Value = (object)lastMatch ?? DBNull.Value },
                    new SqlParameter("@RecordedAt", SqlDbType.DateTime) { Value = recordedAt }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting RuleStatsHistory: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing rule statistics history record in the database
        /// </summary>
        /// <param name="id">The unique identifier of the record to update</param>
        /// <param name="signatureId">The updated signature identifier</param>
        /// <param name="attackName">The updated attack name</param>
        /// <param name="totalChecks">The updated total checks count</param>
        /// <param name="matches">The updated matches count</param>
        /// <param name="totalProcessingTimeMs">The updated total processing time</param>
        /// <param name="matchRate">The updated match rate</param>
        /// <param name="avgProcessingTimeMs">The updated average processing time</param>
        /// <param name="efficiencyScore">The updated efficiency score</param>
        /// <param name="lastChecked">The updated last checked timestamp</param>
        /// <param name="lastMatch">The updated last match timestamp</param>
        /// <param name="recordedAt">The updated recording timestamp</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int id, int signatureId, string attackName, long totalChecks, long matches,
            long totalProcessingTimeMs, double matchRate, double avgProcessingTimeMs,
            double efficiencyScore, DateTime? lastChecked, DateTime? lastMatch, DateTime recordedAt)
        {
            try
            {
                string queryStr = @"
                    UPDATE RuleStatsHistory
                    SET SignatureId = @SignatureId,
                        AttackName = @AttackName,
                        TotalChecks = @TotalChecks,
                        Matches = @Matches,
                        TotalProcessingTimeMs = @TotalProcessingTimeMs,
                        MatchRate = @MatchRate,
                        AvgProcessingTimeMs = @AvgProcessingTimeMs,
                        EfficiencyScore = @EfficiencyScore,
                        LastChecked = @LastChecked,
                        LastMatch = @LastMatch,
                        RecordedAt = @RecordedAt
                    WHERE Id = @Id";

                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id },
                    new SqlParameter("@SignatureId", SqlDbType.Int) { Value = signatureId },
                    new SqlParameter("@AttackName", SqlDbType.NVarChar, 255) { Value = attackName },
                    new SqlParameter("@TotalChecks", SqlDbType.BigInt) { Value = totalChecks },
                    new SqlParameter("@Matches", SqlDbType.BigInt) { Value = matches },
                    new SqlParameter("@TotalProcessingTimeMs", SqlDbType.BigInt) { Value = totalProcessingTimeMs },
                    new SqlParameter("@MatchRate", SqlDbType.Float) { Value = matchRate },
                    new SqlParameter("@AvgProcessingTimeMs", SqlDbType.Float) { Value = avgProcessingTimeMs },
                    new SqlParameter("@EfficiencyScore", SqlDbType.Float) { Value = efficiencyScore },
                    new SqlParameter("@LastChecked", SqlDbType.DateTime) { Value = (object)lastChecked ?? DBNull.Value },
                    new SqlParameter("@LastMatch", SqlDbType.DateTime) { Value = (object)lastMatch ?? DBNull.Value },
                    new SqlParameter("@RecordedAt", SqlDbType.DateTime) { Value = recordedAt }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating RuleStatsHistory: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a rule statistics history record from the database
        /// </summary>
        /// <param name="id">The unique identifier of the record to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int id)
        {
            try
            {
                string query = "DELETE FROM RuleStatsHistory WHERE Id = @Id";
                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting RuleStatsHistory: " + ex.Message);
                return false;
            }
        }
    }
}