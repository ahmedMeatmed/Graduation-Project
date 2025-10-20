using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling protocol statistics history-related operations
    /// </summary>
    internal class ProtocolStatsHistoryDal
    {
        /// <summary>
        /// Retrieves all protocol statistics history records from the database
        /// </summary>
        /// <returns>A ProtocolStatsHistoryCollection containing all historical protocol statistics</returns>
        public static ProtocolStatsHistoryCollection GetAll()
        {
            ProtocolStatsHistoryCollection list = new ProtocolStatsHistoryCollection();
            try
            {
                string query = "SELECT * FROM ProtocolStatsHistory";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    ProtocolStatsHistory item = new ProtocolStatsHistory(
                        (int)row["Id"],
                        row["Protocol"].ToString(),
                        (long)row["PacketCount"],
                        row["TotalPackets"] == DBNull.Value ? null : (long?)row["TotalPackets"],
                        Convert.ToDouble(row["Percentage"]),
                        (DateTime)row["RecordedAt"]
                    );
                    list.Add(item);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching ProtocolStatsHistory: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific protocol statistics history record by its unique identifier
        /// </summary>
        /// <param name="id">The Id of the protocol statistics history record to retrieve</param>
        /// <returns>A ProtocolStatsHistory object if found, otherwise null</returns>
        public static ProtocolStatsHistory GetById(int id)
        {
            ProtocolStatsHistory item = null;
            try
            {
                string query = "SELECT * FROM ProtocolStatsHistory WHERE Id = @Id";
                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    item = new ProtocolStatsHistory(
                        (int)row["Id"],
                        row["Protocol"].ToString(),
                        (long)row["PacketCount"],
                        row["TotalPackets"] == DBNull.Value ? null : (long?)row["TotalPackets"],
                        Convert.ToDouble(row["Percentage"]),
                        (DateTime)row["RecordedAt"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching ProtocolStatsHistory by ID: " + ex.Message);
            }
            return item;
        }

        /// <summary>
        /// Inserts a new protocol statistics history record into the database
        /// </summary>
        /// <param name="protocol">The network protocol name (e.g., TCP, UDP, HTTP, DNS, FTP)</param>
        /// <param name="packetCount">The number of packets for this protocol in the recorded period</param>
        /// <param name="totalPackets">The total number of packets across all protocols in the recorded period (optional)</param>
        /// <param name="percentage">The percentage of total traffic represented by this protocol</param>
        /// <param name="recordedAt">The timestamp when these statistics were recorded</param>
        /// <returns>The newly created record Id if successful, otherwise -1</returns>
        public static int Insert(string protocol, long packetCount, long? totalPackets, double percentage, DateTime recordedAt)
        {
            try
            {
                string query = @"INSERT INTO ProtocolStatsHistory
                                 (Protocol, PacketCount, TotalPackets, Percentage, RecordedAt)
                                 VALUES (@Protocol, @PacketCount, @TotalPackets, @Percentage, @RecordedAt);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@Protocol", SqlDbType.NVarChar, 50) { Value = protocol },
                    new SqlParameter("@PacketCount", SqlDbType.BigInt) { Value = packetCount },
                    new SqlParameter("@TotalPackets", SqlDbType.BigInt) { Value = (object)totalPackets ?? DBNull.Value },
                    new SqlParameter("@Percentage", SqlDbType.Float) { Value = percentage },
                    new SqlParameter("@RecordedAt", SqlDbType.DateTime) { Value = recordedAt }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting ProtocolStatsHistory: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing protocol statistics history record in the database
        /// </summary>
        /// <param name="id">The unique identifier of the record to update</param>
        /// <param name="protocol">The updated network protocol name</param>
        /// <param name="packetCount">The updated packet count for this protocol</param>
        /// <param name="totalPackets">The updated total packet count across all protocols</param>
        /// <param name="percentage">The updated percentage of total traffic</param>
        /// <param name="recordedAt">The updated recording timestamp</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int id, string protocol, long packetCount, long? totalPackets, double percentage, DateTime recordedAt)
        {
            try
            {
                string queryStr = @"
                    UPDATE ProtocolStatsHistory
                    SET Protocol = @Protocol,
                        PacketCount = @PacketCount,
                        TotalPackets = @TotalPackets,
                        Percentage = @Percentage,
                        RecordedAt = @RecordedAt
                    WHERE Id = @Id";

                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id },
                    new SqlParameter("@Protocol", SqlDbType.NVarChar, 50) { Value = protocol },
                    new SqlParameter("@PacketCount", SqlDbType.BigInt) { Value = packetCount },
                    new SqlParameter("@TotalPackets", SqlDbType.BigInt) { Value = (object)totalPackets ?? DBNull.Value },
                    new SqlParameter("@Percentage", SqlDbType.Float) { Value = percentage },
                    new SqlParameter("@RecordedAt", SqlDbType.DateTime) { Value = recordedAt }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating ProtocolStatsHistory: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a protocol statistics history record from the database
        /// </summary>
        /// <param name="id">The unique identifier of the record to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int id)
        {
            try
            {
                string query = "DELETE FROM ProtocolStatsHistory WHERE Id = @Id";
                SqlParameter[] parameters = {
                    new SqlParameter("@Id", SqlDbType.Int) { Value = id }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting ProtocolStatsHistory: " + ex.Message);
                return false;
            }
        }
    }
}