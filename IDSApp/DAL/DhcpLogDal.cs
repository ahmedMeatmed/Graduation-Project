using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling DHCP log-related operations
    /// </summary>
    internal class DhcpLogDal
    {
        /// <summary>
        /// Retrieves all DHCP logs from the database
        /// </summary>
        /// <returns>A DhcpLogCollection containing all DHCP logs</returns>
        public static DhcpLogCollection GetAll()
        {
            DhcpLogCollection list = new DhcpLogCollection();
            try
            {
                string query = "SELECT * FROM DhcpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    DhcpLog log = new DhcpLog(
                        (int)row["DhcpLogID"],
                        (int)row["LogID"],
                        row["MessageType"].ToString(),
                        row["TransactionID"].ToString(),
                        row["ClientIP"].ToString(),
                        row["OfferedIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToInt32(row["LeaseDuration"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DHCP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific DHCP log by its unique identifier
        /// </summary>
        /// <param name="id">The DhcpLogID of the DHCP log to retrieve</param>
        /// <returns>A DhcpLog object if found, otherwise null</returns>
        public static DhcpLog GetById(int id)
        {
            DhcpLog log = null;
            try
            {
                string query = "SELECT * FROM DhcpLogs WHERE DhcpLogID = @DhcpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@DhcpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new DhcpLog(
                        (int)row["DhcpLogID"],
                        (int)row["LogID"],
                        row["MessageType"].ToString(),
                        row["TransactionID"].ToString(),
                        row["ClientIP"].ToString(),
                        row["OfferedIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToInt32(row["LeaseDuration"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DHCP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new DHCP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="messageType">The DHCP message type (e.g., DISCOVER, OFFER, REQUEST, ACK)</param>
        /// <param name="transactionID">The DHCP transaction identifier</param>
        /// <param name="clientIP">The client IP address</param>
        /// <param name="offeredIP">The IP address offered by the DHCP server</param>
        /// <param name="serverIP">The DHCP server IP address</param>
        /// <param name="sourceIP">The source IP address of the packet</param>
        /// <param name="destinationIP">The destination IP address of the packet</param>
        /// <param name="timestamp">The timestamp when the DHCP transaction occurred</param>
        /// <param name="sessionID">The session identifier</param>
        /// <param name="status">The transaction status</param>
        /// <param name="leaseDuration">The lease duration in seconds</param>
        /// <returns>The newly created DhcpLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string messageType, string transactionID, string clientIP, string offeredIP,
                                 string serverIP, string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, int leaseDuration)
        {
            try
            {
                string query = @"INSERT INTO DhcpLogs 
                                 (LogID, MessageType, TransactionID, ClientIP, OfferedIP, ServerIP, SourceIP, DestinationIP, Timestamp, SessionID, Status, LeaseDuration)
                                 VALUES 
                                 (@LogID, @MessageType, @TransactionID, @ClientIP, @OfferedIP, @ServerIP, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status, @LeaseDuration);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@MessageType", SqlDbType.NVarChar, 50) { Value = messageType },
                    new SqlParameter("@TransactionID", SqlDbType.NVarChar, 50) { Value = transactionID },
                    new SqlParameter("@ClientIP", SqlDbType.NVarChar, 50) { Value = clientIP },
                    new SqlParameter("@OfferedIP", SqlDbType.NVarChar, 50) { Value = offeredIP },
                    new SqlParameter("@ServerIP", SqlDbType.NVarChar, 50) { Value = serverIP },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@LeaseDuration", SqlDbType.Int) { Value = leaseDuration }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting DHCP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing DHCP log in the database
        /// </summary>
        /// <param name="dhcpLogId">The unique identifier of the DHCP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="messageType">The updated DHCP message type</param>
        /// <param name="transactionID">The updated transaction identifier</param>
        /// <param name="clientIP">The updated client IP address</param>
        /// <param name="offeredIP">The updated offered IP address</param>
        /// <param name="serverIP">The updated server IP address</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated transaction status</param>
        /// <param name="leaseDuration">The updated lease duration</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int dhcpLogId, int logId, string messageType, string transactionID, string clientIP, string offeredIP,
                                  string serverIP, string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, int leaseDuration)
        {
            try
            {
                string query = @"UPDATE DhcpLogs
                                 SET LogID = @LogID,
                                     MessageType = @MessageType,
                                     TransactionID = @TransactionID,
                                     ClientIP = @ClientIP,
                                     OfferedIP = @OfferedIP,
                                     ServerIP = @ServerIP,
                                     SourceIP = @SourceIP,
                                     DestinationIP = @DestinationIP,
                                     Timestamp = @Timestamp,
                                     SessionID = @SessionID,
                                     Status = @Status,
                                     LeaseDuration = @LeaseDuration
                                 WHERE DhcpLogID = @DhcpLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@DhcpLogID", SqlDbType.Int) { Value = dhcpLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@MessageType", SqlDbType.NVarChar, 50) { Value = messageType },
                    new SqlParameter("@TransactionID", SqlDbType.NVarChar, 50) { Value = transactionID },
                    new SqlParameter("@ClientIP", SqlDbType.NVarChar, 50) { Value = clientIP },
                    new SqlParameter("@OfferedIP", SqlDbType.NVarChar, 50) { Value = offeredIP },
                    new SqlParameter("@ServerIP", SqlDbType.NVarChar, 50) { Value = serverIP },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@LeaseDuration", SqlDbType.Int) { Value = leaseDuration }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating DHCP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a DHCP log from the database
        /// </summary>
        /// <param name="dhcpLogId">The unique identifier of the DHCP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int dhcpLogId)
        {
            try
            {
                string query = "DELETE FROM DhcpLogs WHERE DhcpLogID = @DhcpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@DhcpLogID", SqlDbType.Int) { Value = dhcpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting DHCP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a DHCP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>A DhcpLog object if found, otherwise null</returns>
        public static DhcpLog GetByLogId(int logId)
        {
            DhcpLog log = null;
            try
            {
                string query = "SELECT * FROM DhcpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new DhcpLog(
                        (int)row["DhcpLogID"],
                        (int)row["LogID"],
                        row["MessageType"].ToString(),
                        row["TransactionID"].ToString(),
                        row["ClientIP"].ToString(),
                        row["OfferedIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToInt32(row["LeaseDuration"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DHCP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}