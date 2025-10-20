using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling IMAP log-related operations
    /// </summary>
    internal class ImapLogDal
    {
        /// <summary>
        /// Retrieves all IMAP logs from the database
        /// </summary>
        /// <returns>An ImapLogCollection containing all IMAP logs</returns>
        public static ImapLogCollection GetAll()
        {
            ImapLogCollection list = new ImapLogCollection();
            try
            {
                string query = "SELECT * FROM ImapLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    ImapLog log = new ImapLog(
                        (int)row["ImapLogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Folder"].ToString(),
                        row["ResponseCode"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToInt32(row["AttemptCount"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching IMAP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific IMAP log by its unique identifier
        /// </summary>
        /// <param name="id">The ImapLogID of the IMAP log to retrieve</param>
        /// <returns>An ImapLog object if found, otherwise null</returns>
        public static ImapLog GetById(int id)
        {
            ImapLog log = null;
            try
            {
                string query = "SELECT * FROM ImapLogs WHERE ImapLogID = @ImapLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@ImapLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new ImapLog(
                        (int)row["ImapLogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Folder"].ToString(),
                        row["ResponseCode"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToInt32(row["AttemptCount"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching IMAP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new IMAP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="command">The IMAP command (e.g., LOGIN, SELECT, FETCH, STORE, SEARCH)</param>
        /// <param name="folder">The mail folder being accessed</param>
        /// <param name="responseCode">The server response code (e.g., OK, NO, BAD)</param>
        /// <param name="sourceIP">The source IP address of the IMAP client</param>
        /// <param name="destinationIP">The destination IP address of the IMAP server</param>
        /// <param name="timestamp">The timestamp when the IMAP transaction occurred</param>
        /// <param name="sessionID">The IMAP session identifier</param>
        /// <param name="status">The transaction status</param>
        /// <param name="attemptCount">The number of authentication or command attempts</param>
        /// <returns>The newly created ImapLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string command, string folder, string responseCode,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, int attemptCount)
        {
            try
            {
                string query = @"INSERT INTO ImapLogs (LogID, Command, Folder, ResponseCode, SourceIP, DestinationIP, Timestamp, SessionID, Status, AttemptCount)
                                 VALUES (@LogID, @Command, @Folder, @ResponseCode, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status, @AttemptCount);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 20) { Value = command },
                    new SqlParameter("@Folder", SqlDbType.NVarChar, 255) { Value = folder },
                    new SqlParameter("@ResponseCode", SqlDbType.NVarChar, 50) { Value = responseCode },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@AttemptCount", SqlDbType.Int) { Value = attemptCount }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting IMAP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing IMAP log in the database
        /// </summary>
        /// <param name="imapLogId">The unique identifier of the IMAP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="command">The updated IMAP command</param>
        /// <param name="folder">The updated mail folder</param>
        /// <param name="responseCode">The updated server response code</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated transaction status</param>
        /// <param name="attemptCount">The updated attempt count</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int imapLogId, int logId, string command, string folder, string responseCode,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, int attemptCount)
        {
            try
            {
                string query = @"UPDATE ImapLogs
                                 SET LogID=@LogID, Command=@Command, Folder=@Folder, ResponseCode=@ResponseCode,
                                     SourceIP=@SourceIP, DestinationIP=@DestinationIP, Timestamp=@Timestamp,
                                     SessionID=@SessionID, Status=@Status, AttemptCount=@AttemptCount
                                 WHERE ImapLogID=@ImapLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@ImapLogID", SqlDbType.Int) { Value = imapLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 20) { Value = command },
                    new SqlParameter("@Folder", SqlDbType.NVarChar, 255) { Value = folder },
                    new SqlParameter("@ResponseCode", SqlDbType.NVarChar, 50) { Value = responseCode },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@AttemptCount", SqlDbType.Int) { Value = attemptCount }
                };

                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating IMAP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes an IMAP log from the database
        /// </summary>
        /// <param name="imapLogId">The unique identifier of the IMAP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int imapLogId)
        {
            try
            {
                string query = "DELETE FROM ImapLogs WHERE ImapLogID=@ImapLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@ImapLogID", SqlDbType.Int) { Value = imapLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting IMAP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an IMAP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An ImapLog object if found, otherwise null</returns>
        public static ImapLog GetByLogId(int logId)
        {
            ImapLog log = null;
            try
            {
                string query = "SELECT * FROM ImapLogs WHERE LogID=@LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new ImapLog(
                        (int)row["ImapLogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Folder"].ToString(),
                        row["ResponseCode"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToInt32(row["AttemptCount"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching IMAP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}