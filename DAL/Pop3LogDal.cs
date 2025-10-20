using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling POP3 (Post Office Protocol version 3) log-related operations
    /// </summary>
    internal class Pop3LogDal
    {
        /// <summary>
        /// Retrieves all POP3 logs from the database
        /// </summary>
        /// <returns>A Pop3LogCollection containing all POP3 logs</returns>
        public static Pop3LogCollection GetAll()
        {
            Pop3LogCollection list = new Pop3LogCollection();
            try
            {
                string query = "SELECT * FROM Pop3Logs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    Pop3Log log = new Pop3Log(
                        (int)row["Pop3LogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Username"].ToString(),
                        row["ResponseCode"].ToString(),
                        Convert.ToInt32(row["MessageSize"]),
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
                Console.WriteLine("Error fetching POP3 logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific POP3 log by its unique identifier
        /// </summary>
        /// <param name="id">The Pop3LogID of the POP3 log to retrieve</param>
        /// <returns>A Pop3Log object if found, otherwise null</returns>
        public static Pop3Log GetById(int id)
        {
            Pop3Log log = null;
            try
            {
                string query = "SELECT * FROM Pop3Logs WHERE Pop3LogID = @Pop3LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@Pop3LogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new Pop3Log(
                        (int)row["Pop3LogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Username"].ToString(),
                        row["ResponseCode"].ToString(),
                        Convert.ToInt32(row["MessageSize"]),
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
                Console.WriteLine("Error fetching POP3 log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new POP3 log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="command">The POP3 command (e.g., USER, PASS, LIST, RETR, DELE, QUIT)</param>
        /// <param name="username">The username used for authentication</param>
        /// <param name="responseCode">The server response code (e.g., +OK, -ERR)</param>
        /// <param name="messageSize">The size of the email message in bytes</param>
        /// <param name="sourceIP">The source IP address of the POP3 client</param>
        /// <param name="destinationIP">The destination IP address of the POP3 server</param>
        /// <param name="timestamp">The timestamp when the POP3 transaction occurred</param>
        /// <param name="sessionID">The POP3 session identifier</param>
        /// <param name="status">The transaction status</param>
        /// <param name="attemptCount">The number of authentication or command attempts</param>
        /// <returns>The newly created Pop3LogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string command, string username, string responseCode, int messageSize,
                                 string sourceIP, string destinationIP, DateTime timestamp, string sessionID,
                                 string status, int attemptCount)
        {
            try
            {
                string query = @"INSERT INTO Pop3Logs (LogID, Command, Username, ResponseCode, MessageSize, SourceIP, DestinationIP, Timestamp, SessionID, Status, AttemptCount)
                                 VALUES (@LogID, @Command, @Username, @ResponseCode, @MessageSize, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status, @AttemptCount);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 20) { Value = command },
                    new SqlParameter("@Username", SqlDbType.NVarChar, 255) { Value = username },
                    new SqlParameter("@ResponseCode", SqlDbType.NVarChar, 50) { Value = responseCode },
                    new SqlParameter("@MessageSize", SqlDbType.Int) { Value = messageSize },
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
                Console.WriteLine("Error inserting POP3 log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing POP3 log in the database
        /// </summary>
        /// <param name="pop3LogId">The unique identifier of the POP3 log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="command">The updated POP3 command</param>
        /// <param name="username">The updated username</param>
        /// <param name="responseCode">The updated server response code</param>
        /// <param name="messageSize">The updated message size</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated transaction status</param>
        /// <param name="attemptCount">The updated attempt count</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int pop3LogId, int logId, string command, string username, string responseCode, int messageSize,
                                  string sourceIP, string destinationIP, DateTime timestamp, string sessionID,
                                  string status, int attemptCount)
        {
            try
            {
                string query = @"UPDATE Pop3Logs
                                 SET LogID=@LogID, Command=@Command, Username=@Username, ResponseCode=@ResponseCode,
                                     MessageSize=@MessageSize, SourceIP=@SourceIP, DestinationIP=@DestinationIP,
                                     Timestamp=@Timestamp, SessionID=@SessionID, Status=@Status, AttemptCount=@AttemptCount
                                 WHERE Pop3LogID=@Pop3LogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@Pop3LogID", SqlDbType.Int) { Value = pop3LogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 20) { Value = command },
                    new SqlParameter("@Username", SqlDbType.NVarChar, 255) { Value = username },
                    new SqlParameter("@ResponseCode", SqlDbType.NVarChar, 50) { Value = responseCode },
                    new SqlParameter("@MessageSize", SqlDbType.Int) { Value = messageSize },
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
                Console.WriteLine("Error updating POP3 log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a POP3 log from the database
        /// </summary>
        /// <param name="pop3LogId">The unique identifier of the POP3 log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int pop3LogId)
        {
            try
            {
                string query = "DELETE FROM Pop3Logs WHERE Pop3LogID=@Pop3LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@Pop3LogID", SqlDbType.Int) { Value = pop3LogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting POP3 log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a POP3 log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>A Pop3Log object if found, otherwise null</returns>
        public static Pop3Log GetByLogId(int logId)
        {
            Pop3Log log = null;
            try
            {
                string query = "SELECT * FROM Pop3Logs WHERE LogID=@LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new Pop3Log(
                        (int)row["Pop3LogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Username"].ToString(),
                        row["ResponseCode"].ToString(),
                        Convert.ToInt32(row["MessageSize"]),
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
                Console.WriteLine("Error fetching POP3 log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}