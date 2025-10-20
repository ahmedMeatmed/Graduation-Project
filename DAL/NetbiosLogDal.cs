using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling NetBIOS log-related operations
    /// </summary>
    internal class NetbiosLogDal
    {
        /// <summary>
        /// Retrieves all NetBIOS logs from the database
        /// </summary>
        /// <returns>A NetbiosLogCollection containing all NetBIOS logs</returns>
        public static NetbiosLogCollection GetAll()
        {
            NetbiosLogCollection list = new NetbiosLogCollection();
            try
            {
                string query = "SELECT * FROM NetbiosLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    NetbiosLog log = new NetbiosLog(
                        (int)row["NetbiosLogID"],
                        (int)row["LogID"],
                        row["QueryName"].ToString(),
                        row["QueryType"].ToString(),
                        row["Response"].ToString(),
                        row["ResponderIP"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching NetBIOS logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific NetBIOS log by its unique identifier
        /// </summary>
        /// <param name="id">The NetbiosLogID of the NetBIOS log to retrieve</param>
        /// <returns>A NetbiosLog object if found, otherwise null</returns>
        public static NetbiosLog GetById(int id)
        {
            NetbiosLog log = null;
            try
            {
                string query = "SELECT * FROM NetbiosLogs WHERE NetbiosLogID = @NetbiosLogID";
                SqlParameter[] parameters = { new SqlParameter("@NetbiosLogID", SqlDbType.Int) { Value = id } };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new NetbiosLog(
                        (int)row["NetbiosLogID"],
                        (int)row["LogID"],
                        row["QueryName"].ToString(),
                        row["QueryType"].ToString(),
                        row["Response"].ToString(),
                        row["ResponderIP"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching NetBIOS log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new NetBIOS log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="queryName">The NetBIOS name being queried</param>
        /// <param name="queryType">The type of NetBIOS query (e.g., Name Query, Session Request)</param>
        /// <param name="response">The response received from the NetBIOS service</param>
        /// <param name="responderIP">The IP address of the system responding to the NetBIOS query</param>
        /// <param name="sourceIP">The source IP address of the NetBIOS client</param>
        /// <param name="destinationIP">The destination IP address of the NetBIOS server</param>
        /// <param name="timestamp">The timestamp when the NetBIOS transaction occurred</param>
        /// <param name="sessionID">The NetBIOS session identifier</param>
        /// <param name="status">The transaction status</param>
        /// <returns>The newly created NetbiosLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string queryName, string queryType, string response, string responderIP,
                                 string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status)
        {
            try
            {
                string query = @"INSERT INTO NetbiosLogs
                                 (LogID, QueryName, QueryType, Response, ResponderIP, SourceIP, DestinationIP, Timestamp, SessionID, Status)
                                 VALUES
                                 (@LogID, @QueryName, @QueryType, @Response, @ResponderIP, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@QueryName", SqlDbType.NVarChar, 255) { Value = queryName },
                    new SqlParameter("@QueryType", SqlDbType.NVarChar, 50) { Value = queryType },
                    new SqlParameter("@Response", SqlDbType.NVarChar, 255) { Value = response },
                    new SqlParameter("@ResponderIP", SqlDbType.NVarChar, 50) { Value = responderIP },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting NetBIOS log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing NetBIOS log in the database
        /// </summary>
        /// <param name="netbiosLogId">The unique identifier of the NetBIOS log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="queryName">The updated NetBIOS query name</param>
        /// <param name="queryType">The updated NetBIOS query type</param>
        /// <param name="response">The updated response</param>
        /// <param name="responderIP">The updated responder IP address</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated transaction status</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int netbiosLogId, int logId, string queryName, string queryType, string response, string responderIP,
                                  string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status)
        {
            try
            {
                string query = @"UPDATE NetbiosLogs
                                 SET LogID = @LogID,
                                     QueryName = @QueryName,
                                     QueryType = @QueryType,
                                     Response = @Response,
                                     ResponderIP = @ResponderIP,
                                     SourceIP = @SourceIP,
                                     DestinationIP = @DestinationIP,
                                     Timestamp = @Timestamp,
                                     SessionID = @SessionID,
                                     Status = @Status
                                 WHERE NetbiosLogID = @NetbiosLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@NetbiosLogID", SqlDbType.Int) { Value = netbiosLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@QueryName", SqlDbType.NVarChar, 255) { Value = queryName },
                    new SqlParameter("@QueryType", SqlDbType.NVarChar, 50) { Value = queryType },
                    new SqlParameter("@Response", SqlDbType.NVarChar, 255) { Value = response },
                    new SqlParameter("@ResponderIP", SqlDbType.NVarChar, 50) { Value = responderIP },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating NetBIOS log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a NetBIOS log from the database
        /// </summary>
        /// <param name="netbiosLogId">The unique identifier of the NetBIOS log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int netbiosLogId)
        {
            try
            {
                string query = "DELETE FROM NetbiosLogs WHERE NetbiosLogID = @NetbiosLogID";
                SqlParameter[] parameters = { new SqlParameter("@NetbiosLogID", SqlDbType.Int) { Value = netbiosLogId } };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting NetBIOS log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a NetBIOS log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>A NetbiosLog object if found, otherwise null</returns>
        public static NetbiosLog GetByLogId(int logId)
        {
            NetbiosLog log = null;
            try
            {
                string query = "SELECT * FROM NetbiosLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", SqlDbType.Int) { Value = logId } };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new NetbiosLog(
                        (int)row["NetbiosLogID"],
                        (int)row["LogID"],
                        row["QueryName"].ToString(),
                        row["QueryType"].ToString(),
                        row["Response"].ToString(),
                        row["ResponderIP"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching NetBIOS log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}