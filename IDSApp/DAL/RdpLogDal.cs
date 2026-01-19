using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling RDP (Remote Desktop Protocol) log-related operations
    /// </summary>
    internal class RdpLogDal
    {
        /// <summary>
        /// Retrieves all RDP logs from the database
        /// </summary>
        /// <returns>An RdpLogCollection containing all RDP logs</returns>
        public static RdpLogCollection GetAll()
        {
            RdpLogCollection list = new RdpLogCollection();
            try
            {
                string query = "SELECT * FROM RdpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    RdpLog log = new RdpLog(
                        (int)row["RdpLogID"],
                        (int)row["LogID"],
                        row["ClientIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["SessionID"].ToString(),
                        Convert.ToInt32(row["AuthAttempts"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RDP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific RDP log by its unique identifier
        /// </summary>
        /// <param name="id">The RdpLogID of the RDP log to retrieve</param>
        /// <returns>An RdpLog object if found, otherwise null</returns>
        public static RdpLog GetById(int id)
        {
            RdpLog log = null;
            try
            {
                string query = "SELECT * FROM RdpLogs WHERE RdpLogID = @RdpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@RdpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new RdpLog(
                        (int)row["RdpLogID"],
                        (int)row["LogID"],
                        row["ClientIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["SessionID"].ToString(),
                        Convert.ToInt32(row["AuthAttempts"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RDP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new RDP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="clientIP">The IP address of the RDP client</param>
        /// <param name="serverIP">The IP address of the RDP server</param>
        /// <param name="sessionID">The RDP session identifier</param>
        /// <param name="authAttempts">The number of authentication attempts made</param>
        /// <returns>The newly created RdpLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string clientIP, string serverIP, string sessionID, int authAttempts)
        {
            try
            {
                string query = @"INSERT INTO RdpLogs (LogID, ClientIP, ServerIP, SessionID, AuthAttempts)
                                 VALUES (@LogID, @ClientIP, @ServerIP, @SessionID, @AuthAttempts);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@ClientIP", SqlDbType.NVarChar, 50) { Value = clientIP },
                    new SqlParameter("@ServerIP", SqlDbType.NVarChar, 50) { Value = serverIP },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@AuthAttempts", SqlDbType.Int) { Value = authAttempts }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting RDP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes an RDP log from the database
        /// </summary>
        /// <param name="rdpLogId">The unique identifier of the RDP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int rdpLogId)
        {
            try
            {
                string query = "DELETE FROM RdpLogs WHERE RdpLogID = @RdpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@RdpLogID", SqlDbType.Int) { Value = rdpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting RDP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing RDP log in the database
        /// </summary>
        /// <param name="rdpLogId">The unique identifier of the RDP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="clientIP">The updated client IP address</param>
        /// <param name="serverIP">The updated server IP address</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="authAttempts">The updated authentication attempt count</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int rdpLogId, int logId, string clientIP, string serverIP, string sessionID, int authAttempts)
        {
            try
            {
                string queryStr = @"
            UPDATE RdpLogs
            SET LogID = @LogID,
                ClientIP = @ClientIP,
                ServerIP = @ServerIP,
                SessionID = @SessionID,
                AuthAttempts = @AuthAttempts
            WHERE RdpLogID = @RdpLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@RdpLogID", SqlDbType.Int) { Value = rdpLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@ClientIP", SqlDbType.NVarChar, 50) { Value = clientIP },
            new SqlParameter("@ServerIP", SqlDbType.NVarChar, 50) { Value = serverIP },
            new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
            new SqlParameter("@AuthAttempts", SqlDbType.Int) { Value = authAttempts }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating RDP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an RDP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An RdpLog object if found, otherwise null</returns>
        public static RdpLog GetByLogId(int logId)
        {
            RdpLog log = null;
            try
            {
                string query = "SELECT * FROM RdpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new RdpLog(
                        (int)row["RdpLogID"],
                        (int)row["LogID"],
                        row["ClientIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["SessionID"].ToString(),
                        (int)row["AuthAttempts"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching RDP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}