using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for Telnet log operations in the database.
    /// </summary>
    internal class TelnetLogDal
    {
        /// <summary>
        /// Retrieves all Telnet logs from the database.
        /// </summary>
        /// <returns>A collection of TelnetLog objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static TelnetLogCollection GetAll()
        {
            TelnetLogCollection list = new TelnetLogCollection();
            try
            {
                string query = "SELECT * FROM TelnetLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    TelnetLog log = new TelnetLog(
                        (int)row["TelnetLogID"],
                        (int)row["LogID"],
                        row["ClientIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["Command"].ToString(),
                        Convert.ToInt32(row["AuthAttempts"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Telnet logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific Telnet log by its unique identifier.
        /// </summary>
        /// <param name="id">The TelnetLogID of the record to retrieve.</param>
        /// <returns>A TelnetLog object if found; otherwise, null.</returns>
        public static TelnetLog GetById(int id)
        {
            TelnetLog log = null;
            try
            {
                string query = "SELECT * FROM TelnetLogs WHERE TelnetLogID = @TelnetLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@TelnetLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new TelnetLog(
                        (int)row["TelnetLogID"],
                        (int)row["LogID"],
                        row["ClientIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["Command"].ToString(),
                        Convert.ToInt32(row["AuthAttempts"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Telnet log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new Telnet log record into the database.
        /// </summary>
        /// <param name="logId">The associated LogID.</param>
        /// <param name="clientIP">The client IP address initiating the Telnet connection.</param>
        /// <param name="serverIP">The server IP address receiving the Telnet connection.</param>
        /// <param name="command">The Telnet command executed.</param>
        /// <param name="authAttempts">The number of authentication attempts made.</param>
        /// <returns>The newly created TelnetLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string clientIP, string serverIP, string command, int authAttempts)
        {
            try
            {
                string query = @"INSERT INTO TelnetLogs (LogID, ClientIP, ServerIP, Command, AuthAttempts)
                                 VALUES (@LogID, @ClientIP, @ServerIP, @Command, @AuthAttempts);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@ClientIP", SqlDbType.NVarChar, 50) { Value = clientIP },
                    new SqlParameter("@ServerIP", SqlDbType.NVarChar, 50) { Value = serverIP },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 255) { Value = command },
                    new SqlParameter("@AuthAttempts", SqlDbType.Int) { Value = authAttempts }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting Telnet log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes a specific Telnet log record from the database.
        /// </summary>
        /// <param name="telnetLogId">The TelnetLogID of the record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int telnetLogId)
        {
            try
            {
                string query = "DELETE FROM TelnetLogs WHERE TelnetLogID = @TelnetLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@TelnetLogID", SqlDbType.Int) { Value = telnetLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting Telnet log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing Telnet log record in the database.
        /// </summary>
        /// <param name="telnetLogId">The TelnetLogID of the record to update.</param>
        /// <param name="logId">The new LogID value.</param>
        /// <param name="clientIP">The new client IP address.</param>
        /// <param name="serverIP">The new server IP address.</param>
        /// <param name="command">The new Telnet command.</param>
        /// <param name="authAttempts">The new number of authentication attempts.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int telnetLogId, int logId, string clientIP, string serverIP, string command, int authAttempts)
        {
            try
            {
                string queryStr = @"
            UPDATE TelnetLogs
            SET LogID = @LogID,
                ClientIP = @ClientIP,
                ServerIP = @ServerIP,
                Command = @Command,
                AuthAttempts = @AuthAttempts
            WHERE TelnetLogID = @TelnetLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@TelnetLogID", SqlDbType.Int) { Value = telnetLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@ClientIP", SqlDbType.NVarChar, 50) { Value = clientIP },
            new SqlParameter("@ServerIP", SqlDbType.NVarChar, 50) { Value = serverIP },
            new SqlParameter("@Command", SqlDbType.NVarChar, 255) { Value = command },
            new SqlParameter("@AuthAttempts", SqlDbType.Int) { Value = authAttempts }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating Telnet log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a Telnet log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for.</param>
        /// <returns>A TelnetLog object if found; otherwise, null.</returns>
        public static TelnetLog GetByLogId(int logId)
        {
            TelnetLog log = null;
            try
            {
                string query = "SELECT * FROM TelnetLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new TelnetLog(
                        (int)row["TelnetLogID"],
                        (int)row["LogID"],
                        row["ClientIP"].ToString(),
                        row["ServerIP"].ToString(),
                        row["Command"].ToString(),
                        (int)row["AuthAttempts"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching Telnet log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}