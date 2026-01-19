using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling database log-related operations
    /// </summary>
    internal class DbLogDal
    {
        /// <summary>
        /// Retrieves all database logs from the database
        /// </summary>
        /// <returns>A DbLogCollection containing all database logs</returns>
        public static DbLogCollection GetAll()
        {
            DbLogCollection list = new DbLogCollection();
            try
            {
                string query = "SELECT * FROM DbLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    DbLog log = new DbLog(
                        (int)row["DbLogID"],
                        (int)row["LogID"],
                        row["Engine"].ToString(),
                        row["Command"].ToString(),
                        row["DatabaseName"].ToString(),
                        row["Username"].ToString(),
                        row["QueryText"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToDecimal(row["ExecutionTime"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DB logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific database log by its unique identifier
        /// </summary>
        /// <param name="id">The DbLogID of the database log to retrieve</param>
        /// <returns>A DbLog object if found, otherwise null</returns>
        public static DbLog GetById(int id)
        {
            DbLog log = null;
            try
            {
                string query = "SELECT * FROM DbLogs WHERE DbLogID = @DbLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@DbLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new DbLog(
                        (int)row["DbLogID"],
                        (int)row["LogID"],
                        row["Engine"].ToString(),
                        row["Command"].ToString(),
                        row["DatabaseName"].ToString(),
                        row["Username"].ToString(),
                        row["QueryText"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToDecimal(row["ExecutionTime"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DB log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new database log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="engine">The database engine (e.g., MySQL, SQL Server)</param>
        /// <param name="command">The database command type</param>
        /// <param name="databaseName">The name of the database</param>
        /// <param name="username">The username that executed the query</param>
        /// <param name="queryText">The SQL query text</param>
        /// <param name="sourceIP">The source IP address</param>
        /// <param name="destinationIP">The destination IP address</param>
        /// <param name="timestamp">The timestamp when the query was executed</param>
        /// <param name="sessionID">The database session identifier</param>
        /// <param name="status">The execution status</param>
        /// <param name="executionTime">The query execution time in seconds</param>
        /// <returns>The newly created DbLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string engine, string command, string databaseName, string username,
                                 string queryText, string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, decimal executionTime)
        {
            try
            {
                string query = @"INSERT INTO DbLogs (LogID, Engine, Command, DatabaseName, Username, QueryText, SourceIP, DestinationIP, Timestamp, SessionID, Status, ExecutionTime)
                                 VALUES (@LogID, @Engine, @Command, @DatabaseName, @Username, @QueryText, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status, @ExecutionTime);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Engine", SqlDbType.NVarChar, 50) { Value = engine },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 50) { Value = command },
                    new SqlParameter("@DatabaseName", SqlDbType.NVarChar, 255) { Value = databaseName },
                    new SqlParameter("@Username", SqlDbType.NVarChar, 255) { Value = username },
                    new SqlParameter("@QueryText", SqlDbType.NVarChar, -1) { Value = queryText },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@ExecutionTime", SqlDbType.Decimal) { Value = executionTime }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting DB log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing database log in the database
        /// </summary>
        /// <param name="dbLogId">The unique identifier of the database log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="engine">The updated database engine</param>
        /// <param name="command">The updated database command type</param>
        /// <param name="databaseName">The updated database name</param>
        /// <param name="username">The updated username</param>
        /// <param name="queryText">The updated SQL query text</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated execution status</param>
        /// <param name="executionTime">The updated execution time</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int dbLogId, int logId, string engine, string command, string databaseName, string username,
                                  string queryText, string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, decimal executionTime)
        {
            try
            {
                string query = @"UPDATE DbLogs
                                 SET LogID = @LogID,
                                     Engine = @Engine,
                                     Command = @Command,
                                     DatabaseName = @DatabaseName,
                                     Username = @Username,
                                     QueryText = @QueryText,
                                     SourceIP = @SourceIP,
                                     DestinationIP = @DestinationIP,
                                     Timestamp = @Timestamp,
                                     SessionID = @SessionID,
                                     Status = @Status,
                                     ExecutionTime = @ExecutionTime
                                 WHERE DbLogID = @DbLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@DbLogID", SqlDbType.Int) { Value = dbLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Engine", SqlDbType.NVarChar, 50) { Value = engine },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 50) { Value = command },
                    new SqlParameter("@DatabaseName", SqlDbType.NVarChar, 255) { Value = databaseName },
                    new SqlParameter("@Username", SqlDbType.NVarChar, 255) { Value = username },
                    new SqlParameter("@QueryText", SqlDbType.NVarChar, -1) { Value = queryText },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@ExecutionTime", SqlDbType.Decimal) { Value = executionTime }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating DB log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a database log from the database
        /// </summary>
        /// <param name="dbLogId">The unique identifier of the database log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int dbLogId)
        {
            try
            {
                string query = "DELETE FROM DbLogs WHERE DbLogID = @DbLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@DbLogID", SqlDbType.Int) { Value = dbLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting DB log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a database log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>A DbLog object if found, otherwise null</returns>
        public static DbLog GetByLogId(int logId)
        {
            DbLog log = null;
            try
            {
                string query = "SELECT * FROM DbLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new DbLog(
                        (int)row["DbLogID"],
                        (int)row["LogID"],
                        row["Engine"].ToString(),
                        row["Command"].ToString(),
                        row["DatabaseName"].ToString(),
                        row["Username"].ToString(),
                        row["QueryText"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToDecimal(row["ExecutionTime"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DB log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}