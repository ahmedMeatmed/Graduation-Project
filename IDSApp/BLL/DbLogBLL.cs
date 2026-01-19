using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for database log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for database log-related operations.
    /// </summary>
    internal class DbLogBLL
    {
        /// <summary>
        /// Retrieves all database logs from the system.
        /// </summary>
        /// <returns>A collection of DbLog objects containing all database logs in the system.</returns>
        public static DbLogCollection GetAll()
        {
            return DbLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific database log by its unique identifier.
        /// </summary>
        /// <param name="id">The DbLogID of the database log to retrieve.</param>
        /// <returns>A DbLog object if found; otherwise, null.</returns>
        public static DbLog GetById(int id)
        {
            return DbLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new database log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="engine">The database engine type (e.g., MySQL, PostgreSQL, SQL Server).</param>
        /// <param name="command">The database command type (e.g., SELECT, INSERT, UPDATE, DELETE).</param>
        /// <param name="databaseName">The name of the database being accessed.</param>
        /// <param name="username">The database username used for the operation.</param>
        /// <param name="queryText">The full SQL query text that was executed.</param>
        /// <param name="sourceIp">The source IP address where the query originated.</param>
        /// <param name="destinationIp">The destination IP address of the database server.</param>
        /// <param name="timestamp">The date and time when the database operation occurred.</param>
        /// <param name="sessionId">The database session identifier.</param>
        /// <param name="status">The status of the database operation (e.g., Success, Failed).</param>
        /// <param name="executionTime">The time taken to execute the query in milliseconds.</param>
        /// <returns>The newly created DbLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string engine, string command, string databaseName, string username,
                                 string queryText, string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, decimal executionTime)
        {
            return DbLogDal.Insert(logId, engine, command, databaseName, username, queryText, sourceIP, destinationIP,
                                   timestamp, sessionID, status, executionTime);
        }

        /// <summary>
        /// Updates an existing database log entry with new information.
        /// </summary>
        /// <param name="dbLogId">The DbLogID of the database log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="engine">The updated database engine type.</param>
        /// <param name="command">The updated database command type.</param>
        /// <param name="databaseName">The updated database name.</param>
        /// <param name="username">The updated database username.</param>
        /// <param name="queryText">The updated SQL query text.</param>
        /// <param name="sourceIp">The updated source IP address.</param>
        /// <param name="destinationIp">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionId">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <param name="executionTime">The updated execution time.</param>
        /// <returns>true if the database log was successfully updated; otherwise, false.</returns>
        public static bool Update(int dbLogId, int logId, string engine, string command, string databaseName, string username,
                                  string queryText, string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, decimal executionTime)
        {
            return DbLogDal.Update(dbLogId, logId, engine, command, databaseName, username, queryText, sourceIP, destinationIP,
                                   timestamp, sessionID, status, executionTime);
        }

        /// <summary>
        /// Deletes a specific database log from the system.
        /// </summary>
        /// <param name="dbLogId">The DbLogID of the database log to delete.</param>
        /// <returns>true if the database log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int dbLogId)
        {
            return DbLogDal.Delete(dbLogId);
        }

        /// <summary>
        /// Retrieves a database log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated database logs.</param>
        /// <returns>A DbLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static DbLog GetByLogId(int logId)
        {
            return DbLogDal.GetByLogId(logId);
        }
    }
}