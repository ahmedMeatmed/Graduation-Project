using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a database operation log entry captured by the Intrusion Detection System.
    /// Contains detailed information about database queries, connections, and operations for security monitoring.
    /// </summary>
    public class DbLog
    {
        /// <summary>Unique identifier for the database log entry</summary>
        public int DbLogId { get; set; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get; set; }

        /// <summary>Database engine type (e.g., SQL Server, MySQL, Oracle, PostgreSQL)</summary>
        public string Engine { get; set; }

        /// <summary>Database command type (e.g., SELECT, INSERT, UPDATE, DELETE, DROP, CREATE)</summary>
        public string Command { get; set; }

        /// <summary>Name of the database where the operation was performed</summary>
        public string DatabaseName { get; set; }

        /// <summary>Username of the account that executed the database operation</summary>
        public string Username { get; set; }

        /// <summary>Full SQL query text that was executed</summary>
        public string QueryText { get; set; }

        /// <summary>Source IP address where the database request originated</summary>
        public string SourceIp { get; set; }

        /// <summary>Destination IP address of the database server</summary>
        public string DestinationIp { get; set; }

        /// <summary>Exact timestamp when the database operation occurred</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Database session identifier for tracking connection sessions</summary>
        public string SessionId { get; set; }

        /// <summary>Execution status of the query (e.g., Success, Failed, Timeout, Error)</summary>
        public string Status { get; set; }

        /// <summary>Time taken to execute the query in milliseconds or seconds</summary>
        public decimal ExecutionTime { get; set; }

        /// <summary>
        /// Initializes a new instance of the DbLog class with default values.
        /// </summary>
        public DbLog() { }

        /// <summary>
        /// Initializes a new instance of the DbLog class with specified parameters.
        /// </summary>
        /// <param name="dbLogId">Unique identifier for the database log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="engine">Database engine type</param>
        /// <param name="command">Database command type</param>
        /// <param name="databaseName">Name of the target database</param>
        /// <param name="username">Username that executed the operation</param>
        /// <param name="queryText">Full SQL query text</param>
        /// <param name="sourceIp">Source IP address of the request</param>
        /// <param name="destinationIp">Destination IP address of database server</param>
        /// <param name="timestamp">When the operation occurred</param>
        /// <param name="sessionId">Database session identifier</param>
        /// <param name="status">Execution status of the query</param>
        /// <param name="executionTime">Time taken to execute the query</param>
        public DbLog(int dbLogId, int logId, string engine, string command, string databaseName,
                     string username, string queryText, string sourceIp, string destinationIp,
                     DateTime timestamp, string sessionId, string status, decimal executionTime)
        {
            DbLogId = dbLogId;
            LogId = logId;
            Engine = engine;
            Command = command;
            DatabaseName = databaseName;
            Username = username;
            QueryText = queryText;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            Timestamp = timestamp;
            SessionId = sessionId;
            Status = status;
            ExecutionTime = executionTime;
        }

        /// <summary>
        /// Initializes a new instance of the DbLog class as a copy of an existing DbLog object.
        /// </summary>
        /// <param name="d">Source DbLog object to copy from</param>
        public DbLog(DbLog d) : this(d.DbLogId, d.LogId, d.Engine, d.Command, d.DatabaseName,
                                     d.Username, d.QueryText, d.SourceIp, d.DestinationIp,
                                     d.Timestamp, d.SessionId, d.Status, d.ExecutionTime)
        { }

        /// <summary>
        /// Creates a deep copy of the current DbLog instance.
        /// </summary>
        /// <returns>A new DbLog object that is an exact copy of the current instance</returns>
        public DbLog Clone() => new DbLog(this);
    }
}