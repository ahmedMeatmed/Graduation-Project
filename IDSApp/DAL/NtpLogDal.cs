using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling NTP (Network Time Protocol) log-related operations
    /// </summary>
    internal class NtpLogDal
    {
        /// <summary>
        /// Retrieves all NTP logs from the database
        /// </summary>
        /// <returns>An NtpLogCollection containing all NTP logs</returns>
        public static NtpLogCollection GetAll()
        {
            NtpLogCollection list = new NtpLogCollection();
            try
            {
                string query = "SELECT * FROM NtpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    NtpLog log = new NtpLog(
                        (int)row["NtpLogID"],
                        (int)row["LogID"],
                        row["Version"].ToString(),
                        row["Mode"].ToString(),
                        (int)row["Stratum"],
                        Convert.ToDateTime(row["TransmitTimestamp"]),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToDecimal(row["Offset"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching NTP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific NTP log by its unique identifier
        /// </summary>
        /// <param name="id">The NtpLogID of the NTP log to retrieve</param>
        /// <returns>An NtpLog object if found, otherwise null</returns>
        public static NtpLog GetById(int id)
        {
            NtpLog log = null;
            try
            {
                string query = "SELECT * FROM NtpLogs WHERE NtpLogID = @NtpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@NtpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new NtpLog(
                        (int)row["NtpLogID"],
                        (int)row["LogID"],
                        row["Version"].ToString(),
                        row["Mode"].ToString(),
                        (int)row["Stratum"],
                        Convert.ToDateTime(row["TransmitTimestamp"]),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToDecimal(row["Offset"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching NTP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new NTP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="version">The NTP protocol version (e.g., 3, 4)</param>
        /// <param name="mode">The NTP mode (e.g., client, server, symmetric, broadcast)</param>
        /// <param name="stratum">The stratum level indicating distance from reference clock (0-15)</param>
        /// <param name="transmitTimestamp">The timestamp when the NTP packet was transmitted</param>
        /// <param name="sourceIP">The source IP address of the NTP client</param>
        /// <param name="destinationIP">The destination IP address of the NTP server</param>
        /// <param name="timestamp">The timestamp when the log entry was created</param>
        /// <param name="sessionID">The NTP session identifier</param>
        /// <param name="status">The transaction status</param>
        /// <param name="offset">The time offset between client and server in seconds</param>
        /// <returns>The newly created NtpLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string version, string mode, int stratum, DateTime transmitTimestamp,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, decimal offset)
        {
            try
            {
                string query = @"
                INSERT INTO NtpLogs (LogID, Version, Mode, Stratum, TransmitTimestamp, SourceIP, DestinationIP, Timestamp, SessionID, Status, Offset)
                VALUES (@LogID, @Version, @Mode, @Stratum, @TransmitTimestamp, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status, @Offset);
                SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Version", SqlDbType.NVarChar, 10) { Value = version },
                    new SqlParameter("@Mode", SqlDbType.NVarChar, 20) { Value = mode },
                    new SqlParameter("@Stratum", SqlDbType.Int) { Value = stratum },
                    new SqlParameter("@TransmitTimestamp", SqlDbType.DateTime2) { Value = transmitTimestamp },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@Offset", SqlDbType.Decimal) { Value = offset }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting NTP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing NTP log in the database
        /// </summary>
        /// <param name="ntpLogId">The unique identifier of the NTP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="version">The updated NTP protocol version</param>
        /// <param name="mode">The updated NTP mode</param>
        /// <param name="stratum">The updated stratum level</param>
        /// <param name="transmitTimestamp">The updated transmit timestamp</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated log timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated transaction status</param>
        /// <param name="offset">The updated time offset</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int ntpLogId, int logId, string version, string mode, int stratum, DateTime transmitTimestamp,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, decimal offset)
        {
            try
            {
                string query = @"
                UPDATE NtpLogs
                SET LogID=@LogID, Version=@Version, Mode=@Mode, Stratum=@Stratum, TransmitTimestamp=@TransmitTimestamp,
                    SourceIP=@SourceIP, DestinationIP=@DestinationIP, Timestamp=@Timestamp, SessionID=@SessionID,
                    Status=@Status, Offset=@Offset
                WHERE NtpLogID=@NtpLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@NtpLogID", SqlDbType.Int) { Value = ntpLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Version", SqlDbType.NVarChar, 10) { Value = version },
                    new SqlParameter("@Mode", SqlDbType.NVarChar, 20) { Value = mode },
                    new SqlParameter("@Stratum", SqlDbType.Int) { Value = stratum },
                    new SqlParameter("@TransmitTimestamp", SqlDbType.DateTime2) { Value = transmitTimestamp },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@Offset", SqlDbType.Decimal) { Value = offset }
                };

                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating NTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes an NTP log from the database
        /// </summary>
        /// <param name="ntpLogId">The unique identifier of the NTP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int ntpLogId)
        {
            try
            {
                string query = "DELETE FROM NtpLogs WHERE NtpLogID=@NtpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@NtpLogID", SqlDbType.Int) { Value = ntpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting NTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an NTP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An NtpLog object if found, otherwise null</returns>
        public static NtpLog GetByLogId(int logId)
        {
            NtpLog log = null;
            try
            {
                string query = "SELECT * FROM NtpLogs WHERE LogID=@LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new NtpLog(
                        (int)row["NtpLogID"],
                        (int)row["LogID"],
                        row["Version"].ToString(),
                        row["Mode"].ToString(),
                        (int)row["Stratum"],
                        Convert.ToDateTime(row["TransmitTimestamp"]),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        Convert.ToDecimal(row["Offset"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching NTP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}