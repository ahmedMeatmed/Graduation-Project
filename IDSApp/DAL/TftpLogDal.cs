using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for TFTP (Trivial File Transfer Protocol) log operations in the database.
    /// </summary>
    internal class TftpLogDal
    {
        /// <summary>
        /// Retrieves all TFTP logs from the database.
        /// </summary>
        /// <returns>A collection of TftpLog objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static TftpLogCollection GetAll()
        {
            TftpLogCollection list = new TftpLogCollection();
            try
            {
                string query = "SELECT * FROM TftpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    TftpLog log = new TftpLog(
                        (int)row["TftpLogID"],
                        (int)row["LogID"],
                        row["Operation"].ToString(),
                        row["Filename"].ToString(),
                        row["TransferSize"] != DBNull.Value ? (int)row["TransferSize"] : 0,
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        row["Timestamp"] != DBNull.Value ? (DateTime)row["Timestamp"] : DateTime.MinValue,
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching TFTP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific TFTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The TftpLogID of the record to retrieve.</param>
        /// <returns>A TftpLog object if found; otherwise, null.</returns>
        public static TftpLog GetById(int id)
        {
            TftpLog log = null;
            try
            {
                string query = "SELECT * FROM TftpLogs WHERE TftpLogID = @TftpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@TftpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new TftpLog(
                        (int)row["TftpLogID"],
                        (int)row["LogID"],
                        row["Operation"].ToString(),
                        row["Filename"].ToString(),
                        row["TransferSize"] != DBNull.Value ? (int)row["TransferSize"] : 0,
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        row["Timestamp"] != DBNull.Value ? (DateTime)row["Timestamp"] : DateTime.MinValue,
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching TFTP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new TFTP log record into the database.
        /// </summary>
        /// <param name="logId">The associated LogID.</param>
        /// <param name="operation">The TFTP operation type (e.g., READ, WRITE).</param>
        /// <param name="filename">The name of the file being transferred.</param>
        /// <param name="transferSize">The size of the file transfer in bytes.</param>
        /// <param name="sourceIP">The source IP address of the TFTP request.</param>
        /// <param name="destinationIP">The destination IP address of the TFTP request.</param>
        /// <param name="timestamp">The date and time when the TFTP transfer occurred.</param>
        /// <param name="sessionID">The session identifier for the TFTP transaction.</param>
        /// <param name="status">The status of the TFTP transfer (e.g., Success, Failed).</param>
        /// <returns>The newly created TftpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string operation, string filename, int transferSize,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status)
        {
            try
            {
                string query = @"INSERT INTO TftpLogs (LogID, Operation, Filename, TransferSize, SourceIP, DestinationIP, Timestamp, SessionID, Status)
                                 VALUES (@LogID, @Operation, @Filename, @TransferSize, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Operation", SqlDbType.NVarChar, 20) { Value = operation },
                    new SqlParameter("@Filename", SqlDbType.NVarChar, 255) { Value = filename },
                    new SqlParameter("@TransferSize", SqlDbType.Int) { Value = transferSize },
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
                Console.WriteLine("Error inserting TFTP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing TFTP log record in the database.
        /// </summary>
        /// <param name="tftpLogId">The TftpLogID of the record to update.</param>
        /// <param name="logId">The new LogID value.</param>
        /// <param name="operation">The new TFTP operation type.</param>
        /// <param name="filename">The new filename being transferred.</param>
        /// <param name="transferSize">The new transfer size in bytes.</param>
        /// <param name="sourceIP">The new source IP address.</param>
        /// <param name="destinationIP">The new destination IP address.</param>
        /// <param name="timestamp">The new timestamp of the transfer.</param>
        /// <param name="sessionID">The new session identifier.</param>
        /// <param name="status">The new transfer status.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int tftpLogId, int logId, string operation, string filename, int transferSize,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status)
        {
            try
            {
                string query = @"UPDATE TftpLogs
                                 SET LogID=@LogID, Operation=@Operation, Filename=@Filename, TransferSize=@TransferSize,
                                     SourceIP=@SourceIP, DestinationIP=@DestinationIP, Timestamp=@Timestamp,
                                     SessionID=@SessionID, Status=@Status
                                 WHERE TftpLogID=@TftpLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@TftpLogID", SqlDbType.Int) { Value = tftpLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Operation", SqlDbType.NVarChar, 20) { Value = operation },
                    new SqlParameter("@Filename", SqlDbType.NVarChar, 255) { Value = filename },
                    new SqlParameter("@TransferSize", SqlDbType.Int) { Value = transferSize },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating TFTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a specific TFTP log record from the database.
        /// </summary>
        /// <param name="tftpLogId">The TftpLogID of the record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int tftpLogId)
        {
            try
            {
                string query = "DELETE FROM TftpLogs WHERE TftpLogID=@TftpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@TftpLogID", SqlDbType.Int) { Value = tftpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting TFTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a TFTP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for.</param>
        /// <returns>A TftpLog object if found; otherwise, null.</returns>
        public static TftpLog GetByLogId(int logId)
        {
            TftpLog log = null;
            try
            {
                string query = "SELECT * FROM TftpLogs WHERE LogID=@LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new TftpLog(
                        (int)row["TftpLogID"],
                        (int)row["LogID"],
                        row["Operation"].ToString(),
                        row["Filename"].ToString(),
                        row["TransferSize"] != DBNull.Value ? (int)row["TransferSize"] : 0,
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        row["Timestamp"] != DBNull.Value ? (DateTime)row["Timestamp"] : DateTime.MinValue,
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching TFTP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}