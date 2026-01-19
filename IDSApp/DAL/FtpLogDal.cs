using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling FTP log-related operations
    /// </summary>
    internal class FtpLogDal
    {
        /// <summary>
        /// Retrieves all FTP logs from the database
        /// </summary>
        /// <returns>An FtpLogCollection containing all FTP logs</returns>
        public static FtpLogCollection GetAll()
        {
            FtpLogCollection list = new FtpLogCollection();
            try
            {
                string query = "SELECT * FROM FtpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    FtpLog log = new FtpLog(
                        (int)row["FtpLogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Filename"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching FTP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific FTP log by its unique identifier
        /// </summary>
        /// <param name="id">The FtpLogID of the FTP log to retrieve</param>
        /// <returns>An FtpLog object if found, otherwise null</returns>
        public static FtpLog GetById(int id)
        {
            FtpLog log = null;
            try
            {
                string query = "SELECT * FROM FtpLogs WHERE FtpLogID = @FtpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@FtpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new FtpLog(
                        (int)row["FtpLogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Filename"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching FTP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new FTP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="command">The FTP command (e.g., RETR, STOR, LIST, DELE, MKD, RMD)</param>
        /// <param name="filename">The filename associated with the FTP operation</param>
        /// <returns>The newly created FtpLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string command, string filename)
        {
            try
            {
                string query = @"INSERT INTO FtpLogs (LogID, Command, Filename)
                                 VALUES (@LogID, @Command, @Filename);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 10) { Value = command },
                    new SqlParameter("@Filename", SqlDbType.NVarChar, 255) { Value = filename }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting FTP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes an FTP log from the database
        /// </summary>
        /// <param name="ftpLogId">The unique identifier of the FTP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int ftpLogId)
        {
            try
            {
                string query = "DELETE FROM FtpLogs WHERE FtpLogID = @FtpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@FtpLogID", SqlDbType.Int) { Value = ftpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting FTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing FTP log in the database
        /// </summary>
        /// <param name="ftpLogId">The unique identifier of the FTP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="command">The updated FTP command</param>
        /// <param name="filename">The updated filename</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int ftpLogId, int logId, string command, string filename)
        {
            try
            {
                string queryStr = @"
                    UPDATE FtpLogs
                    SET LogID = @LogID,
                        Command = @Command,
                        Filename = @Filename
                    WHERE FtpLogID = @FtpLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@FtpLogID", SqlDbType.Int) { Value = ftpLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Command", SqlDbType.NVarChar, 10) { Value = command },
                    new SqlParameter("@Filename", SqlDbType.NVarChar, 255) { Value = filename }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating FTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an FTP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An FtpLog object if found, otherwise null</returns>
        public static FtpLog GetByLogId(int logId)
        {
            FtpLog log = null;
            try
            {
                string query = "SELECT * FROM FtpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new FtpLog(
                        (int)row["FtpLogID"],
                        (int)row["LogID"],
                        row["Command"].ToString(),
                        row["Filename"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching FTP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}