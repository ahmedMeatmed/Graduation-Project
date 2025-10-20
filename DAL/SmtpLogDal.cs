using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for SMTP log operations in the database.
    /// </summary>
    internal class SmtpLogDal
    {
        /// <summary>
        /// Retrieves all SMTP logs from the database.
        /// </summary>
        /// <returns>A collection of SmtpLog objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static SmtpLogCollection GetAll()
        {
            SmtpLogCollection list = new SmtpLogCollection();
            try
            {
                string query = "SELECT * FROM SmtpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    SmtpLog log = new SmtpLog(
                        (int)row["SmtpLogID"],
                        (int)row["LogID"],
                        row["FromAddress"].ToString(),
                        row["ToAddress"].ToString(),
                        row["Subject"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SMTP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific SMTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The SmtpLogID of the record to retrieve.</param>
        /// <returns>A SmtpLog object if found; otherwise, null.</returns>
        public static SmtpLog GetById(int id)
        {
            SmtpLog log = null;
            try
            {
                string query = "SELECT * FROM SmtpLogs WHERE SmtpLogID = @SmtpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SmtpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new SmtpLog(
                        (int)row["SmtpLogID"],
                        (int)row["LogID"],
                        row["FromAddress"].ToString(),
                        row["ToAddress"].ToString(),
                        row["Subject"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SMTP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new SMTP log record into the database.
        /// </summary>
        /// <param name="logId">The associated LogID.</param>
        /// <param name="fromAddress">The sender's email address.</param>
        /// <param name="toAddress">The recipient's email address.</param>
        /// <param name="subject">The email subject line.</param>
        /// <returns>The newly created SmtpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string fromAddress, string toAddress, string subject)
        {
            try
            {
                string query = @"INSERT INTO SmtpLogs (LogID, FromAddress, ToAddress, Subject)
                                 VALUES (@LogID, @FromAddress, @ToAddress, @Subject);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@FromAddress", SqlDbType.NVarChar, 255) { Value = fromAddress },
                    new SqlParameter("@ToAddress", SqlDbType.NVarChar, 255) { Value = toAddress },
                    new SqlParameter("@Subject", SqlDbType.NVarChar, 255) { Value = subject }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting SMTP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes a specific SMTP log record from the database.
        /// </summary>
        /// <param name="smtpLogId">The SmtpLogID of the record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int smtpLogId)
        {
            try
            {
                string query = "DELETE FROM SmtpLogs WHERE SmtpLogID = @SmtpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SmtpLogID", SqlDbType.Int) { Value = smtpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting SMTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing SMTP log record in the database.
        /// </summary>
        /// <param name="smtpLogId">The SmtpLogID of the record to update.</param>
        /// <param name="logId">The new LogID value.</param>
        /// <param name="fromAddress">The new sender's email address.</param>
        /// <param name="toAddress">The new recipient's email address.</param>
        /// <param name="subject">The new email subject line.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int smtpLogId, int logId, string fromAddress, string toAddress, string subject)
        {
            try
            {
                string queryStr = @"
            UPDATE SmtpLogs
            SET LogID = @LogID,
                FromAddress = @FromAddress,
                ToAddress = @ToAddress,
                Subject = @Subject
            WHERE SmtpLogID = @SmtpLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@SmtpLogID", SqlDbType.Int) { Value = smtpLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@FromAddress", SqlDbType.NVarChar, 255) { Value = fromAddress },
            new SqlParameter("@ToAddress", SqlDbType.NVarChar, 255) { Value = toAddress },
            new SqlParameter("@Subject", SqlDbType.NVarChar, 255) { Value = subject }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating SMTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an SMTP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for.</param>
        /// <returns>A SmtpLog object if found; otherwise, null.</returns>
        public static SmtpLog GetByLogId(int logId)
        {
            SmtpLog log = null;
            try
            {
                string query = "SELECT * FROM SmtpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new SmtpLog(
                        (int)row["SmtpLogID"],
                        (int)row["LogID"],
                        row["From"].ToString(),
                        row["To"].ToString(),
                        row["Subject"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SMTP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}