using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for SMTP (Simple Mail Transfer Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for SMTP log-related operations.
    /// </summary>
    internal class SmtpLogBLL
    {
        /// <summary>
        /// Retrieves all SMTP logs from the system.
        /// </summary>
        /// <returns>A collection of SmtpLog objects containing all SMTP logs in the system.</returns>
        public static SmtpLogCollection GetAll()
        {
            return SmtpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific SMTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The SmtpLogID of the SMTP log to retrieve.</param>
        /// <returns>An SmtpLog object if found; otherwise, null.</returns>
        public static SmtpLog GetById(int id)
        {
            return SmtpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new SMTP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="fromAddress">The sender's email address from the SMTP transaction.</param>
        /// <param name="toAddress">The recipient's email address from the SMTP transaction.</param>
        /// <param name="subject">The subject line of the email message.</param>
        /// <returns>The newly created SmtpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string fromAddress, string toAddress, string subject)
        {
            return SmtpLogDal.Insert(logId, fromAddress, toAddress, subject);
        }

        /// <summary>
        /// Deletes a specific SMTP log from the system.
        /// </summary>
        /// <param name="smtpLogId">The SmtpLogID of the SMTP log to delete.</param>
        /// <returns>true if the SMTP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int smtpLogId)
        {
            return SmtpLogDal.Delete(smtpLogId);
        }

        /// <summary>
        /// Updates an existing SMTP log entry with new information.
        /// </summary>
        /// <param name="smtpLogId">The SmtpLogID of the SMTP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="fromAddress">The updated sender's email address.</param>
        /// <param name="toAddress">The updated recipient's email address.</param>
        /// <param name="subject">The updated email subject line.</param>
        /// <returns>true if the SMTP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int smtpLogId, int logId, string fromAddress, string toAddress, string subject)
        {
            return SmtpLogDal.Update(smtpLogId, logId, fromAddress, toAddress, subject);
        }
    }
}