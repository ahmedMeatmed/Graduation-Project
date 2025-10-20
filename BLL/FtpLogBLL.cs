using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for FTP (File Transfer Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for FTP log-related operations.
    /// </summary>
    internal class FtpLogBLL
    {
        /// <summary>
        /// Retrieves all FTP logs from the system.
        /// </summary>
        /// <returns>A collection of FtpLog objects containing all FTP logs in the system.</returns>
        public static FtpLogCollection GetAll()
        {
            return FtpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific FTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The FtpLogID of the FTP log to retrieve.</param>
        /// <returns>An FtpLog object if found; otherwise, null.</returns>
        public static FtpLog GetById(int id)
        {
            return FtpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new FTP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="command">The FTP command that was executed (e.g., RETR, STOR, LIST, DELE, MKD).</param>
        /// <param name="filename">The name of the file involved in the FTP operation, if applicable.</param>
        /// <returns>The newly created FtpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string command, string filename)
        {
            return FtpLogDal.Insert(logId, command, filename);
        }

        /// <summary>
        /// Deletes a specific FTP log from the system.
        /// </summary>
        /// <param name="ftpLogId">The FtpLogID of the FTP log to delete.</param>
        /// <returns>true if the FTP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int ftpLogId)
        {
            return FtpLogDal.Delete(ftpLogId);
        }

        /// <summary>
        /// Updates an existing FTP log entry with new information.
        /// </summary>
        /// <param name="ftpLogId">The FtpLogID of the FTP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="command">The updated FTP command.</param>
        /// <param name="filename">The updated filename.</param>
        /// <returns>true if the FTP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int ftpLogId, int logId, string command, string filename)
        {
            return FtpLogDal.Update(ftpLogId, logId, command, filename);
        }
    }
}