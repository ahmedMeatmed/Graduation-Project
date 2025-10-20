using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for TFTP (Trivial File Transfer Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for TFTP log-related operations.
    /// </summary>
    internal class TftpLogBLL
    {
        /// <summary>
        /// Retrieves all TFTP logs from the system.
        /// </summary>
        /// <returns>A collection of TftpLog objects containing all TFTP logs in the system.</returns>
        public static TftpLogCollection GetAll()
        {
            return TftpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific TFTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The TftpLogID of the TFTP log to retrieve.</param>
        /// <returns>A TftpLog object if found; otherwise, null.</returns>
        public static TftpLog GetById(int id)
        {
            return TftpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new TFTP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="operation">The TFTP operation type (e.g., READ, WRITE).</param>
        /// <param name="filename">The name of the file being transferred.</param>
        /// <param name="transferSize">The size of the file transfer in bytes.</param>
        /// <param name="sourceIP">The source IP address of the TFTP client.</param>
        /// <param name="destinationIP">The destination IP address of the TFTP server.</param>
        /// <param name="timestamp">The date and time when the TFTP transfer occurred.</param>
        /// <param name="sessionID">The session identifier for the TFTP transaction.</param>
        /// <param name="status">The status of the TFTP transfer (e.g., Success, Failed, Timeout).</param>
        /// <returns>The newly created TftpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string operation, string filename, int transferSize,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status)
        {
            return TftpLogDal.Insert(logId, operation, filename, transferSize, sourceIP, destinationIP, timestamp, sessionID, status);
        }

        /// <summary>
        /// Updates an existing TFTP log entry with new information.
        /// </summary>
        /// <param name="tftpLogId">The TftpLogID of the TFTP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="operation">The updated TFTP operation type.</param>
        /// <param name="filename">The updated filename.</param>
        /// <param name="transferSize">The updated transfer size in bytes.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated transfer status.</param>
        /// <returns>true if the TFTP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int tftpLogId, int logId, string operation, string filename, int transferSize,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status)
        {
            return TftpLogDal.Update(tftpLogId, logId, operation, filename, transferSize, sourceIP, destinationIP, timestamp, sessionID, status);
        }

        /// <summary>
        /// Deletes a specific TFTP log from the system.
        /// </summary>
        /// <param name="tftpLogId">The TftpLogID of the TFTP log to delete.</param>
        /// <returns>true if the TFTP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int tftpLogId)
        {
            return TftpLogDal.Delete(tftpLogId);
        }

        /// <summary>
        /// Retrieves a TFTP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated TFTP logs.</param>
        /// <returns>A TftpLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static TftpLog GetByLogId(int logId)
        {
            return TftpLogDal.GetByLogId(logId);
        }
    }
}