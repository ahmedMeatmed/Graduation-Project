using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for IMAP (Internet Message Access Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for IMAP log-related operations.
    /// </summary>
    internal class ImapLogBLL
    {
        /// <summary>
        /// Retrieves all IMAP logs from the system.
        /// </summary>
        /// <returns>A collection of ImapLog objects containing all IMAP logs in the system.</returns>
        public static ImapLogCollection GetAll()
        {
            return ImapLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific IMAP log by its unique identifier.
        /// </summary>
        /// <param name="id">The ImapLogID of the IMAP log to retrieve.</param>
        /// <returns>An ImapLog object if found; otherwise, null.</returns>
        public static ImapLog GetById(int id)
        {
            return ImapLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new IMAP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="command">The IMAP command executed (e.g., LOGIN, SELECT, FETCH, STORE, SEARCH).</param>
        /// <param name="folder">The mail folder being accessed (e.g., INBOX, Sent, Drafts).</param>
        /// <param name="responseCode">The IMAP response code from the server (e.g., OK, NO, BAD).</param>
        /// <param name="sourceIP">The source IP address of the IMAP client.</param>
        /// <param name="destinationIP">The destination IP address of the IMAP server.</param>
        /// <param name="timestamp">The date and time when the IMAP operation occurred.</param>
        /// <param name="sessionID">The session identifier for the IMAP connection.</param>
        /// <param name="status">The status of the IMAP operation (e.g., Success, Failed, Partial).</param>
        /// <param name="attemptCount">The number of authentication or operation attempts made.</param>
        /// <returns>The newly created ImapLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string command, string folder, string responseCode,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, int attemptCount)
        {
            return ImapLogDal.Insert(logId, command, folder, responseCode, sourceIP, destinationIP, timestamp, sessionID, status, attemptCount);
        }

        /// <summary>
        /// Updates an existing IMAP log entry with new information.
        /// </summary>
        /// <param name="imapLogId">The ImapLogID of the IMAP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="command">The updated IMAP command.</param>
        /// <param name="folder">The updated mail folder.</param>
        /// <param name="responseCode">The updated IMAP response code.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <param name="attemptCount">The updated attempt count.</param>
        /// <returns>true if the IMAP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int imapLogId, int logId, string command, string folder, string responseCode,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, int attemptCount)
        {
            return ImapLogDal.Update(imapLogId, logId, command, folder, responseCode, sourceIP, destinationIP, timestamp, sessionID, status, attemptCount);
        }

        /// <summary>
        /// Deletes a specific IMAP log from the system.
        /// </summary>
        /// <param name="imapLogId">The ImapLogID of the IMAP log to delete.</param>
        /// <returns>true if the IMAP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int imapLogId)
        {
            return ImapLogDal.Delete(imapLogId);
        }

        /// <summary>
        /// Retrieves an IMAP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated IMAP logs.</param>
        /// <returns>An ImapLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static ImapLog GetByLogId(int logId)
        {
            return ImapLogDal.GetByLogId(logId);
        }
    }
}