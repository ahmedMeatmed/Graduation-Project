using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for POP3 (Post Office Protocol version 3) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for POP3 log-related operations.
    /// </summary>
    internal class Pop3LogBLL
    {
        /// <summary>
        /// Retrieves all POP3 logs from the system.
        /// </summary>
        /// <returns>A collection of Pop3Log objects containing all POP3 logs in the system.</returns>
        public static Pop3LogCollection GetAll()
        {
            return Pop3LogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific POP3 log by its unique identifier.
        /// </summary>
        /// <param name="id">The Pop3LogID of the POP3 log to retrieve.</param>
        /// <returns>A Pop3Log object if found; otherwise, null.</returns>
        public static Pop3Log GetById(int id)
        {
            return Pop3LogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new POP3 log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="command">The POP3 command executed (e.g., USER, PASS, LIST, RETR, DELE, QUIT).</param>
        /// <param name="username">The username used for authentication.</param>
        /// <param name="responseCode">The POP3 server response code (e.g., +OK, -ERR).</param>
        /// <param name="messageSize">The size of the email message in bytes, if applicable.</param>
        /// <param name="sourceIP">The source IP address of the POP3 client.</param>
        /// <param name="destinationIP">The destination IP address of the POP3 server.</param>
        /// <param name="timestamp">The date and time when the POP3 operation occurred.</param>
        /// <param name="sessionID">The session identifier for the POP3 connection.</param>
        /// <param name="status">The status of the POP3 operation (e.g., Success, Failed, Authenticated).</param>
        /// <param name="attemptCount">The number of authentication attempts made.</param>
        /// <returns>The newly created Pop3LogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string command, string username, string responseCode, int messageSize,
                                 string sourceIP, string destinationIP, DateTime timestamp, string sessionID,
                                 string status, int attemptCount)
        {
            return Pop3LogDal.Insert(logId, command, username, responseCode, messageSize,
                                     sourceIP, destinationIP, timestamp, sessionID, status, attemptCount);
        }

        /// <summary>
        /// Updates an existing POP3 log entry with new information.
        /// </summary>
        /// <param name="pop3LogId">The Pop3LogID of the POP3 log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="command">The updated POP3 command.</param>
        /// <param name="username">The updated username.</param>
        /// <param name="responseCode">The updated POP3 response code.</param>
        /// <param name="messageSize">The updated message size in bytes.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <param name="attemptCount">The updated attempt count.</param>
        /// <returns>true if the POP3 log was successfully updated; otherwise, false.</returns>
        public static bool Update(int pop3LogId, int logId, string command, string username, string responseCode, int messageSize,
                                  string sourceIP, string destinationIP, DateTime timestamp, string sessionID,
                                  string status, int attemptCount)
        {
            return Pop3LogDal.Update(pop3LogId, logId, command, username, responseCode, messageSize,
                                     sourceIP, destinationIP, timestamp, sessionID, status, attemptCount);
        }

        /// <summary>
        /// Deletes a specific POP3 log from the system.
        /// </summary>
        /// <param name="pop3LogId">The Pop3LogID of the POP3 log to delete.</param>
        /// <returns>true if the POP3 log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int pop3LogId)
        {
            return Pop3LogDal.Delete(pop3LogId);
        }

        /// <summary>
        /// Retrieves a POP3 log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated POP3 logs.</param>
        /// <returns>A Pop3Log object associated with the specified log entry if found; otherwise, null.</returns>
        public static Pop3Log GetByLogId(int logId)
        {
            return Pop3LogDal.GetByLogId(logId);
        }
    }
}