using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for NTP (Network Time Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for NTP log-related operations.
    /// </summary>
    internal class NtpLogBLL
    {
        /// <summary>
        /// Retrieves all NTP logs from the system.
        /// </summary>
        /// <returns>A collection of NtpLog objects containing all NTP logs in the system.</returns>
        public static NtpLogCollection GetAll()
        {
            return NtpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific NTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The NtpLogID of the NTP log to retrieve.</param>
        /// <returns>An NtpLog object if found; otherwise, null.</returns>
        public static NtpLog GetById(int id)
        {
            return NtpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new NTP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="version">The NTP protocol version (e.g., 3, 4).</param>
        /// <param name="mode">The NTP mode (e.g., Client, Server, Broadcast).</param>
        /// <param name="stratum">The stratum level indicating the distance from the reference clock (1=primary, 2=secondary, etc.).</param>
        /// <param name="transmitTimestamp">The timestamp when the NTP message was transmitted.</param>
        /// <param name="sourceIP">The source IP address of the NTP client.</param>
        /// <param name="destinationIP">The destination IP address of the NTP server.</param>
        /// <param name="timestamp">The date and time when the NTP transaction occurred.</param>
        /// <param name="sessionID">The session identifier for the NTP transaction.</param>
        /// <param name="status">The status of the NTP operation (e.g., Success, Failed, Offset Adjusted).</param>
        /// <param name="offset">The time offset between client and server in milliseconds.</param>
        /// <returns>The newly created NtpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string version, string mode, int stratum, DateTime transmitTimestamp,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, decimal offset)
        {
            return NtpLogDal.Insert(logId, version, mode, stratum, transmitTimestamp, sourceIP, destinationIP, timestamp, sessionID, status, offset);
        }

        /// <summary>
        /// Updates an existing NTP log entry with new information.
        /// </summary>
        /// <param name="ntpLogId">The NtpLogID of the NTP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="version">The updated NTP protocol version.</param>
        /// <param name="mode">The updated NTP mode.</param>
        /// <param name="stratum">The updated stratum level.</param>
        /// <param name="transmitTimestamp">The updated transmit timestamp.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <param name="offset">The updated time offset in milliseconds.</param>
        /// <returns>true if the NTP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int ntpLogId, int logId, string version, string mode, int stratum, DateTime transmitTimestamp,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, decimal offset)
        {
            return NtpLogDal.Update(ntpLogId, logId, version, mode, stratum, transmitTimestamp, sourceIP, destinationIP, timestamp, sessionID, status, offset);
        }

        /// <summary>
        /// Deletes a specific NTP log from the system.
        /// </summary>
        /// <param name="ntpLogId">The NtpLogID of the NTP log to delete.</param>
        /// <returns>true if the NTP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int ntpLogId)
        {
            return NtpLogDal.Delete(ntpLogId);
        }

        /// <summary>
        /// Retrieves an NTP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated NTP logs.</param>
        /// <returns>An NtpLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static NtpLog GetByLogId(int logId)
        {
            return NtpLogDal.GetByLogId(logId);
        }
    }
}