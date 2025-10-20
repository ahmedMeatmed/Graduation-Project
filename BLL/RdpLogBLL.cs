using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for RDP (Remote Desktop Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for RDP log-related operations.
    /// </summary>
    internal class RdpLogBLL
    {
        /// <summary>
        /// Retrieves all RDP logs from the system.
        /// </summary>
        /// <returns>A collection of RdpLog objects containing all RDP logs in the system.</returns>
        public static RdpLogCollection GetAll()
        {
            return RdpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific RDP log by its unique identifier.
        /// </summary>
        /// <param name="id">The RdpLogID of the RDP log to retrieve.</param>
        /// <returns>An RdpLog object if found; otherwise, null.</returns>
        public static RdpLog GetById(int id)
        {
            return RdpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new RDP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="clientIP">The IP address of the RDP client attempting the connection.</param>
        /// <param name="serverIP">The IP address of the RDP server (remote desktop host).</param>
        /// <param name="sessionID">The unique session identifier for the RDP connection.</param>
        /// <param name="authAttempts">The number of authentication attempts made during the connection.</param>
        /// <returns>The newly created RdpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string clientIP, string serverIP, string sessionID, int authAttempts)
        {
            return RdpLogDal.Insert(logId, clientIP, serverIP, sessionID, authAttempts);
        }

        /// <summary>
        /// Deletes a specific RDP log from the system.
        /// </summary>
        /// <param name="rdpLogId">The RdpLogID of the RDP log to delete.</param>
        /// <returns>true if the RDP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int rdpLogId)
        {
            return RdpLogDal.Delete(rdpLogId);
        }

        /// <summary>
        /// Updates an existing RDP log entry with new information.
        /// </summary>
        /// <param name="rdpLogId">The RdpLogID of the RDP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="clientIP">The updated client IP address.</param>
        /// <param name="serverIP">The updated server IP address.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="authAttempts">The updated authentication attempt count.</param>
        /// <returns>true if the RDP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int rdpLogId, int logId, string clientIP, string serverIP, string sessionID, int authAttempts)
        {
            return RdpLogDal.Update(rdpLogId, logId, clientIP, serverIP, sessionID, authAttempts);
        }
    }
}