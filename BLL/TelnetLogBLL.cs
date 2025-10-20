using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for Telnet log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for Telnet log-related operations.
    /// </summary>
    internal class TelnetLogBLL
    {
        /// <summary>
        /// Retrieves all Telnet logs from the system.
        /// </summary>
        /// <returns>A collection of TelnetLog objects containing all Telnet logs in the system.</returns>
        public static TelnetLogCollection GetAll()
        {
            return TelnetLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific Telnet log by its unique identifier.
        /// </summary>
        /// <param name="id">The TelnetLogID of the Telnet log to retrieve.</param>
        /// <returns>A TelnetLog object if found; otherwise, null.</returns>
        public static TelnetLog GetById(int id)
        {
            return TelnetLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new Telnet log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="clientIP">The IP address of the Telnet client initiating the connection.</param>
        /// <param name="serverIP">The IP address of the Telnet server receiving the connection.</param>
        /// <param name="command">The Telnet command executed during the session.</param>
        /// <param name="authAttempts">The number of authentication attempts made during the Telnet session.</param>
        /// <returns>The newly created TelnetLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string clientIP, string serverIP, string command, int authAttempts)
        {
            return TelnetLogDal.Insert(logId, clientIP, serverIP, command, authAttempts);
        }

        /// <summary>
        /// Deletes a specific Telnet log from the system.
        /// </summary>
        /// <param name="telnetLogId">The TelnetLogID of the Telnet log to delete.</param>
        /// <returns>true if the Telnet log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int telnetLogId)
        {
            return TelnetLogDal.Delete(telnetLogId);
        }

        /// <summary>
        /// Updates an existing Telnet log entry with new information.
        /// </summary>
        /// <param name="telnetLogId">The TelnetLogID of the Telnet log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="clientIP">The updated client IP address.</param>
        /// <param name="serverIP">The updated server IP address.</param>
        /// <param name="command">The updated Telnet command.</param>
        /// <param name="authAttempts">The updated authentication attempt count.</param>
        /// <returns>true if the Telnet log was successfully updated; otherwise, false.</returns>
        public static bool Update(int telnetLogId, int logId, string clientIP, string serverIP, string command, int authAttempts)
        {
            return TelnetLogDal.Update(telnetLogId, logId, clientIP, serverIP, command, authAttempts);
        }
    }
}