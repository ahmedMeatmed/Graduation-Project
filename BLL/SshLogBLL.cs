using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for SSH (Secure Shell) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for SSH log-related operations.
    /// </summary>
    internal class SshLogBLL
    {
        /// <summary>
        /// Retrieves all SSH logs from the system.
        /// </summary>
        /// <returns>A collection of SshLog objects containing all SSH logs in the system.</returns>
        public static SshLogCollection GetAll()
        {
            return SshLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific SSH log by its unique identifier.
        /// </summary>
        /// <param name="id">The SshLogID of the SSH log to retrieve.</param>
        /// <returns>An SshLog object if found; otherwise, null.</returns>
        public static SshLog GetById(int id)
        {
            return SshLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new SSH log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="clientVersion">The SSH client version string used in the connection.</param>
        /// <param name="serverVersion">The SSH server version string used in the connection.</param>
        /// <param name="authAttempts">The number of authentication attempts made during the SSH session.</param>
        /// <returns>The newly created SshLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string clientVersion, string serverVersion, int authAttempts)
        {
            return SshLogDal.Insert(logId, clientVersion, serverVersion, authAttempts);
        }

        /// <summary>
        /// Deletes a specific SSH log from the system.
        /// </summary>
        /// <param name="sshLogId">The SshLogID of the SSH log to delete.</param>
        /// <returns>true if the SSH log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int sshLogId)
        {
            return SshLogDal.Delete(sshLogId);
        }

        /// <summary>
        /// Updates an existing SSH log entry with new information.
        /// </summary>
        /// <param name="sshLogId">The SshLogID of the SSH log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="clientVersion">The updated SSH client version.</param>
        /// <param name="serverVersion">The updated SSH server version.</param>
        /// <param name="authAttempts">The updated authentication attempt count.</param>
        /// <returns>true if the SSH log was successfully updated; otherwise, false.</returns>
        public static bool Update(int sshLogId, int logId, string clientVersion, string serverVersion, int authAttempts)
        {
            return SshLogDal.Update(sshLogId, logId, clientVersion, serverVersion, authAttempts);
        }

        /// <summary>
        /// Retrieves an SSH log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated SSH logs.</param>
        /// <returns>An SshLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static SshLog GetByLogId(int logId)
        {
            return SshLogDal.GetByLogId(logId);
        }
    }
}