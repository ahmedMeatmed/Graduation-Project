using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for LDAP (Lightweight Directory Access Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for LDAP log-related operations.
    /// </summary>
    internal class LdapLogBLL
    {
        /// <summary>
        /// Retrieves all LDAP logs from the system.
        /// </summary>
        /// <returns>A collection of LdapLog objects containing all LDAP logs in the system.</returns>
        public static LdapLogCollection GetAll()
        {
            return LdapLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific LDAP log by its unique identifier.
        /// </summary>
        /// <param name="id">The LdapLogID of the LDAP log to retrieve.</param>
        /// <returns>An LdapLog object if found; otherwise, null.</returns>
        public static LdapLog GetById(int id)
        {
            return LdapLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new LDAP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="operation">The LDAP operation performed (e.g., Bind, Search, Add, Modify, Delete).</param>
        /// <param name="distinguishedName">The Distinguished Name (DN) of the directory object being accessed.</param>
        /// <param name="resultCode">The LDAP result code indicating the operation outcome (e.g., 0=Success, 49=Invalid Credentials).</param>
        /// <param name="sourceIP">The source IP address of the LDAP client.</param>
        /// <param name="destinationIP">The destination IP address of the LDAP server.</param>
        /// <param name="timestamp">The date and time when the LDAP operation occurred.</param>
        /// <param name="sessionID">The session identifier for the LDAP connection.</param>
        /// <param name="status">The status of the LDAP operation (e.g., Success, Failed, Partial).</param>
        /// <returns>The newly created LdapLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string operation, string distinguishedName, string resultCode,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status)
        {
            return LdapLogDal.Insert(logId, operation, distinguishedName, resultCode, sourceIP, destinationIP, timestamp, sessionID, status);
        }

        /// <summary>
        /// Updates an existing LDAP log entry with new information.
        /// </summary>
        /// <param name="ldapLogId">The LdapLogID of the LDAP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="operation">The updated LDAP operation.</param>
        /// <param name="distinguishedName">The updated Distinguished Name.</param>
        /// <param name="resultCode">The updated LDAP result code.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <returns>true if the LDAP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int ldapLogId, int logId, string operation, string distinguishedName, string resultCode,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status)
        {
            return LdapLogDal.Update(ldapLogId, logId, operation, distinguishedName, resultCode, sourceIP, destinationIP, timestamp, sessionID, status);
        }

        /// <summary>
        /// Deletes a specific LDAP log from the system.
        /// </summary>
        /// <param name="ldapLogId">The LdapLogID of the LDAP log to delete.</param>
        /// <returns>true if the LDAP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int ldapLogId)
        {
            return LdapLogDal.Delete(ldapLogId);
        }

        /// <summary>
        /// Retrieves an LDAP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated LDAP logs.</param>
        /// <returns>An LdapLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static LdapLog GetByLogId(int logId)
        {
            return LdapLogDal.GetByLogId(logId);
        }
    }
}