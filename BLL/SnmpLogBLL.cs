using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for SNMP (Simple Network Management Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for SNMP log-related operations.
    /// </summary>
    internal class SnmpLogBLL
    {
        /// <summary>
        /// Retrieves all SNMP logs from the system.
        /// </summary>
        /// <returns>A collection of SnmpLog objects containing all SNMP logs in the system.</returns>
        public static SnmpLogCollection GetAll()
        {
            return SnmpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific SNMP log by its unique identifier.
        /// </summary>
        /// <param name="id">The SnmpLogID of the SNMP log to retrieve.</param>
        /// <returns>An SnmpLog object if found; otherwise, null.</returns>
        public static SnmpLog GetById(int id)
        {
            return SnmpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new SNMP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="version">The SNMP protocol version (e.g., SNMPv1, SNMPv2c, SNMPv3).</param>
        /// <param name="community">The SNMP community string used for authentication.</param>
        /// <param name="oid">The Object Identifier (OID) being accessed or modified.</param>
        /// <param name="value">The value associated with the OID in the SNMP operation.</param>
        /// <param name="sourceIP">The source IP address of the SNMP client.</param>
        /// <param name="destinationIP">The destination IP address of the SNMP agent.</param>
        /// <param name="timestamp">The date and time when the SNMP operation occurred.</param>
        /// <param name="sessionID">The session identifier for the SNMP transaction.</param>
        /// <param name="status">The status of the SNMP operation (e.g., Success, Failed, Timeout).</param>
        /// <param name="requestType">The type of SNMP request (e.g., GET, GETNEXT, SET, TRAP, INFORM).</param>
        /// <returns>The newly created SnmpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string version, string community, string oid, string value,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, string requestType)
        {
            return SnmpLogDal.Insert(logId, version, community, oid, value, sourceIP, destinationIP, timestamp, sessionID, status, requestType);
        }

        /// <summary>
        /// Updates an existing SNMP log entry with new information.
        /// </summary>
        /// <param name="snmpLogId">The SnmpLogID of the SNMP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="version">The updated SNMP protocol version.</param>
        /// <param name="community">The updated community string.</param>
        /// <param name="oid">The updated Object Identifier.</param>
        /// <param name="value">The updated OID value.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <param name="requestType">The updated request type.</param>
        /// <returns>true if the SNMP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int snmpLogId, int logId, string version, string community, string oid, string value,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, string requestType)
        {
            return SnmpLogDal.Update(snmpLogId, logId, version, community, oid, value, sourceIP, destinationIP, timestamp, sessionID, status, requestType);
        }

        /// <summary>
        /// Deletes a specific SNMP log from the system.
        /// </summary>
        /// <param name="snmpLogId">The SnmpLogID of the SNMP log to delete.</param>
        /// <returns>true if the SNMP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int snmpLogId)
        {
            return SnmpLogDal.Delete(snmpLogId);
        }

        /// <summary>
        /// Retrieves an SNMP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated SNMP logs.</param>
        /// <returns>An SnmpLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static SnmpLog GetByLogId(int logId)
        {
            return SnmpLogDal.GetByLogId(logId);
        }
    }
}