using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for NetBIOS (Network Basic Input/Output System) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for NetBIOS log-related operations.
    /// </summary>
    internal class NetbiosLogBLL
    {
        /// <summary>
        /// Retrieves all NetBIOS logs from the system.
        /// </summary>
        /// <returns>A collection of NetbiosLog objects containing all NetBIOS logs in the system.</returns>
        public static NetbiosLogCollection GetAll()
        {
            return NetbiosLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific NetBIOS log by its unique identifier.
        /// </summary>
        /// <param name="id">The NetbiosLogID of the NetBIOS log to retrieve.</param>
        /// <returns>A NetbiosLog object if found; otherwise, null.</returns>
        public static NetbiosLog GetById(int id)
        {
            return NetbiosLogDal.GetById(id);
        }

        /// <summary>
        /// Retrieves a NetBIOS log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated NetBIOS logs.</param>
        /// <returns>A NetbiosLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static NetbiosLog GetByLogId(int logId)
        {
            return NetbiosLogDal.GetByLogId(logId);
        }

        /// <summary>
        /// Creates a new NetBIOS log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="queryName">The NetBIOS name being queried (e.g., computer name, domain name).</param>
        /// <param name="queryType">The type of NetBIOS query (e.g., Name Query, Name Registration, Name Release).</param>
        /// <param name="response">The response received from the NetBIOS name server.</param>
        /// <param name="responderIP">The IP address of the system that responded to the NetBIOS query.</param>
        /// <param name="sourceIP">The source IP address of the NetBIOS query.</param>
        /// <param name="destinationIP">The destination IP address of the NetBIOS query.</param>
        /// <param name="timestamp">The date and time when the NetBIOS query occurred.</param>
        /// <param name="sessionID">The session identifier for the NetBIOS transaction.</param>
        /// <param name="status">The status of the NetBIOS operation (e.g., Success, Failed, Timeout).</param>
        /// <returns>The newly created NetbiosLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string queryName, string queryType, string response, string responderIP,
                                 string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status)
        {
            return NetbiosLogDal.Insert(logId, queryName, queryType, response, responderIP, sourceIP, destinationIP, timestamp, sessionID, status);
        }

        /// <summary>
        /// Updates an existing NetBIOS log entry with new information.
        /// </summary>
        /// <param name="netbiosLogId">The NetbiosLogID of the NetBIOS log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="queryName">The updated NetBIOS query name.</param>
        /// <param name="queryType">The updated NetBIOS query type.</param>
        /// <param name="response">The updated response from the NetBIOS name server.</param>
        /// <param name="responderIP">The updated responder IP address.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated operation status.</param>
        /// <returns>true if the NetBIOS log was successfully updated; otherwise, false.</returns>
        public static bool Update(int netbiosLogId, int logId, string queryName, string queryType, string response, string responderIP,
                                  string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status)
        {
            return NetbiosLogDal.Update(netbiosLogId, logId, queryName, queryType, response, responderIP, sourceIP, destinationIP, timestamp, sessionID, status);
        }

        /// <summary>
        /// Deletes a specific NetBIOS log from the system.
        /// </summary>
        /// <param name="netbiosLogId">The NetbiosLogID of the NetBIOS log to delete.</param>
        /// <returns>true if the NetBIOS log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int netbiosLogId)
        {
            return NetbiosLogDal.Delete(netbiosLogId);
        }
    }
}