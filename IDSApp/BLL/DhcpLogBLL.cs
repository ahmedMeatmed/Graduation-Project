using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for DHCP (Dynamic Host Configuration Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for DHCP log-related operations.
    /// </summary>
    internal class DhcpLogBLL
    {
        /// <summary>
        /// Retrieves all DHCP logs from the system.
        /// </summary>
        /// <returns>A collection of DhcpLog objects containing all DHCP logs in the system.</returns>
        public static DhcpLogCollection GetAll()
        {
            return DhcpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific DHCP log by its unique identifier.
        /// </summary>
        /// <param name="id">The DhcpLogID of the DHCP log to retrieve.</param>
        /// <returns>A DhcpLog object if found; otherwise, null.</returns>
        public static DhcpLog GetById(int id)
        {
            return DhcpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new DHCP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="messageType">The DHCP message type (e.g., DISCOVER, OFFER, REQUEST, ACK, NAK).</param>
        /// <param name="transactionID">The unique transaction identifier for the DHCP exchange.</param>
        /// <param name="clientIP">The current IP address of the DHCP client.</param>
        /// <param name="offeredIP">The IP address offered by the DHCP server.</param>
        /// <param name="serverIP">The IP address of the DHCP server.</param>
        /// <param name="sourceIP">The source IP address of the DHCP packet.</param>
        /// <param name="destinationIP">The destination IP address of the DHCP packet.</param>
        /// <param name="timestamp">The date and time when the DHCP transaction occurred.</param>
        /// <param name="sessionID">The session identifier for the DHCP transaction.</param>
        /// <param name="status">The status of the DHCP transaction (e.g., Success, Failed, In Progress).</param>
        /// <param name="leaseDuration">The duration of the IP address lease in seconds.</param>
        /// <returns>The newly created DhcpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string messageType, string transactionID, string clientIP, string offeredIP,
                                 string serverIP, string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, int leaseDuration)
        {
            return DhcpLogDal.Insert(logId, messageType, transactionID, clientIP, offeredIP, serverIP, sourceIP, destinationIP, timestamp, sessionID, status, leaseDuration);
        }

        /// <summary>
        /// Updates an existing DHCP log entry with new information.
        /// </summary>
        /// <param name="dhcpLogId">The DhcpLogID of the DHCP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="messageType">The updated DHCP message type.</param>
        /// <param name="transactionID">The updated transaction identifier.</param>
        /// <param name="clientIP">The updated client IP address.</param>
        /// <param name="offeredIP">The updated offered IP address.</param>
        /// <param name="serverIP">The updated DHCP server IP address.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <param name="timestamp">The updated timestamp.</param>
        /// <param name="sessionID">The updated session identifier.</param>
        /// <param name="status">The updated transaction status.</param>
        /// <param name="leaseDuration">The updated lease duration in seconds.</param>
        /// <returns>true if the DHCP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int dhcpLogId, int logId, string messageType, string transactionID, string clientIP, string offeredIP,
                                  string serverIP, string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, int leaseDuration)
        {
            return DhcpLogDal.Update(dhcpLogId, logId, messageType, transactionID, clientIP, offeredIP, serverIP, sourceIP, destinationIP, timestamp, sessionID, status, leaseDuration);
        }

        /// <summary>
        /// Deletes a specific DHCP log from the system.
        /// </summary>
        /// <param name="dhcpLogId">The DhcpLogID of the DHCP log to delete.</param>
        /// <returns>true if the DHCP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int dhcpLogId)
        {
            return DhcpLogDal.Delete(dhcpLogId);
        }

        /// <summary>
        /// Retrieves a DHCP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for associated DHCP logs.</param>
        /// <returns>A DhcpLog object associated with the specified log entry if found; otherwise, null.</returns>
        public static DhcpLog GetByLogId(int logId)
        {
            return DhcpLogDal.GetByLogId(logId);
        }
    }
}