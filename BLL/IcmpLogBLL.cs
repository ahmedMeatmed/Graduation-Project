using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for ICMP (Internet Control Message Protocol) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for ICMP log-related operations.
    /// </summary>
    internal class IcmpLogBLL
    {
        /// <summary>
        /// Retrieves all ICMP logs from the system.
        /// </summary>
        /// <returns>A collection of IcmpLog objects containing all ICMP logs in the system.</returns>
        public static IcmpLogCollection GetAll()
        {
            return IcmpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific ICMP log by its unique identifier.
        /// </summary>
        /// <param name="id">The IcmpLogID of the ICMP log to retrieve.</param>
        /// <returns>An IcmpLog object if found; otherwise, null.</returns>
        public static IcmpLog GetById(int id)
        {
            return IcmpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new ICMP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="type">The ICMP message type (e.g., 0=Echo Reply, 8=Echo Request, 3=Destination Unreachable).</param>
        /// <param name="code">The ICMP message code that provides additional context for the message type.</param>
        /// <param name="sourceIP">The source IP address of the ICMP packet.</param>
        /// <param name="destIP">The destination IP address of the ICMP packet.</param>
        /// <returns>The newly created IcmpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, int type, int code, string sourceIP, string destIP)
        {
            return IcmpLogDal.Insert(logId, type, code, sourceIP, destIP);
        }

        /// <summary>
        /// Deletes a specific ICMP log from the system.
        /// </summary>
        /// <param name="icmpLogId">The IcmpLogID of the ICMP log to delete.</param>
        /// <returns>true if the ICMP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int icmpLogId)
        {
            return IcmpLogDal.Delete(icmpLogId);
        }

        /// <summary>
        /// Updates an existing ICMP log entry with new information.
        /// </summary>
        /// <param name="icmpLogId">The IcmpLogID of the ICMP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="type">The updated ICMP message type.</param>
        /// <param name="code">The updated ICMP message code.</param>
        /// <param name="sourceIP">The updated source IP address.</param>
        /// <param name="destinationIP">The updated destination IP address.</param>
        /// <returns>true if the ICMP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int icmpLogId, int logId, int type, int code, string sourceIP, string destinationIP)
        {
            return IcmpLogDal.Update(icmpLogId, logId, type, code, sourceIP, destinationIP);
        }
    }
}