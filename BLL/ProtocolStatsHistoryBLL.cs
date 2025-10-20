using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for protocol statistics history management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for protocol statistics history operations.
    /// </summary>
    internal class ProtocolStatsHistoryBLL
    {
        /// <summary>
        /// Retrieves all protocol statistics history records from the system.
        /// </summary>
        /// <returns>A collection of ProtocolStatsHistory objects containing all protocol statistics history records in the system.</returns>
        public static ProtocolStatsHistoryCollection GetAll()
        {
            return ProtocolStatsHistoryDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific protocol statistics history record by its unique identifier.
        /// </summary>
        /// <param name="id">The ID of the protocol statistics history record to retrieve.</param>
        /// <returns>A ProtocolStatsHistory object if found; otherwise, null.</returns>
        public static ProtocolStatsHistory GetById(int id)
        {
            return ProtocolStatsHistoryDal.GetById(id);
        }

        /// <summary>
        /// Creates a new protocol statistics history record in the system.
        /// </summary>
        /// <param name="protocol">The network protocol name (e.g., TCP, UDP, HTTP, DNS, SSH).</param>
        /// <param name="packetCount">The number of packets observed for this protocol during the recording period.</param>
        /// <param name="totalPackets">The total number of packets across all protocols during the recording period.</param>
        /// <param name="percentage">The percentage of total network traffic represented by this protocol.</param>
        /// <param name="recordedAt">The date and time when these statistics were recorded.</param>
        /// <returns>The newly created record ID if successful; otherwise, -1.</returns>
        public static int Insert(string protocol, long packetCount, long? totalPackets, double percentage, DateTime recordedAt)
        {
            return ProtocolStatsHistoryDal.Insert(protocol, packetCount, totalPackets, percentage, recordedAt);
        }

        /// <summary>
        /// Updates an existing protocol statistics history record with new information.
        /// </summary>
        /// <param name="id">The ID of the protocol statistics history record to update.</param>
        /// <param name="protocol">The updated network protocol name.</param>
        /// <param name="packetCount">The updated packet count for this protocol.</param>
        /// <param name="totalPackets">The updated total packet count across all protocols.</param>
        /// <param name="percentage">The updated percentage of total network traffic.</param>
        /// <param name="recordedAt">The updated recording timestamp.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int id, string protocol, long packetCount, long? totalPackets, double percentage, DateTime recordedAt)
        {
            return ProtocolStatsHistoryDal.Update(id, protocol, packetCount, totalPackets, percentage, recordedAt);
        }

        /// <summary>
        /// Deletes a specific protocol statistics history record from the system.
        /// </summary>
        /// <param name="id">The ID of the protocol statistics history record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int id)
        {
            return ProtocolStatsHistoryDal.Delete(id);
        }
    }
}