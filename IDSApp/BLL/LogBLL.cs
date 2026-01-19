using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using SharpPcap.WinDivert;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for general log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for log-related operations.
    /// </summary>
    internal class LogBLL
    {
        /// <summary>
        /// Retrieves all logs from the system.
        /// </summary>
        /// <returns>A collection of Logs objects containing all logs in the system.</returns>
        public static LogCollection GetAll()
        {
            return DAL.LogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific log by its unique identifier.
        /// </summary>
        /// <param name="id">The LogID of the log to retrieve.</param>
        /// <returns>A Logs object if found; otherwise, null.</returns>
        public static Logs GetById(int id)
        {
            return DAL.LogDal.GetById(id);
        }

        /// <summary>
        /// Retrieves logs based on their timestamp.
        /// </summary>
        /// <param name="timestamp">The timestamp to search for logs.</param>
        /// <returns>A Logs object matching the specified timestamp if found; otherwise, null.</returns>
        public static Logs GetByTimeStamp(DateTime timestamp)
        {
            return DAL.LogDal.GetByTimeStamp(timestamp);
        }

        /// <summary>
        /// Creates a new log entry in the system with comprehensive network traffic details.
        /// </summary>
        /// <param name="timestamp">The date and time when the network event occurred.</param>
        /// <param name="sourceIp">The source IP address of the network traffic.</param>
        /// <param name="destinationIp">The destination IP address of the network traffic.</param>
        /// <param name="packetSize">The size of the packet in bytes.</param>
        /// <param name="isMalicious">Indicates whether the traffic was flagged as malicious.</param>
        /// <param name="protocolName">The name of the network protocol (e.g., HTTP, DNS, SSH).</param>
        /// <param name="protocol">The protocol identifier or number.</param>
        /// <param name="srcPort">The source port number.</param>
        /// <param name="destPort">The destination port number.</param>
        /// <param name="payloadSize">The size of the payload data in bytes.</param>
        /// <param name="tcpFlags">The TCP flags set in the packet (e.g., SYN, ACK, FIN, RST).</param>
        /// <param name="flowDirection">The direction of network flow (e.g., Inbound, Outbound, Internal).</param>
        /// <param name="packetCount">The number of packets in the session or flow.</param>
        /// <param name="duration">The duration of the network session in seconds.</param>
        /// <param name="matchedSignatureId">The ID of the intrusion detection signature that matched this traffic, if any.</param>
        /// <param name="info">Additional information or context about the log entry.</param>
        /// <returns>The newly created LogID if successful; otherwise, -1.</returns>
        public static int Insert(DateTime timestamp,
                                 string sourceIp,
                                 string destinationIp,
                                 double packetSize,
                                 bool isMalicious,
                                 string protocolName,
                                 string protocol,
                                 int srcPort,
                                 int destPort,
                                 double payloadSize,
                                 string tcpFlags,
                                 string flowDirection,
                                 int packetCount,
                                 double duration,
                                 int? matchedSignatureId, string info)
        {
            return DAL.LogDal.Insert(
                timestamp, sourceIp, destinationIp, packetSize, isMalicious,
                protocolName, protocol, srcPort, destPort, payloadSize,
                tcpFlags, flowDirection, packetCount, duration, matchedSignatureId, info
            );
        }

        /// <summary>
        /// Deletes a specific log from the system.
        /// </summary>
        /// <param name="logId">The LogID of the log to delete.</param>
        /// <returns>true if the log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int logId)
        {
            return DAL.LogDal.Delete(logId);
        }
    }
}