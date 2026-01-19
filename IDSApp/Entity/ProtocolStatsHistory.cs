using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents historical statistics for network protocol usage captured by the Intrusion Detection System.
    /// Tracks protocol distribution over time for traffic analysis, anomaly detection, and network behavior monitoring.
    /// </summary>
    internal class ProtocolStatsHistory
    {
        int id;
        string protocol;
        long packetCount;
        long? totalPackets;
        double percentage;
        DateTime recordedAt;

        /// <summary>Unique identifier for the protocol statistics record</summary>
        public int Id { get => id; set => id = value; }

        /// <summary>Network protocol name (e.g., TCP, UDP, HTTP, DNS, FTP, SSH)</summary>
        public string Protocol { get => protocol; set => protocol = value; }

        /// <summary>Number of packets observed for this protocol during the recording period</summary>
        public long PacketCount { get => packetCount; set => packetCount = value; }

        /// <summary>Total number of packets across all protocols during the recording period</summary>
        public long? TotalPackets { get => totalPackets; set => totalPackets = value; }

        /// <summary>Percentage of total traffic represented by this protocol</summary>
        public double Percentage { get => percentage; set => percentage = value; }

        /// <summary>Timestamp when these statistics were recorded</summary>
        public DateTime RecordedAt { get => recordedAt; set => recordedAt = value; }

        /// <summary>
        /// Initializes a new instance of the ProtocolStatsHistory class with specified parameters.
        /// </summary>
        /// <param name="id">Unique identifier for the protocol statistics record</param>
        /// <param name="protocol">Network protocol name</param>
        /// <param name="packetCount">Number of packets for this protocol</param>
        /// <param name="totalPackets">Total packets across all protocols</param>
        /// <param name="percentage">Percentage of total traffic for this protocol</param>
        /// <param name="recordedAt">When these statistics were recorded</param>
        internal ProtocolStatsHistory(int id, string protocol, long packetCount, long? totalPackets, double percentage, DateTime recordedAt)
        {
            this.id = id;
            this.protocol = protocol;
            this.packetCount = packetCount;
            this.totalPackets = totalPackets;
            this.percentage = percentage;
            this.recordedAt = recordedAt;
        }

        /// <summary>
        /// Initializes a new instance of the ProtocolStatsHistory class as a copy of an existing ProtocolStatsHistory object.
        /// </summary>
        /// <param name="p">Source ProtocolStatsHistory object to copy from</param>
        internal ProtocolStatsHistory(ProtocolStatsHistory p) : this(p.id, p.protocol, p.packetCount, p.totalPackets, p.percentage, p.recordedAt) { }

        /// <summary>
        /// Creates a deep copy of the current ProtocolStatsHistory instance.
        /// </summary>
        /// <returns>A new ProtocolStatsHistory object that is an exact copy of the current instance</returns>
        public ProtocolStatsHistory Clone() => new ProtocolStatsHistory(this);
    }
}
