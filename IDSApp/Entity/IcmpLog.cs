using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an ICMP (Internet Control Message Protocol) log entry captured by the Intrusion Detection System.
    /// Contains information about ICMP packets for monitoring network diagnostics, host discovery,
    /// and detecting potential network reconnaissance or denial-of-service attacks.
    /// </summary>
    internal class IcmpLog
    {
        int icmpLogId;
        int logId;
        int type;
        int code;
        string sourceIP;
        string destinationIP;

        /// <summary>Unique identifier for the ICMP log entry</summary>
        public int IcmpLogId { get => icmpLogId; set => icmpLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>ICMP message type (e.g., 0=Echo Reply, 3=Destination Unreachable, 8=Echo Request, 11=Time Exceeded)</summary>
        public int Type { get => type; set => type = value; }

        /// <summary>ICMP code providing additional context for the message type</summary>
        public int Code { get => code; set => code = value; }

        /// <summary>Source IP address of the ICMP packet</summary>
        public string SourceIP { get => sourceIP; set => sourceIP = value; }

        /// <summary>Destination IP address of the ICMP packet</summary>
        public string DestinationIP { get => destinationIP; set => destinationIP = value; }

        /// <summary>
        /// Initializes a new instance of the IcmpLog class with specified parameters.
        /// </summary>
        /// <param name="icmpLogId">Unique identifier for the ICMP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="type">ICMP message type</param>
        /// <param name="code">ICMP code providing additional context</param>
        /// <param name="sourceIP">Source IP address of the ICMP packet</param>
        /// <param name="destinationIP">Destination IP address of the ICMP packet</param>
        internal IcmpLog(int icmpLogId, int logId, int type, int code, string sourceIP, string destinationIP)
        {
            this.icmpLogId = icmpLogId;
            this.logId = logId;
            this.type = type;
            this.code = code;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
        }

        /// <summary>
        /// Initializes a new instance of the IcmpLog class as a copy of an existing IcmpLog object.
        /// </summary>
        /// <param name="i">Source IcmpLog object to copy from</param>
        internal IcmpLog(IcmpLog i) : this(i.icmpLogId, i.logId, i.type, i.code, i.sourceIP, i.destinationIP) { }

        /// <summary>
        /// Creates a deep copy of the current IcmpLog instance.
        /// </summary>
        /// <returns>A new IcmpLog object that is an exact copy of the current instance</returns>
        public IcmpLog Clone() => new IcmpLog(this);
    }
}