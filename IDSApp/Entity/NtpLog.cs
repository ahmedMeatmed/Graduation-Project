using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an NTP (Network Time Protocol) log entry captured by the Intrusion Detection System.
    /// Contains detailed information about time synchronization operations for monitoring time protocol usage
    /// and detecting potential NTP-based attacks, amplification attacks, or time manipulation attempts.
    /// </summary>
    internal class NtpLog
    {
        int ntpLogId;
        int logId;
        string version;
        string mode;
        int stratum;
        DateTime transmitTimestamp;
        string sourceIP;
        string destinationIP;
        DateTime timestamp;
        string sessionID;
        string status;
        decimal offset;

        /// <summary>Unique identifier for the NTP log entry</summary>
        public int NtpLogId { get => ntpLogId; set => ntpLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>NTP protocol version (e.g., 3, 4)</summary>
        public string Version { get => version; set => version = value; }

        /// <summary>NTP mode of operation (e.g., client, server, broadcast, symmetric)</summary>
        public string Mode { get => mode; set => mode = value; }

        /// <summary>Stratum level indicating distance from reference clock (1=primary, 2=secondary, etc.)</summary>
        public int Stratum { get => stratum; set => stratum = value; }

        /// <summary>Timestamp when the NTP packet was transmitted</summary>
        public DateTime TransmitTimestamp { get => transmitTimestamp; set => transmitTimestamp = value; }

        /// <summary>Source IP address of the NTP client or server</summary>
        public string SourceIP { get => sourceIP; set => sourceIP = value; }

        /// <summary>Destination IP address of the NTP server or client</summary>
        public string DestinationIP { get => destinationIP; set => destinationIP = value; }

        /// <summary>Timestamp when the NTP packet was captured by the IDS</summary>
        public DateTime Timestamp { get => timestamp; set => timestamp = value; }

        /// <summary>Unique session identifier for tracking NTP conversations</summary>
        public string SessionID { get => sessionID; set => sessionID = value; }

        /// <summary>Operation status (e.g., Success, Failed, Spoofed, Amplification)</summary>
        public string Status { get => status; set => status = value; }

        /// <summary>Time offset between client and server in milliseconds or seconds</summary>
        public decimal Offset { get => offset; set => offset = value; }

        /// <summary>
        /// Initializes a new instance of the NtpLog class with specified parameters.
        /// </summary>
        /// <param name="ntpLogId">Unique identifier for the NTP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="version">NTP protocol version</param>
        /// <param name="mode">NTP mode of operation</param>
        /// <param name="stratum">Stratum level indicating distance from reference clock</param>
        /// <param name="transmitTimestamp">Timestamp when the NTP packet was transmitted</param>
        /// <param name="sourceIP">Source IP address of the NTP client or server</param>
        /// <param name="destinationIP">Destination IP address of the NTP server or client</param>
        /// <param name="timestamp">When the NTP packet was captured by the IDS</param>
        /// <param name="sessionID">Unique session identifier for tracking conversations</param>
        /// <param name="status">Operation status</param>
        /// <param name="offset">Time offset between client and server</param>
        internal NtpLog(int ntpLogId, int logId, string version, string mode, int stratum, DateTime transmitTimestamp,
            string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status, decimal offset)
        {
            this.ntpLogId = ntpLogId;
            this.logId = logId;
            this.version = version;
            this.mode = mode;
            this.stratum = stratum;
            this.transmitTimestamp = transmitTimestamp;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.timestamp = timestamp;
            this.sessionID = sessionID;
            this.status = status;
            this.offset = offset;
        }

        /// <summary>
        /// Initializes a new instance of the NtpLog class as a copy of an existing NtpLog object.
        /// </summary>
        /// <param name="n">Source NtpLog object to copy from</param>
        internal NtpLog(NtpLog n) : this(n.ntpLogId, n.logId, n.version, n.mode, n.stratum,
            n.transmitTimestamp, n.sourceIP, n.destinationIP, n.timestamp, n.sessionID, n.status, n.offset)
        { }

        /// <summary>
        /// Creates a deep copy of the current NtpLog instance.
        /// </summary>
        /// <returns>A new NtpLog object that is an exact copy of the current instance</returns>
        public NtpLog Clone() => new NtpLog(this);
    }
}