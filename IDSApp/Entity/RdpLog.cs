using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an RDP (Remote Desktop Protocol) log entry captured by the Intrusion Detection System.
    /// Contains information about remote desktop connections for monitoring remote access,
    /// detecting brute force attacks, and identifying unauthorized remote access attempts.
    /// </summary>
    internal class RdpLog
    {
        int rdpLogId;
        int logId;
        string clientIP;
        string serverIP;
        string sessionID;
        int authAttempts;

        /// <summary>Unique identifier for the RDP log entry</summary>
        public int RdpLogId { get => rdpLogId; set => rdpLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>IP address of the RDP client initiating the connection</summary>
        public string ClientIP { get => clientIP; set => clientIP = value; }

        /// <summary>IP address of the RDP server (remote desktop host)</summary>
        public string ServerIP { get => serverIP; set => serverIP = value; }

        /// <summary>Unique session identifier for the RDP connection</summary>
        public string SessionID { get => sessionID; set => sessionID = value; }

        /// <summary>Number of authentication attempts made during the connection</summary>
        public int AuthAttempts { get => authAttempts; set => authAttempts = value; }

        /// <summary>
        /// Initializes a new instance of the RdpLog class with specified parameters.
        /// </summary>
        /// <param name="rdpLogId">Unique identifier for the RDP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="clientIP">IP address of the RDP client</param>
        /// <param name="serverIP">IP address of the RDP server</param>
        /// <param name="sessionID">Unique session identifier for the connection</param>
        /// <param name="authAttempts">Number of authentication attempts made</param>
        internal RdpLog(int rdpLogId, int logId, string clientIP, string serverIP, string sessionID, int authAttempts)
        {
            this.rdpLogId = rdpLogId;
            this.logId = logId;
            this.clientIP = clientIP;
            this.serverIP = serverIP;
            this.sessionID = sessionID;
            this.authAttempts = authAttempts;
        }

        /// <summary>
        /// Initializes a new instance of the RdpLog class as a copy of an existing RdpLog object.
        /// </summary>
        /// <param name="r">Source RdpLog object to copy from</param>
        internal RdpLog(RdpLog r) : this(r.rdpLogId, r.logId, r.clientIP, r.serverIP, r.sessionID, r.authAttempts) { }

        /// <summary>
        /// Creates a deep copy of the current RdpLog instance.
        /// </summary>
        /// <returns>A new RdpLog object that is an exact copy of the current instance</returns>
        public RdpLog Clone() => new RdpLog(this);
    }
}