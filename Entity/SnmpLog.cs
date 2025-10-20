using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for SNMP (Simple Network Management Protocol) activity.
    /// Contains information about the SNMP version, community, OID, value, source and destination IPs, timestamp, session, status, and request type.
    /// </summary>
    internal class SnmpLog
    {
        private int snmpLogId;
        private int logId;
        private string version;
        private string community;
        private string oid;
        private string value;
        private string sourceIP;
        private string destinationIP;
        private DateTime timestamp;
        private string sessionID;
        private string status;
        private string requestType;

        /// <summary>
        /// Gets or sets the unique identifier for this SNMP log entry.
        /// </summary>
        public int SnmpLogId { get => snmpLogId; set => snmpLogId = value; }

        /// <summary>
        /// Gets or sets the associated general log entry ID.
        /// </summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>
        /// Gets or sets the SNMP version used.
        /// </summary>
        public string Version { get => version; set => version = value; }

        /// <summary>
        /// Gets or sets the SNMP community string.
        /// </summary>
        public string Community { get => community; set => community = value; }

        /// <summary>
        /// Gets or sets the Object Identifier (OID) of the SNMP request.
        /// </summary>
        public string OID { get => oid; set => oid = value; }

        /// <summary>
        /// Gets or sets the value associated with the OID.
        /// </summary>
        public string Value { get => this.value; set => this.value = value; }

        /// <summary>
        /// Gets or sets the source IP address of the SNMP message.
        /// </summary>
        public string SourceIP { get => sourceIP; set => sourceIP = value; }

        /// <summary>
        /// Gets or sets the destination IP address of the SNMP message.
        /// </summary>
        public string DestinationIP { get => destinationIP; set => destinationIP = value; }

        /// <summary>
        /// Gets or sets the timestamp when the SNMP log was recorded.
        /// </summary>
        public DateTime Timestamp { get => timestamp; set => timestamp = value; }

        /// <summary>
        /// Gets or sets the session ID for the SNMP communication.
        /// </summary>
        public string SessionID { get => sessionID; set => sessionID = value; }

        /// <summary>
        /// Gets or sets the status of the SNMP request (e.g., success, error).
        /// </summary>
        public string Status { get => status; set => status = value; }

        /// <summary>
        /// Gets or sets the SNMP request type (e.g., GET, SET, TRAP).
        /// </summary>
        public string RequestType { get => requestType; set => requestType = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SnmpLog"/> class with specified values.
        /// </summary>
        internal SnmpLog(int snmpLogId, int logId, string version, string community, string oid, string value,
            string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status, string requestType)
        {
            this.snmpLogId = snmpLogId;
            this.logId = logId;
            this.version = version;
            this.community = community;
            this.oid = oid;
            this.value = value;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.timestamp = timestamp;
            this.sessionID = sessionID;
            this.status = status;
            this.requestType = requestType;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SnmpLog"/> class by copying another instance.
        /// </summary>
        /// <param name="s">The <see cref="SnmpLog"/> instance to copy.</param>
        internal SnmpLog(SnmpLog s) : this(s.snmpLogId, s.logId, s.version, s.community, s.oid, s.value,
            s.sourceIP, s.destinationIP, s.timestamp, s.sessionID, s.status, s.requestType)
        { }

        /// <summary>
        /// Creates a deep copy of the current <see cref="SnmpLog"/> instance.
        /// </summary>
        /// <returns>A new <see cref="SnmpLog"/> object identical to the current instance.</returns>
        public SnmpLog Clone() => new SnmpLog(this);
    }
}
