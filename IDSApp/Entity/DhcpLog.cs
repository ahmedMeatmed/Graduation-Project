using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a DHCP (Dynamic Host Configuration Protocol) log entry captured by the Intrusion Detection System.
    /// Contains detailed information about DHCP network transactions for monitoring IP address allocation and potential network threats.
    /// </summary>
    public class DhcpLog
    {
        /// <summary>Unique identifier for the DHCP log entry</summary>
        public int DhcpLogId { get; set; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get; set; }

        /// <summary>DHCP message type (e.g., DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE)</summary>
        public string MessageType { get; set; }

        /// <summary>Unique transaction ID to correlate DHCP request-response pairs</summary>
        public string TransactionId { get; set; }

        /// <summary>Current IP address of the DHCP client (may be 0.0.0.0 for initial requests)</summary>
        public string ClientIp { get; set; }

        /// <summary>IP address being offered or assigned to the client</summary>
        public string OfferedIp { get; set; }

        /// <summary>IP address of the DHCP server handling the request</summary>
        public string ServerIp { get; set; }

        /// <summary>Source IP address of the DHCP packet</summary>
        public string SourceIp { get; set; }

        /// <summary>Destination IP address of the DHCP packet</summary>
        public string DestinationIp { get; set; }

        /// <summary>Timestamp when the DHCP transaction occurred</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Session identifier for tracking DHCP conversations</summary>
        public string SessionId { get; set; }

        /// <summary>Transaction status (e.g., Success, Failed, Pending, Error)</summary>
        public string Status { get; set; }

        /// <summary>Duration of the IP address lease in seconds</summary>
        public int LeaseDuration { get; set; }

        /// <summary>
        /// Initializes a new instance of the DhcpLog class with default values.
        /// </summary>
        public DhcpLog() { }

        /// <summary>
        /// Initializes a new instance of the DhcpLog class with specified parameters.
        /// </summary>
        /// <param name="dhcpLogId">Unique identifier for the DHCP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="messageType">DHCP message type</param>
        /// <param name="transactionId">Unique transaction ID for request-response correlation</param>
        /// <param name="clientIp">Current IP address of the DHCP client</param>
        /// <param name="offeredIp">IP address being offered or assigned</param>
        /// <param name="serverIp">IP address of the DHCP server</param>
        /// <param name="sourceIp">Source IP address of the DHCP packet</param>
        /// <param name="destinationIp">Destination IP address of the DHCP packet</param>
        /// <param name="timestamp">When the DHCP transaction occurred</param>
        /// <param name="sessionId">Session identifier for tracking conversations</param>
        /// <param name="status">Transaction status</param>
        /// <param name="leaseDuration">Duration of IP address lease in seconds</param>
        public DhcpLog(int dhcpLogId, int logId, string messageType, string transactionId,
                       string clientIp, string offeredIp, string serverIp, string sourceIp,
                       string destinationIp, DateTime timestamp, string sessionId, string status,
                       int leaseDuration)
        {
            DhcpLogId = dhcpLogId;
            LogId = logId;
            MessageType = messageType;
            TransactionId = transactionId;
            ClientIp = clientIp;
            OfferedIp = offeredIp;
            ServerIp = serverIp;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            Timestamp = timestamp;
            SessionId = sessionId;
            Status = status;
            LeaseDuration = leaseDuration;
        }

        /// <summary>
        /// Initializes a new instance of the DhcpLog class as a copy of an existing DhcpLog object.
        /// </summary>
        /// <param name="d">Source DhcpLog object to copy from</param>
        public DhcpLog(DhcpLog d) : this(d.DhcpLogId, d.LogId, d.MessageType, d.TransactionId,
                                         d.ClientIp, d.OfferedIp, d.ServerIp, d.SourceIp,
                                         d.DestinationIp, d.Timestamp, d.SessionId, d.Status,
                                         d.LeaseDuration)
        { }

        /// <summary>
        /// Creates a deep copy of the current DhcpLog instance.
        /// </summary>
        /// <returns>A new DhcpLog object that is an exact copy of the current instance</returns>
        public DhcpLog Clone() => new DhcpLog(this);
    }
}