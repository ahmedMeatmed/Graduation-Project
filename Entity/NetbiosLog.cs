using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a NetBIOS (Network Basic Input/Output System) log entry captured by the Intrusion Detection System.
    /// Contains information about NetBIOS name resolution and service discovery operations for monitoring
    /// Windows network browsing, host discovery, and detecting network reconnaissance activities.
    /// </summary>
    public class NetbiosLog
    {
        /// <summary>Unique identifier for the NetBIOS log entry</summary>
        public int NetbiosLogId { get; set; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get; set; }

        /// <summary>NetBIOS name being queried or resolved</summary>
        public string QueryName { get; set; }

        /// <summary>Type of NetBIOS query (e.g., NBSTAT, NBTNAME, SESSION, DATAGRAM)</summary>
        public string QueryType { get; set; }

        /// <summary>Response data from the NetBIOS query, including resolved names and services</summary>
        public string Response { get; set; }

        /// <summary>IP address of the system responding to the NetBIOS query</summary>
        public string ResponderIp { get; set; }

        /// <summary>Source IP address initiating the NetBIOS query</summary>
        public string SourceIp { get; set; }

        /// <summary>Destination IP address for the NetBIOS query (often broadcast address)</summary>
        public string DestinationIp { get; set; }

        /// <summary>Timestamp when the NetBIOS operation occurred</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Unique session identifier for tracking NetBIOS conversations</summary>
        public string SessionId { get; set; }

        /// <summary>Operation status (e.g., Success, Failed, Timeout, NoResponse)</summary>
        public string Status { get; set; }

        /// <summary>
        /// Initializes a new instance of the NetbiosLog class with default values.
        /// </summary>
        public NetbiosLog() { }

        /// <summary>
        /// Initializes a new instance of the NetbiosLog class with specified parameters.
        /// </summary>
        /// <param name="netbiosLogId">Unique identifier for the NetBIOS log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="queryName">NetBIOS name being queried or resolved</param>
        /// <param name="queryType">Type of NetBIOS query</param>
        /// <param name="response">Response data from the NetBIOS query</param>
        /// <param name="responderIp">IP address of the system responding to the query</param>
        /// <param name="sourceIp">Source IP address initiating the query</param>
        /// <param name="destinationIp">Destination IP address for the query</param>
        /// <param name="timestamp">When the NetBIOS operation occurred</param>
        /// <param name="sessionId">Unique session identifier for tracking conversations</param>
        /// <param name="status">Operation status</param>
        public NetbiosLog(int netbiosLogId, int logId, string queryName, string queryType,
                          string response, string responderIp, string sourceIp, string destinationIp,
                          DateTime timestamp, string sessionId, string status)
        {
            NetbiosLogId = netbiosLogId;
            LogId = logId;
            QueryName = queryName;
            QueryType = queryType;
            Response = response;
            ResponderIp = responderIp;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            Timestamp = timestamp;
            SessionId = sessionId;
            Status = status;
        }

        /// <summary>
        /// Initializes a new instance of the NetbiosLog class as a copy of an existing NetbiosLog object.
        /// </summary>
        /// <param name="n">Source NetbiosLog object to copy from</param>
        public NetbiosLog(NetbiosLog n) : this(n.NetbiosLogId, n.LogId, n.QueryName, n.QueryType,
                                               n.Response, n.ResponderIp, n.SourceIp, n.DestinationIp,
                                               n.Timestamp, n.SessionId, n.Status)
        { }

        /// <summary>
        /// Creates a deep copy of the current NetbiosLog instance.
        /// </summary>
        /// <returns>A new NetbiosLog object that is an exact copy of the current instance</returns>
        public NetbiosLog Clone() => new NetbiosLog(this);
    }
}