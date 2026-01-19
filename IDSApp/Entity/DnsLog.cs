using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a DNS (Domain Name System) log entry captured by the Intrusion Detection System.
    /// Contains information about DNS queries and responses for monitoring domain resolution activities
    /// and detecting potential DNS-based attacks or suspicious domain lookups.
    /// </summary>
    internal class DnsLog
    {
        int dnsLogId;
        int logId;
        string query;
        string queryType;
        string response;
        int ttl;
        string recordType;
        /// <summary>Unique identifier for the DNS log entry</summary>
        public int DnsLogId { get => dnsLogId; set => dnsLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>Domain name or hostname that was queried in the DNS request</summary>
        public string Query { get => query; set => query = value; }

        /// <summary>Type of DNS query (e.g., A, AAAA, CNAME, MX, TXT, PTR, NS)</summary>
        public string QueryType { get => queryType; set => queryType = value; }

        /// <summary>DNS server response to the query, including resolved IP addresses or error codes</summary>
        public string Response { get => response; set => response = value; }


        public int TTL { get => ttl; set => ttl = value; }


        public string RecordType { get => recordType; set => recordType = value; }

        /// <summary>
        /// Initializes a new instance of the DnsLog class with specified parameters.
        /// </summary>
        /// <param name="dnsLogId">Unique identifier for the DNS log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="query">Domain name or hostname that was queried</param>
        /// <param name="queryType">Type of DNS query</param>
        /// <param name="response">DNS server response including resolved addresses</param>
        internal DnsLog(int dnsLogId, int logId, string query, string queryType, string response,int ttl,string recordType)
        {
            this.dnsLogId = dnsLogId;
            this.logId = logId;
            this.query = query;
            this.queryType = queryType;
            this.response = response;
            this.ttl = ttl;this.recordType = recordType;
        }

        /// <summary>
        /// Initializes a new instance of the DnsLog class as a copy of an existing DnsLog object.
        /// </summary>
        /// <param name="d">Source DnsLog object to copy from</param>
        internal DnsLog(DnsLog d)
            : this(d.dnsLogId, d.logId, d.query, d.queryType, d.response,d.ttl,d.recordType) { }

        /// <summary>
        /// Creates a deep copy of the current DnsLog instance.
        /// </summary>
        /// <returns>A new DnsLog object that is an exact copy of the current instance</returns>
        public DnsLog Clone() => new DnsLog(this);
    }
}