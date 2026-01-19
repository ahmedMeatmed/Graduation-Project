using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an LDAP (Lightweight Directory Access Protocol) log entry captured by the Intrusion Detection System.
    /// Contains detailed information about directory service operations for monitoring authentication,
    /// directory queries, and detecting unauthorized access attempts or directory service attacks.
    /// </summary>
    public class LdapLog
    {
        /// <summary>Unique identifier for the LDAP log entry</summary>
        public int LdapLogId { get; set; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get; set; }

        /// <summary>LDAP operation performed (e.g., Bind, Search, Add, Delete, Modify, Compare)</summary>
        public string Operation { get; set; }

        /// <summary>Distinguished Name (DN) of the directory object being accessed or modified</summary>
        public string DistinguishedName { get; set; }

        /// <summary>LDAP result code indicating operation outcome (e.g., success, invalid credentials, no such object)</summary>
        public string ResultCode { get; set; }

        /// <summary>Source IP address of the client making the LDAP request</summary>
        public string SourceIp { get; set; }

        /// <summary>Destination IP address of the LDAP directory server</summary>
        public string DestinationIp { get; set; }

        /// <summary>Timestamp when the LDAP operation occurred</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Unique session identifier for tracking LDAP client connections</summary>
        public string SessionId { get; set; }

        /// <summary>Operation status (e.g., Success, Failed, Partial, Error, Timeout)</summary>
        public string Status { get; set; }

        /// <summary>
        /// Initializes a new instance of the LdapLog class with default values.
        /// </summary>
        public LdapLog() { }

        /// <summary>
        /// Initializes a new instance of the LdapLog class with specified parameters.
        /// </summary>
        /// <param name="ldapLogId">Unique identifier for the LDAP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="operation">LDAP operation performed</param>
        /// <param name="distinguishedName">Distinguished Name of the directory object</param>
        /// <param name="resultCode">LDAP result code indicating operation outcome</param>
        /// <param name="sourceIp">Source IP address of the client</param>
        /// <param name="destinationIp">Destination IP address of the LDAP server</param>
        /// <param name="timestamp">When the LDAP operation occurred</param>
        /// <param name="sessionId">Unique session identifier for tracking connections</param>
        /// <param name="status">Operation status</param>
        public LdapLog(int ldapLogId, int logId, string operation, string distinguishedName,
                       string resultCode, string sourceIp, string destinationIp,
                       DateTime timestamp, string sessionId, string status)
        {
            LdapLogId = ldapLogId;
            LogId = logId;
            Operation = operation;
            DistinguishedName = distinguishedName;
            ResultCode = resultCode;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            Timestamp = timestamp;
            SessionId = sessionId;
            Status = status;
        }

        /// <summary>
        /// Initializes a new instance of the LdapLog class as a copy of an existing LdapLog object.
        /// </summary>
        /// <param name="l">Source LdapLog object to copy from</param>
        public LdapLog(LdapLog l) : this(l.LdapLogId, l.LogId, l.Operation, l.DistinguishedName,
                                         l.ResultCode, l.SourceIp, l.DestinationIp,
                                         l.Timestamp, l.SessionId, l.Status)
        { }

        /// <summary>
        /// Creates a deep copy of the current LdapLog instance.
        /// </summary>
        /// <returns>A new LdapLog object that is an exact copy of the current instance</returns>
        public LdapLog Clone() => new LdapLog(this);
    }
}