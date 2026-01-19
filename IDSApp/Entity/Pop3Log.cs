using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a POP3 (Post Office Protocol version 3) log entry captured by the Intrusion Detection System.
    /// Contains detailed information about email retrieval operations for monitoring email client activities
    /// and detecting unauthorized email access, credential attacks, or data exfiltration through email.
    /// </summary>
    internal class Pop3Log
    {
        int pop3LogId;
        int logId;
        string command;
        string username;
        string responseCode;
        int messageSize;
        string sourceIP;
        string destinationIP;
        DateTime timestamp;
        string sessionID;
        string status;
        int attemptCount;

        /// <summary>Unique identifier for the POP3 log entry</summary>
        public int Pop3LogId { get => pop3LogId; set => pop3LogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>POP3 command executed (e.g., USER, PASS, LIST, RETR, DELE, QUIT, STAT, TOP)</summary>
        public string Command { get => command; set => command = value; }

        /// <summary>Username used for POP3 authentication</summary>
        public string Username { get => username; set => username = value; }

        /// <summary>POP3 server response code and message (e.g., +OK, -ERR)</summary>
        public string ResponseCode { get => responseCode; set => responseCode = value; }

        /// <summary>Size of the email message in bytes (for RETR commands)</summary>
        public int MessageSize { get => messageSize; set => messageSize = value; }

        /// <summary>Source IP address of the email client</summary>
        public string SourceIP { get => sourceIP; set => sourceIP = value; }

        /// <summary>Destination IP address of the POP3 email server</summary>
        public string DestinationIP { get => destinationIP; set => destinationIP = value; }

        /// <summary>Timestamp when the POP3 operation occurred</summary>
        public DateTime Timestamp { get => timestamp; set => timestamp = value; }

        /// <summary>Unique session identifier for tracking POP3 client connections</summary>
        public string SessionID { get => sessionID; set => sessionID = value; }

        /// <summary>Operation status (e.g., Success, Failed, Authentication Failed, Timeout)</summary>
        public string Status { get => status; set => status = value; }

        /// <summary>Number of authentication attempts made in the session</summary>
        public int AttemptCount { get => attemptCount; set => attemptCount = value; }

        /// <summary>
        /// Initializes a new instance of the Pop3Log class with specified parameters.
        /// </summary>
        /// <param name="pop3LogId">Unique identifier for the POP3 log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="command">POP3 command executed</param>
        /// <param name="username">Username used for POP3 authentication</param>
        /// <param name="responseCode">POP3 server response code and message</param>
        /// <param name="messageSize">Size of the email message in bytes</param>
        /// <param name="sourceIP">Source IP address of the email client</param>
        /// <param name="destinationIP">Destination IP address of the POP3 server</param>
        /// <param name="timestamp">When the POP3 operation occurred</param>
        /// <param name="sessionID">Unique session identifier for tracking connections</param>
        /// <param name="status">Operation status</param>
        /// <param name="attemptCount">Number of authentication attempts made</param>
        internal Pop3Log(int pop3LogId, int logId, string command, string username, string responseCode, int messageSize,
            string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status, int attemptCount)
        {
            this.pop3LogId = pop3LogId;
            this.logId = logId;
            this.command = command;
            this.username = username;
            this.responseCode = responseCode;
            this.messageSize = messageSize;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.timestamp = timestamp;
            this.sessionID = sessionID;
            this.status = status;
            this.attemptCount = attemptCount;
        }

        /// <summary>
        /// Initializes a new instance of the Pop3Log class as a copy of an existing Pop3Log object.
        /// </summary>
        /// <param name="p">Source Pop3Log object to copy from</param>
        internal Pop3Log(Pop3Log p) : this(p.pop3LogId, p.logId, p.command, p.username, p.responseCode, p.messageSize,
            p.sourceIP, p.destinationIP, p.timestamp, p.sessionID, p.status, p.attemptCount)
        { }

        /// <summary>
        /// Creates a deep copy of the current Pop3Log instance.
        /// </summary>
        /// <returns>A new Pop3Log object that is an exact copy of the current instance</returns>
        public Pop3Log Clone() => new Pop3Log(this);
    }
}