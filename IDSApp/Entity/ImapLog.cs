using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an IMAP (Internet Message Access Protocol) log entry captured by the Intrusion Detection System.
    /// Contains detailed information about email access operations for monitoring email client activities
    /// and detecting unauthorized email access, data exfiltration, or email-based attacks.
    /// </summary>
    internal class ImapLog
    {
        int imapLogId;
        int logId;
        string command;
        string folder;
        string responseCode;
        string sourceIP;
        string destinationIP;
        DateTime timestamp;
        string sessionID;
        string status;
        int attemptCount;

        /// <summary>Unique identifier for the IMAP log entry</summary>
        public int ImapLogId { get => imapLogId; set => imapLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>IMAP command executed (e.g., LOGIN, SELECT, FETCH, STORE, SEARCH, COPY, DELETE)</summary>
        public string Command { get => command; set => command = value; }

        /// <summary>Email folder/mailbox involved in the operation (e.g., INBOX, Sent, Drafts)</summary>
        public string Folder { get => folder; set => folder = value; }

        /// <summary>IMAP server response code (e.g., OK, NO, BAD, BYE) with status information</summary>
        public string ResponseCode { get => responseCode; set => responseCode = value; }

        /// <summary>Source IP address of the email client making the IMAP request</summary>
        public string SourceIP { get => sourceIP; set => sourceIP = value; }

        /// <summary>Destination IP address of the IMAP email server</summary>
        public string DestinationIP { get => destinationIP; set => destinationIP = value; }

        /// <summary>Timestamp when the IMAP operation occurred</summary>
        public DateTime Timestamp { get => timestamp; set => timestamp = value; }

        /// <summary>Unique session identifier for tracking IMAP client connections</summary>
        public string SessionID { get => sessionID; set => sessionID = value; }

        /// <summary>Operation status (e.g., Success, Failed, Partial, Error, Timeout)</summary>
        public string Status { get => status; set => status = value; }

        /// <summary>Number of authentication or command attempts made in the session</summary>
        public int AttemptCount { get => attemptCount; set => attemptCount = value; }

        /// <summary>
        /// Initializes a new instance of the ImapLog class with specified parameters.
        /// </summary>
        /// <param name="imapLogId">Unique identifier for the IMAP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="command">IMAP command executed</param>
        /// <param name="folder">Email folder/mailbox involved in the operation</param>
        /// <param name="responseCode">IMAP server response code</param>
        /// <param name="sourceIP">Source IP address of the email client</param>
        /// <param name="destinationIP">Destination IP address of the IMAP server</param>
        /// <param name="timestamp">When the IMAP operation occurred</param>
        /// <param name="sessionID">Unique session identifier for tracking connections</param>
        /// <param name="status">Operation status</param>
        /// <param name="attemptCount">Number of authentication or command attempts</param>
        internal ImapLog(int imapLogId, int logId, string command, string folder, string responseCode,
            string sourceIP, string destinationIP, DateTime timestamp, string sessionID, string status, int attemptCount)
        {
            this.imapLogId = imapLogId;
            this.logId = logId;
            this.command = command;
            this.folder = folder;
            this.responseCode = responseCode;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.timestamp = timestamp;
            this.sessionID = sessionID;
            this.status = status;
            this.attemptCount = attemptCount;
        }

        /// <summary>
        /// Initializes a new instance of the ImapLog class as a copy of an existing ImapLog object.
        /// </summary>
        /// <param name="i">Source ImapLog object to copy from</param>
        internal ImapLog(ImapLog i) : this(i.imapLogId, i.logId, i.command, i.folder, i.responseCode,
            i.sourceIP, i.destinationIP, i.timestamp, i.sessionID, i.status, i.attemptCount)
        { }

        /// <summary>
        /// Creates a deep copy of the current ImapLog instance.
        /// </summary>
        /// <returns>A new ImapLog object that is an exact copy of the current instance</returns>
        public ImapLog Clone() => new ImapLog(this);
    }
}