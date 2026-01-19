using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for TFTP (Trivial File Transfer Protocol) activity.
    /// Contains information about the operation, file transferred, transfer size, source and destination IPs, timestamp, session, and status.
    /// </summary>
    public class TftpLog
    {
        /// <summary>
        /// Gets or sets the unique identifier for this TFTP log entry.
        /// </summary>
        public int TftpLogId { get; set; }

        /// <summary>
        /// Gets or sets the associated general log entry ID.
        /// </summary>
        public int LogId { get; set; }

        /// <summary>
        /// Gets or sets the TFTP operation performed (e.g., read, write).
        /// </summary>
        public string Operation { get; set; }

        /// <summary>
        /// Gets or sets the name of the file involved in the TFTP operation.
        /// </summary>
        public string Filename { get; set; }

        /// <summary>
        /// Gets or sets the size of the file transferred in bytes.
        /// </summary>
        public int TransferSize { get; set; }

        /// <summary>
        /// Gets or sets the source IP address of the TFTP transfer.
        /// </summary>
        public string SourceIp { get; set; }

        /// <summary>
        /// Gets or sets the destination IP address of the TFTP transfer.
        /// </summary>
        public string DestinationIp { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the TFTP log was recorded.
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Gets or sets the session ID for the TFTP transfer.
        /// </summary>
        public string SessionId { get; set; }

        /// <summary>
        /// Gets or sets the status of the TFTP operation (e.g., success, error).
        /// </summary>
        public string Status { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TftpLog"/> class.
        /// </summary>
        public TftpLog() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="TftpLog"/> class with specified values.
        /// </summary>
        public TftpLog(int tftpLogId, int logId, string operation, string filename, int transferSize,
                       string sourceIp, string destinationIp, DateTime timestamp, string sessionId, string status)
        {
            TftpLogId = tftpLogId;
            LogId = logId;
            Operation = operation;
            Filename = filename;
            TransferSize = transferSize;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            Timestamp = timestamp;
            SessionId = sessionId;
            Status = status;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TftpLog"/> class by copying another instance.
        /// </summary>
        /// <param name="t">The <see cref="TftpLog"/> instance to copy.</param>
        public TftpLog(TftpLog t) : this(t.TftpLogId, t.LogId, t.Operation, t.Filename, t.TransferSize,
                                         t.SourceIp, t.DestinationIp, t.Timestamp, t.SessionId, t.Status)
        { }

        /// <summary>
        /// Creates a deep copy of the current <see cref="TftpLog"/> instance.
        /// </summary>
        /// <returns>A new <see cref="TftpLog"/> object identical to the current instance.</returns>
        public TftpLog Clone() => new TftpLog(this);
    }
}
