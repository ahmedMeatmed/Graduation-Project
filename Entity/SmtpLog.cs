using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for SMTP (Simple Mail Transfer Protocol) activity.
    /// Contains information about the sender, recipient, and subject of an email.
    /// </summary>
    internal class SmtpLog
    {
        private int smtpLogId;
        private int logId;
        private string fromAddress;
        private string toAddress;
        private string subject;

        /// <summary>
        /// Gets or sets the unique identifier for this SMTP log entry.
        /// </summary>
        public int SmtpLogId { get => smtpLogId; set => smtpLogId = value; }

        /// <summary>
        /// Gets or sets the associated general log entry ID.
        /// </summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>
        /// Gets or sets the sender email address.
        /// </summary>
        public string FromAddress { get => fromAddress; set => fromAddress = value; }

        /// <summary>
        /// Gets or sets the recipient email address.
        /// </summary>
        public string ToAddress { get => toAddress; set => toAddress = value; }

        /// <summary>
        /// Gets or sets the subject of the email.
        /// </summary>
        public string Subject { get => subject; set => subject = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmtpLog"/> class with specified values.
        /// </summary>
        /// <param name="smtpLogId">The unique identifier for this SMTP log entry.</param>
        /// <param name="logId">The associated general log entry ID.</param>
        /// <param name="fromAddress">The sender email address.</param>
        /// <param name="toAddress">The recipient email address.</param>
        /// <param name="subject">The email subject.</param>
        internal SmtpLog(int smtpLogId, int logId, string fromAddress, string toAddress, string subject)
        {
            this.smtpLogId = smtpLogId;
            this.logId = logId;
            this.fromAddress = fromAddress;
            this.toAddress = toAddress;
            this.subject = subject;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SmtpLog"/> class by copying another instance.
        /// </summary>
        /// <param name="s">The <see cref="SmtpLog"/> instance to copy.</param>
        internal SmtpLog(SmtpLog s) : this(s.smtpLogId, s.logId, s.fromAddress, s.toAddress, s.subject) { }

        /// <summary>
        /// Creates a deep copy of the current <see cref="SmtpLog"/> instance.
        /// </summary>
        /// <returns>A new <see cref="SmtpLog"/> object identical to the current instance.</returns>
        public SmtpLog Clone() => new SmtpLog(this);
    }
}
