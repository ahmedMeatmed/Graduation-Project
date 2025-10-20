using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for Telnet activity.
    /// Contains information about client and server IPs, executed commands, and authentication attempts.
    /// </summary>
    internal class TelnetLog
    {
        private int telnetLogId;
        private int logId;
        private string clientIP;
        private string serverIP;
        private string command;
        private int authAttempts;

        /// <summary>
        /// Gets or sets the unique identifier for this Telnet log entry.
        /// </summary>
        public int TelnetLogId { get => telnetLogId; set => telnetLogId = value; }

        /// <summary>
        /// Gets or sets the associated general log entry ID.
        /// </summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>
        /// Gets or sets the client IP address involved in the Telnet session.
        /// </summary>
        public string ClientIP { get => clientIP; set => clientIP = value; }

        /// <summary>
        /// Gets or sets the server IP address involved in the Telnet session.
        /// </summary>
        public string ServerIP { get => serverIP; set => serverIP = value; }

        /// <summary>
        /// Gets or sets the command executed during the Telnet session.
        /// </summary>
        public string Command { get => command; set => command = value; }

        /// <summary>
        /// Gets or sets the number of authentication attempts during the Telnet session.
        /// </summary>
        public int AuthAttempts { get => authAttempts; set => authAttempts = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TelnetLog"/> class with specified values.
        /// </summary>
        /// <param name="telnetLogId">The unique identifier for this Telnet log entry.</param>
        /// <param name="logId">The associated general log entry ID.</param>
        /// <param name="clientIP">The client IP address.</param>
        /// <param name="serverIP">The server IP address.</param>
        /// <param name="command">The command executed.</param>
        /// <param name="authAttempts">The number of authentication attempts.</param>
        internal TelnetLog(int telnetLogId, int logId, string clientIP, string serverIP, string command, int authAttempts)
        {
            this.telnetLogId = telnetLogId;
            this.logId = logId;
            this.clientIP = clientIP;
            this.serverIP = serverIP;
            this.command = command;
            this.authAttempts = authAttempts;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TelnetLog"/> class by copying another instance.
        /// </summary>
        /// <param name="t">The <see cref="TelnetLog"/> instance to copy.</param>
        internal TelnetLog(TelnetLog t) : this(t.telnetLogId, t.logId, t.clientIP, t.serverIP, t.command, t.authAttempts) { }

        /// <summary>
        /// Creates a deep copy of the current <see cref="TelnetLog"/> instance.
        /// </summary>
        /// <returns>A new <see cref="TelnetLog"/> object identical to the current instance.</returns>
        public TelnetLog Clone() => new TelnetLog(this);
    }
}
