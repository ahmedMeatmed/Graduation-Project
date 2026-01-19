using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for SSH (Secure Shell) activity.
    /// Contains information about client and server versions and authentication attempts.
    /// </summary>
    internal class SshLog
    {
        private int sshLogId;
        private int logId;
        private string clientVersion;
        private string serverVersion;
        private int authAttempts;

        /// <summary>
        /// Gets or sets the unique identifier for this SSH log entry.
        /// </summary>
        public int SshLogId { get => sshLogId; set => sshLogId = value; }

        /// <summary>
        /// Gets or sets the associated general log entry ID.
        /// </summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>
        /// Gets or sets the SSH client version.
        /// </summary>
        public string ClientVersion { get => clientVersion; set => clientVersion = value; }

        /// <summary>
        /// Gets or sets the SSH server version.
        /// </summary>
        public string ServerVersion { get => serverVersion; set => serverVersion = value; }

        /// <summary>
        /// Gets or sets the number of authentication attempts.
        /// </summary>
        public int AuthAttempts { get => authAttempts; set => authAttempts = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SshLog"/> class with specified values.
        /// </summary>
        /// <param name="sshLogId">The unique identifier for this SSH log entry.</param>
        /// <param name="logId">The associated general log entry ID.</param>
        /// <param name="clientVersion">The SSH client version.</param>
        /// <param name="serverVersion">The SSH server version.</param>
        /// <param name="authAttempts">The number of authentication attempts.</param>
        internal SshLog(int sshLogId, int logId, string clientVersion, string serverVersion, int authAttempts)
        {
            this.sshLogId = sshLogId;
            this.logId = logId;
            this.clientVersion = clientVersion;
            this.serverVersion = serverVersion;
            this.authAttempts = authAttempts;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SshLog"/> class by copying another instance.
        /// </summary>
        /// <param name="s">The <see cref="SshLog"/> instance to copy.</param>
        internal SshLog(SshLog s) : this(s.sshLogId, s.logId, s.clientVersion, s.serverVersion, s.authAttempts) { }

        /// <summary>
        /// Creates a deep copy of the current <see cref="SshLog"/> instance.
        /// </summary>
        /// <returns>A new <see cref="SshLog"/> object identical to the current instance.</returns>
        public SshLog Clone() => new SshLog(this);
    }
}
