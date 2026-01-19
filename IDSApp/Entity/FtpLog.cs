using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an FTP (File Transfer Protocol) log entry captured by the Intrusion Detection System.
    /// Contains information about FTP commands and file operations for monitoring file transfers
    /// and detecting unauthorized access or suspicious file activities.
    /// </summary>
    internal class FtpLog
    {
        int ftpLogId;
        int logId;
        string command;
        string filename;

        /// <summary>Unique identifier for the FTP log entry</summary>
        public int FtpLogId { get => ftpLogId; set => ftpLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>FTP command executed (e.g., RETR, STOR, DELE, LIST, CWD, MKD, RMD, USER, PASS)</summary>
        public string Command { get => command; set => command = value; }

        /// <summary>Name of the file involved in the FTP operation, if applicable</summary>
        public string Filename { get => filename; set => filename = value; }

        /// <summary>
        /// Initializes a new instance of the FtpLog class with specified parameters.
        /// </summary>
        /// <param name="ftpLogId">Unique identifier for the FTP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="command">FTP command executed</param>
        /// <param name="filename">Name of the file involved in the operation</param>
        internal FtpLog(int ftpLogId, int logId, string command, string filename)
        {
            this.ftpLogId = ftpLogId;
            this.logId = logId;
            this.command = command;
            this.filename = filename;
        }

        /// <summary>
        /// Initializes a new instance of the FtpLog class as a copy of an existing FtpLog object.
        /// </summary>
        /// <param name="f">Source FtpLog object to copy from</param>
        internal FtpLog(FtpLog f) : this(f.ftpLogId, f.logId, f.command, f.filename) { }

        /// <summary>
        /// Creates a deep copy of the current FtpLog instance.
        /// </summary>
        /// <returns>A new FtpLog object that is an exact copy of the current instance</returns>
        public FtpLog Clone() => new FtpLog(this);
    }
}