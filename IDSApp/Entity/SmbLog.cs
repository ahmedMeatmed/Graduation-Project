using IDSApp.Collection;
using System;
using System.Collections.Generic;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for SMB (Server Message Block) activity.
    /// Contains information about the command executed, the file accessed, the share involved,
    /// and additional protocol/security metadata.
    /// </summary>
    internal class SmbLog
    {
        private int smbLogId;
        private int logId;
        private string command;
        private string filename;
        private string share;

        private string service = "none";
        private ulong treeId = 0;
        private ulong sessionId = 0;
        private string dialect = "unknown";
        private int payloadSize = 0;
        private string tcpFlags = string.Empty;
        private bool isSuspicious = false;
        private List<string> notes = new();
        private List<string> suspicionReasons = new();

        public int SmbLogId { get => smbLogId; set => smbLogId = value; }
        public int LogId { get => logId; set => logId = value; }
        public string Command { get => command; set => command = value; }
        public string Filename { get => filename; set => filename = value; }
        public string Share { get => share; set => share = value; }

        public string Service { get => service; set => service = value; }
        public ulong TreeId { get => treeId; set => treeId = value; }
        public ulong SessionId { get => sessionId; set => sessionId = value; }
        public string Dialect { get => dialect; set => dialect = value; }
        public int PayloadSize { get => payloadSize; set => payloadSize = value; }
        public string TcpFlags { get => tcpFlags; set => tcpFlags = value; }
        public bool IsSuspicious { get => isSuspicious; set => isSuspicious = value; }
        public List<string> Notes { get => notes; set => notes = value; }
        public List<string> SuspicionReasons { get => suspicionReasons; set => suspicionReasons = value; }
        internal SmbLog()
        {

        }
        internal SmbLog(int smbLogId, int logId, string command, string filename, string share,
                        string service = "none", ulong treeId = 0, ulong sessionId = 0, string dialect = "unknown",
                        int payloadSize = 0, string tcpFlags = "", bool isSuspicious = false,
                        List<string>? notes = null, List<string>? suspicionReasons = null)
        {
            this.smbLogId = smbLogId;
            this.logId = logId;
            this.command = command;
            this.filename = filename;
            this.share = share;
            this.service = service;
            this.treeId = treeId;
            this.sessionId = sessionId;
            this.dialect = dialect;
            this.payloadSize = payloadSize;
            this.tcpFlags = tcpFlags;
            this.isSuspicious = isSuspicious;
            this.notes = notes ?? new List<string>();
            this.suspicionReasons = suspicionReasons ?? new List<string>();
        }

        internal SmbLog(SmbLog s) : this(s.smbLogId, s.logId, s.command, s.filename, s.share,
                                         s.service, s.treeId, s.sessionId, s.dialect,
                                         s.payloadSize, s.tcpFlags, s.isSuspicious,
                                         new List<string>(s.notes), new List<string>(s.suspicionReasons))
        { }

        public SmbLog Clone() => new SmbLog(this);
    }
}
