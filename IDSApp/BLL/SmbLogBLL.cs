using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using System;
using System.Collections.Generic;

namespace IDSApp.BLL
{
    internal class SmbLogBLL
    {
        public static SmbLogCollection GetAll()
        {
            return SmbLogDal.GetAll();
        }

        public static SmbLog GetById(int id)
        {
            return SmbLogDal.GetById(id);
        }

        public static SmbLog GetByLogId(int logId)
        {
            return SmbLogDal.GetByLogId(logId);
        }

        public static int Insert(
            int logId,
            string command,
            string filename,
            string share,
            string service = "none",
            uint treeId = 0,
            uint sessionId = 0,
            string dialect = "unknown",
            int payloadSize = 0,
            string tcpFlags = "",
            bool isSuspicious = false,
            List<string>? notes = null,
            List<string>? suspicionReasons = null)
        {
            SmbLog log = new SmbLog
            {
                LogId = logId,
                Command = command,
                Filename = filename,
                Share = share,
                Service = service,
                TreeId = treeId,
                SessionId = sessionId,
                Dialect = dialect,
                PayloadSize = payloadSize,
                TcpFlags = tcpFlags,
                IsSuspicious = isSuspicious,
                Notes = notes ?? new List<string>(),
                SuspicionReasons = suspicionReasons ?? new List<string>()
            };

            return SmbLogDal.Insert(log);
        }

        public static bool Update(SmbLog log)
        {
            return SmbLogDal.Update(log);
        }

        public static bool Delete(int smbLogId)
        {
            return SmbLogDal.Delete(smbLogId);
        }
    }
}
