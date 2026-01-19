using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;

namespace IDSApp.DAL
{
    internal class SmbLogDal
    {
        public static SmbLogCollection GetAll()
        {
            SmbLogCollection list = new SmbLogCollection();
            try
            {
                string query = "SELECT * FROM SmbLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    SmbLog log = MapDataRowToSmbLog(row);
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SMB logs: " + ex.Message);
            }
            return list;
        }

        public static SmbLog GetById(int id)
        {
            SmbLog log = null;
            try
            {
                string query = "SELECT * FROM SmbLogs WHERE SmbLogID = @SmbLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SmbLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    log = MapDataRowToSmbLog(dt.Rows[0]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SMB log by ID: " + ex.Message);
            }
            return log;
        }

        public static SmbLog GetByLogId(int logId)
        {
            SmbLog log = null;
            try
            {
                string query = "SELECT * FROM SmbLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    log = MapDataRowToSmbLog(dt.Rows[0]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SMB log by LogID: " + ex.Message);
            }
            return log;
        }

        public static int Insert(SmbLog log)
        {
            try
            {
                string query = @"INSERT INTO SmbLogs 
                                 (LogID, Command, Filename, Share, Service, TreeId, SessionId, Dialect, PayloadSize, TcpFlags, IsSuspicious, Notes, SuspicionReasons)
                                 VALUES
                                 (@LogID, @Command, @Filename, @Share, @Service, @TreeId, @SessionId, @Dialect, @PayloadSize, @TcpFlags, @IsSuspicious, @Notes, @SuspicionReasons);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = CreateSqlParameters(log);

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting SMB log: " + ex.Message);
                return -1;
            }
        }

        public static bool Update(SmbLog log)
        {
            try
            {
                string query = @"
                    UPDATE SmbLogs
                    SET LogID = @LogID,
                        Command = @Command,
                        Filename = @Filename,
                        Share = @Share,
                        Service = @Service,
                        TreeId = @TreeId,
                        SessionId = @SessionId,
                        Dialect = @Dialect,
                        PayloadSize = @PayloadSize,
                        TcpFlags = @TcpFlags,
                        IsSuspicious = @IsSuspicious,
                        Notes = @Notes,
                        SuspicionReasons = @SuspicionReasons
                    WHERE SmbLogID = @SmbLogID";

                SqlParameter[] parameters = CreateSqlParameters(log, includeId: true);

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating SMB log: " + ex.Message);
                return false;
            }
        }

        public static bool Delete(int smbLogId)
        {
            try
            {
                string query = "DELETE FROM SmbLogs WHERE SmbLogID = @SmbLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SmbLogID", SqlDbType.Int) { Value = smbLogId }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting SMB log: " + ex.Message);
                return false;
            }
        }

        #region Helper Methods
        private static SmbLog MapDataRowToSmbLog(DataRow row)
        {
            return new SmbLog(
                (int)row["SmbLogID"],
                (int)row["LogID"],
                row["Command"].ToString(),
                row["Filename"].ToString(),
                row["Share"].ToString(),
                row["Service"].ToString(),
                Convert.ToUInt32(row["TreeId"]),
                Convert.ToUInt32(row["SessionId"]),
                row["Dialect"].ToString(),
                Convert.ToInt32(row["PayloadSize"]),
                row["TcpFlags"].ToString(),
                Convert.ToBoolean(row["IsSuspicious"]),
                JsonSerializer.Deserialize<List<string>>(row["Notes"]?.ToString() ?? "[]"),
                JsonSerializer.Deserialize<List<string>>(row["SuspicionReasons"]?.ToString() ?? "[]")
            );
        }

        private static SqlParameter[] CreateSqlParameters(SmbLog log, bool includeId = false)
        {
            List<SqlParameter> parameters = new List<SqlParameter>
    {
        new SqlParameter("@LogID", SqlDbType.Int) { Value = log.LogId },
        new SqlParameter("@Command", SqlDbType.NVarChar, 50) { Value = string.IsNullOrEmpty(log.Command) ? "unknown" : log.Command },
        new SqlParameter("@Filename", SqlDbType.NVarChar, 255) { Value = string.IsNullOrEmpty(log.Filename) ? "none" : log.Filename },
        new SqlParameter("@Share", SqlDbType.NVarChar, 255) { Value = string.IsNullOrEmpty(log.Share) ? "none" : log.Share },
        new SqlParameter("@Service", SqlDbType.NVarChar, 50) { Value = string.IsNullOrEmpty(log.Service) ? "none" : log.Service },
        new SqlParameter("@TreeId", SqlDbType.BigInt) { Value = log.TreeId },
        new SqlParameter("@SessionId", SqlDbType.BigInt) { Value = log.SessionId },
        new SqlParameter("@Dialect", SqlDbType.NVarChar, 50) { Value = string.IsNullOrEmpty(log.Dialect) ? "none" : log.Dialect },
        new SqlParameter("@PayloadSize", SqlDbType.Int) { Value = log.PayloadSize },
        new SqlParameter("@TcpFlags", SqlDbType.NVarChar, 50) { Value = string.IsNullOrEmpty(log.TcpFlags) ? "" : log.TcpFlags },
        new SqlParameter("@IsSuspicious", SqlDbType.Bit) { Value = log.IsSuspicious },
        new SqlParameter("@Notes", SqlDbType.NVarChar) { Value = JsonSerializer.Serialize(log.Notes ?? new List<string>()) },
        new SqlParameter("@SuspicionReasons", SqlDbType.NVarChar) { Value = JsonSerializer.Serialize(log.SuspicionReasons ?? new List<string>()) }
    };

            if (includeId)
            {
                parameters.Add(new SqlParameter("@SmbLogID", SqlDbType.Int) { Value = log.SmbLogId });
            }

            return parameters.ToArray();
        }

        #endregion
    }
}
