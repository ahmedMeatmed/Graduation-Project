using IDSApp.Collection;
using IDSApp.Entity;
using IDSApp.Helper;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling general log-related operations and coordinating protocol-specific logs
    /// </summary>
    internal class LogDal
    {
        /// <summary>
        /// Retrieves all logs from the database with their associated protocol-specific log data
        /// </summary>
        /// <returns>A LogCollection containing all logs with complete protocol information</returns>
        public static LogCollection GetAll()
        {
            LogCollection logList = new LogCollection();

            try
            {
                string query = "SELECT * FROM Logs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    Logs log = CreateLogFromDataRow(row);

                    // Attach protocol-specific logs
                    AttachProtocolLog(log);

                    logList.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching logs: " + ex.Message);
            }

            return logList;
        }

        /// <summary>
        /// Retrieves a specific log by its unique identifier with all associated protocol data
        /// </summary>
        /// <param name="id">The LogID of the log to retrieve</param>
        /// <returns>A Logs object with complete protocol information if found, otherwise null</returns>
        public static Logs GetById(int id)
        {
            Logs log = null;

            try
            {
                string query = "SELECT * FROM Logs WHERE LogID = @LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = id }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = CreateLogFromDataRow(row);

                    // Attach protocol-specific logs
                    AttachProtocolLog(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching log by ID: " + ex.Message);
            }

            return log;
        }

        /// <summary>
        /// Retrieves a log by its exact timestamp with all associated protocol data
        /// </summary>
        /// <param name="timestamp">The exact timestamp to search for</param>
        /// <returns>A Logs object with complete protocol information if found, otherwise null</returns>
        public static Logs GetByTimeStamp(DateTime timestamp)
        {
            Logs log = null;

            try
            {
                string query = "SELECT * FROM Logs WHERE Timestamp = @Timestamp";
                SqlParameter[] parameters = {
                    new SqlParameter("@Timestamp", SqlDbType.DateTime) { Value = timestamp }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = CreateLogFromDataRow(row);

                    // Attach protocol-specific logs
                    AttachProtocolLog(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching log by timestamp: " + ex.Message);
            }

            return log;
        }

        /// <summary>
        /// Inserts a new log entry into the database
        /// </summary>
        /// <param name="timestamp">The timestamp when the network event occurred</param>
        /// <param name="sourceIp">The source IP address</param>
        /// <param name="destinationIp">The destination IP address</param>
        /// <param name="packetSize">The size of the packet in bytes</param>
        /// <param name="isMalicious">Indicates if the packet was detected as malicious</param>
        /// <param name="protocolName">The name of the protocol (e.g., HTTP, DNS, FTP)</param>
        /// <param name="protocol">The protocol type (e.g., TCP, UDP, ICMP)</param>
        /// <param name="srcPort">The source port number</param>
        /// <param name="destPort">The destination port number</param>
        /// <param name="payloadSize">The size of the payload in bytes</param>
        /// <param name="tcpFlags">TCP flags if applicable (e.g., SYN, ACK, FIN)</param>
        /// <param name="flowDirection">The direction of network flow (e.g., inbound, outbound)</param>
        /// <param name="packetCount">The number of packets in the session</param>
        /// <param name="duration">The duration of the session in seconds</param>
        /// <param name="matchedSignatureId">The ID of the matched intrusion detection signature, if any</param>
        /// <param name="info">Additional information about the log entry</param>
        /// <returns>The newly created LogID if successful, otherwise -1</returns>
        public static int Insert(
            DateTime timestamp,
            string sourceIp,
            string destinationIp,
            double packetSize,
            bool isMalicious,
            string protocolName,
            string protocol,
            int srcPort,
            int destPort,
            double payloadSize,
            string tcpFlags,
            string flowDirection,
            int packetCount,
            double duration,
            int? matchedSignatureId,
            string info)
        {
            try
            {
                // Log debug قبل التنفيذ
                OptimizedLogger.LogDebug($"[Redis] Attempting INSERT with values: " +
                    $"Timestamp={timestamp}, SourceIp='{sourceIp}', DestinationIp='{destinationIp}', " +
                    $"PacketSize={packetSize}, IsMalicious={isMalicious}, ProtocolName='{protocolName}', Protocol='{protocol}', " +
                    $"SrcPort={srcPort}, DestPort={destPort}, PayloadSize={payloadSize}, TcpFlags='{tcpFlags}', " +
                    $"FlowDirection='{flowDirection}', PacketCount={packetCount}, Duration={duration}, " +
                    $"MatchedSignatureId={(matchedSignatureId.HasValue ? matchedSignatureId.Value.ToString() : "NULL")}, Info='{info}'");

                // string query = @"
                    // SET NOCOUNT OFF;

                    // INSERT INTO Logs 
                    //     (Timestamp, SourceIp, DestinationIp, PacketSize, IsMalicious, ProtocolName, Protocol,
                    //     SrcPort, DestPort, PayloadSize, TcpFlags, FlowDirection, PacketCount, Duration,
                    //     MatchedSignatureId, Info)
                    // VALUES
                    //     (@Timestamp, @SourceIp, @DestinationIp, @PacketSize, @IsMalicious, @ProtocolName, @Protocol,
                    //     @SrcPort, @DestPort, @PayloadSize, @TcpFlags, @FlowDirection, @PacketCount, @Duration,
                    //     @MatchedSignatureId, @Info);

                    // SELECT CAST(@@IDENTITY AS INT);
                    // ";

                // SqlParameter[] parameters = {
                //     new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                //     new SqlParameter("@SourceIp", SqlDbType.NVarChar, 100) { Value = (object)sourceIp ?? DBNull.Value },
                //     new SqlParameter("@DestinationIp", SqlDbType.NVarChar, 100) { Value = (object)destinationIp ?? DBNull.Value },
                //     new SqlParameter("@PacketSize", SqlDbType.Float) { Value = packetSize },
                //     new SqlParameter("@IsMalicious", SqlDbType.Bit) { Value = isMalicious },
                //     new SqlParameter("@ProtocolName", SqlDbType.NVarChar, 100) { Value = (object)protocolName ?? DBNull.Value },
                //     new SqlParameter("@Protocol", SqlDbType.NVarChar, 40) { Value = (object)protocol ?? DBNull.Value },
                //     new SqlParameter("@SrcPort", SqlDbType.Int) { Value = srcPort },
                //     new SqlParameter("@DestPort", SqlDbType.Int) { Value = destPort },
                //     new SqlParameter("@PayloadSize", SqlDbType.Float) { Value = payloadSize },
                //     new SqlParameter("@TcpFlags", SqlDbType.NVarChar, 40) { Value = (object)tcpFlags ?? DBNull.Value },
                //     new SqlParameter("@FlowDirection", SqlDbType.NVarChar, 20) { Value = (object)flowDirection ?? DBNull.Value },
                //     new SqlParameter("@PacketCount", SqlDbType.Int) { Value = packetCount },
                //     new SqlParameter("@Duration", SqlDbType.Float) { Value = duration },
                //     new SqlParameter("@MatchedSignatureId", SqlDbType.Int) { Value = (object)matchedSignatureId ?? DBNull.Value },
                //     new SqlParameter("@Info", SqlDbType.NVarChar, -1) { Value = (object)info ?? DBNull.Value }
                // };

            //     object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);

                //     if (result != null && int.TryParse(result.ToString(), out int newId) && newId > 0)
                //     {
                //         OptimizedLogger.LogDebug($"[DB-SUCCESS] Log inserted successfully with ID={newId}");
                //         return newId;
                //     }
                //     else
                //     {
                //         OptimizedLogger.LogError("[DB-FAIL] Insert executed but returned no valid ID (possible NOCOUNT ON, missing identity, or trigger interference).");
                //         return 0;
                //     }
                // }
                // catch (SqlException ex)
                // {
                //     OptimizedLogger.LogError($"[DB-EXCEPTION] SQL Error inserting log: Number={ex.Number}, Message={ex.Message}, " +
                //         $"Inner={ex.InnerException?.Message}, StackTrace={ex.StackTrace}");
                //     return -1;
                // }
                // catch (Exception ex)
                // {
                //     OptimizedLogger.LogError($"[DB-GENERAL] Unexpected error inserting log: Message={ex.Message}, " +
                //         $"Inner={ex.InnerException?.Message}, StackTrace={ex.StackTrace}");
                //     return -1;
                // }
        
            string json = $@"{{
            ""timestamp"": ""{timestamp:yyyy-MM-dd HH:mm:ss}"",
            ""sourceIp"": ""{sourceIp}"",
            ""destinationIp"": ""{destinationIp}"",
            ""packetSize"": {packetSize},
            ""isMalicious"": {isMalicious.ToString().ToLower()},
            ""protocolName"": ""{protocolName}"",
            ""protocol"": ""{protocol}"",
            ""srcPort"": {srcPort},
            ""destPort"": {destPort},
            ""payloadSize"": {payloadSize},
            ""tcpFlags"": ""{tcpFlags}"",
            ""flowDirection"": ""{flowDirection}"",
            ""packetCount"": {packetCount},
            ""duration"": {duration},
            ""matchedSignatureId"": {(matchedSignatureId.HasValue ? matchedSignatureId.Value.ToString() : "null")},
            ""info"": ""{info}""
        }}";

            int result = DBL.DBL.PushLog(json,"log");

            if (result == 1)
            {
                OptimizedLogger.LogDebug("[REDIS-SUCCESS] Log pushed to Redis successfully.");
                return 1; // success
            }
            else
            {
                OptimizedLogger.LogError("[REDIS-FAIL] Failed to push log to Redis.");
                return 0;
            }
        }
        catch (Exception ex)
        {
            OptimizedLogger.LogError($"[REDIS-ERROR] Unexpected error pushing log: {ex.Message}");
            return -1;
        }
        
        }


        /// <summary>
        /// Deletes a log entry from the database
        /// </summary>
        /// <param name="logId">The unique identifier of the log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int logId)
        {
            try
            {
                string query = "DELETE FROM Logs WHERE LogID = @LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Creates a Logs object from a DataRow
        /// </summary>
        /// <param name="row">The DataRow containing log data</param>
        /// <returns>A populated Logs object</returns>
        private static Logs CreateLogFromDataRow(DataRow row)
        {
            return new Logs(
                (int)row["LogID"],
                Convert.ToDateTime(row["Timestamp"]),
                row["SourceIp"].ToString(),
                row["DestinationIp"].ToString(),
                Convert.ToDouble(row["PacketSize"]),
                Convert.ToBoolean(row["IsMalicious"]),
                AlertDal.GetByLogId((int)row["LogID"]),
                row["ProtocolName"].ToString(),
                row["Protocol"].ToString(),
                Convert.ToInt32(row["SrcPort"]),
                Convert.ToInt32(row["DestPort"]),
                Convert.ToDouble(row["PayloadSize"]),
                row["TcpFlags"].ToString(),
                row["FlowDirection"].ToString(),
                Convert.ToInt32(row["PacketCount"]),
                Convert.ToDouble(row["Duration"]),
                row["MatchedSignatureId"] != DBNull.Value ? (int?)Convert.ToInt32(row["MatchedSignatureId"]) : null,
                row["Info"] != DBNull.Value ? row["Info"].ToString() : ""
            );
        }

        /// <summary>
        /// Attaches protocol-specific log data to a Logs object based on the protocol name
        /// </summary>
        /// <param name="log">The Logs object to which protocol data will be attached</param>
        private static void AttachProtocolLog(Logs log)
        {
            switch (log.ProtocolName.ToLower())
            {
                case "http":
                    log.HttpLog = HttpLogDal.GetByLogId(log.Id);
                    break;
                case "dns":
                    log.DnsLog = DnsLogDal.GetByLogId(log.Id);
                    break;
                case "smb":
                    log.SmbLog = SmbLogDal.GetByLogId(log.Id);
                    break;
                case "ftp":
                    log.FtpLog = FtpLogDal.GetByLogId(log.Id);
                    break;
                case "smtp":
                    log.SmtpLog = SmtpLogDal.GetByLogId(log.Id);
                    break;
                case "tls":
                    log.TlsLog = TlsLogDal.GetByLogId(log.Id);
                    break;
                case "telnet":
                    log.TelnetLog = TelnetLogDal.GetByLogId(log.Id);
                    break;
                case "ssh":
                    log.SshLog = SshLogDal.GetByLogId(log.Id);
                    break;
                case "rdp":
                    log.RdpLog = RdpLogDal.GetByLogId(log.Id);
                    break;
                case "icmp":
                    log.IcmpLog = IcmpLogDal.GetByLogId(log.Id);
                    break;
                    // add more protocols here if needed
            }
        }
    }
}