using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for SNMP log operations in the database.
    /// </summary>
    internal class SnmpLogDal
    {
        /// <summary>
        /// Retrieves all SNMP logs from the database.
        /// </summary>
        /// <returns>A collection of SnmpLog objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static SnmpLogCollection GetAll()
        {
            SnmpLogCollection list = new SnmpLogCollection();
            try
            {
                string query = "SELECT * FROM SnmpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    SnmpLog log = new SnmpLog(
                        (int)row["SnmpLogID"],
                        (int)row["LogID"],
                        row["Version"].ToString(),
                        row["Community"].ToString(),
                        row["OID"].ToString(),
                        row["Value"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        row["RequestType"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SNMP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific SNMP log by its unique identifier.
        /// </summary>
        /// <param name="id">The SnmpLogID of the record to retrieve.</param>
        /// <returns>A SnmpLog object if found; otherwise, null.</returns>
        public static SnmpLog GetById(int id)
        {
            SnmpLog log = null;
            try
            {
                string query = "SELECT * FROM SnmpLogs WHERE SnmpLogID = @SnmpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SnmpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new SnmpLog(
                        (int)row["SnmpLogID"],
                        (int)row["LogID"],
                        row["Version"].ToString(),
                        row["Community"].ToString(),
                        row["OID"].ToString(),
                        row["Value"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        row["RequestType"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SNMP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new SNMP log record into the database.
        /// </summary>
        /// <param name="logId">The associated LogID.</param>
        /// <param name="version">The SNMP protocol version.</param>
        /// <param name="community">The SNMP community string.</param>
        /// <param name="oid">The Object Identifier (OID) for the SNMP request.</param>
        /// <param name="value">The value associated with the OID.</param>
        /// <param name="sourceIP">The source IP address of the SNMP request.</param>
        /// <param name="destinationIP">The destination IP address of the SNMP request.</param>
        /// <param name="timestamp">The date and time when the SNMP event occurred.</param>
        /// <param name="sessionID">The session identifier for the SNMP transaction.</param>
        /// <param name="status">The status of the SNMP request (e.g., success, failure).</param>
        /// <param name="requestType">The type of SNMP request (e.g., GET, SET, TRAP).</param>
        /// <returns>The newly created SnmpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string version, string community, string oid, string value,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status, string requestType)
        {
            try
            {
                string query = @"INSERT INTO SnmpLogs 
                                 (LogID, Version, Community, OID, Value, SourceIP, DestinationIP, Timestamp, SessionID, Status, RequestType)
                                 VALUES 
                                 (@LogID, @Version, @Community, @OID, @Value, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status, @RequestType);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Version", SqlDbType.NVarChar, 20) { Value = version },
                    new SqlParameter("@Community", SqlDbType.NVarChar, 255) { Value = community },
                    new SqlParameter("@OID", SqlDbType.NVarChar, 255) { Value = oid },
                    new SqlParameter("@Value", SqlDbType.NVarChar, 255) { Value = value },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@RequestType", SqlDbType.NVarChar, 20) { Value = requestType }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting SNMP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing SNMP log record in the database.
        /// </summary>
        /// <param name="snmpLogId">The SnmpLogID of the record to update.</param>
        /// <param name="logId">The new LogID value.</param>
        /// <param name="version">The new SNMP protocol version.</param>
        /// <param name="community">The new SNMP community string.</param>
        /// <param name="oid">The new Object Identifier (OID) for the SNMP request.</param>
        /// <param name="value">The new value associated with the OID.</param>
        /// <param name="sourceIP">The new source IP address of the SNMP request.</param>
        /// <param name="destinationIP">The new destination IP address of the SNMP request.</param>
        /// <param name="timestamp">The new date and time when the SNMP event occurred.</param>
        /// <param name="sessionID">The new session identifier for the SNMP transaction.</param>
        /// <param name="status">The new status of the SNMP request.</param>
        /// <param name="requestType">The new type of SNMP request.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int snmpLogId, int logId, string version, string community, string oid, string value,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status, string requestType)
        {
            try
            {
                string query = @"UPDATE SnmpLogs SET
                                 LogID = @LogID,
                                 Version = @Version,
                                 Community = @Community,
                                 OID = @OID,
                                 Value = @Value,
                                 SourceIP = @SourceIP,
                                 DestinationIP = @DestinationIP,
                                 Timestamp = @Timestamp,
                                 SessionID = @SessionID,
                                 Status = @Status,
                                 RequestType = @RequestType
                                 WHERE SnmpLogID = @SnmpLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@SnmpLogID", SqlDbType.Int) { Value = snmpLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Version", SqlDbType.NVarChar, 20) { Value = version },
                    new SqlParameter("@Community", SqlDbType.NVarChar, 255) { Value = community },
                    new SqlParameter("@OID", SqlDbType.NVarChar, 255) { Value = oid },
                    new SqlParameter("@Value", SqlDbType.NVarChar, 255) { Value = value },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status },
                    new SqlParameter("@RequestType", SqlDbType.NVarChar, 20) { Value = requestType }
                };

                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating SNMP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes a specific SNMP log record from the database.
        /// </summary>
        /// <param name="snmpLogId">The SnmpLogID of the record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int snmpLogId)
        {
            try
            {
                string query = "DELETE FROM SnmpLogs WHERE SnmpLogID = @SnmpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SnmpLogID", SqlDbType.Int) { Value = snmpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting SNMP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an SNMP log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for.</param>
        /// <returns>A SnmpLog object if found; otherwise, null.</returns>
        public static SnmpLog GetByLogId(int logId)
        {
            SnmpLog log = null;
            try
            {
                string query = "SELECT * FROM SnmpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new SnmpLog(
                        (int)row["SnmpLogID"],
                        (int)row["LogID"],
                        row["Version"].ToString(),
                        row["Community"].ToString(),
                        row["OID"].ToString(),
                        row["Value"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString(),
                        row["RequestType"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SNMP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}