using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling LDAP log-related operations
    /// </summary>
    internal class LdapLogDal
    {
        /// <summary>
        /// Retrieves all LDAP logs from the database
        /// </summary>
        /// <returns>An LdapLogCollection containing all LDAP logs</returns>
        public static LdapLogCollection GetAll()
        {
            LdapLogCollection list = new LdapLogCollection();
            try
            {
                string query = "SELECT * FROM LdapLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    LdapLog log = new LdapLog(
                        (int)row["LdapLogID"],
                        (int)row["LogID"],
                        row["Operation"].ToString(),
                        row["DistinguishedName"].ToString(),
                        row["ResultCode"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching LDAP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific LDAP log by its unique identifier
        /// </summary>
        /// <param name="id">The LdapLogID of the LDAP log to retrieve</param>
        /// <returns>An LdapLog object if found, otherwise null</returns>
        public static LdapLog GetById(int id)
        {
            LdapLog log = null;
            try
            {
                string query = "SELECT * FROM LdapLogs WHERE LdapLogID = @LdapLogID";
                SqlParameter[] parameters = { new SqlParameter("@LdapLogID", SqlDbType.Int) { Value = id } };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new LdapLog(
                        (int)row["LdapLogID"],
                        (int)row["LogID"],
                        row["Operation"].ToString(),
                        row["DistinguishedName"].ToString(),
                        row["ResultCode"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching LDAP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new LDAP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="operation">The LDAP operation (e.g., Bind, Search, Add, Delete, Modify)</param>
        /// <param name="distinguishedName">The distinguished name (DN) of the LDAP entry</param>
        /// <param name="resultCode">The LDAP result code (e.g., success, invalidCredentials, noSuchObject)</param>
        /// <param name="sourceIP">The source IP address of the LDAP client</param>
        /// <param name="destinationIP">The destination IP address of the LDAP server</param>
        /// <param name="timestamp">The timestamp when the LDAP operation occurred</param>
        /// <param name="sessionID">The LDAP session identifier</param>
        /// <param name="status">The operation status</param>
        /// <returns>The newly created LdapLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string operation, string distinguishedName, string resultCode,
                                 string sourceIP, string destinationIP, DateTime timestamp,
                                 string sessionID, string status)
        {
            try
            {
                string query = @"INSERT INTO LdapLogs 
                                (LogID, Operation, DistinguishedName, ResultCode, SourceIP, DestinationIP, Timestamp, SessionID, Status)
                                 VALUES
                                (@LogID, @Operation, @DistinguishedName, @ResultCode, @SourceIP, @DestinationIP, @Timestamp, @SessionID, @Status);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Operation", SqlDbType.NVarChar, 50) { Value = operation },
                    new SqlParameter("@DistinguishedName", SqlDbType.NVarChar, 255) { Value = distinguishedName },
                    new SqlParameter("@ResultCode", SqlDbType.NVarChar, 50) { Value = resultCode },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting LDAP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing LDAP log in the database
        /// </summary>
        /// <param name="ldapLogId">The unique identifier of the LDAP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="operation">The updated LDAP operation</param>
        /// <param name="distinguishedName">The updated distinguished name</param>
        /// <param name="resultCode">The updated result code</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <param name="timestamp">The updated timestamp</param>
        /// <param name="sessionID">The updated session identifier</param>
        /// <param name="status">The updated operation status</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int ldapLogId, int logId, string operation, string distinguishedName, string resultCode,
                                  string sourceIP, string destinationIP, DateTime timestamp,
                                  string sessionID, string status)
        {
            try
            {
                string query = @"UPDATE LdapLogs
                                 SET LogID=@LogID, Operation=@Operation, DistinguishedName=@DistinguishedName, ResultCode=@ResultCode,
                                     SourceIP=@SourceIP, DestinationIP=@DestinationIP, Timestamp=@Timestamp, SessionID=@SessionID, Status=@Status
                                 WHERE LdapLogID=@LdapLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@LdapLogID", SqlDbType.Int) { Value = ldapLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Operation", SqlDbType.NVarChar, 50) { Value = operation },
                    new SqlParameter("@DistinguishedName", SqlDbType.NVarChar, 255) { Value = distinguishedName },
                    new SqlParameter("@ResultCode", SqlDbType.NVarChar, 50) { Value = resultCode },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP },
                    new SqlParameter("@Timestamp", SqlDbType.DateTime2) { Value = timestamp },
                    new SqlParameter("@SessionID", SqlDbType.NVarChar, 50) { Value = sessionID },
                    new SqlParameter("@Status", SqlDbType.NVarChar, 20) { Value = status }
                };

                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating LDAP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes an LDAP log from the database
        /// </summary>
        /// <param name="ldapLogId">The unique identifier of the LDAP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int ldapLogId)
        {
            try
            {
                string query = "DELETE FROM LdapLogs WHERE LdapLogID=@LdapLogID";
                SqlParameter[] parameters = { new SqlParameter("@LdapLogID", SqlDbType.Int) { Value = ldapLogId } };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting LDAP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an LDAP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An LdapLog object if found, otherwise null</returns>
        public static LdapLog GetByLogId(int logId)
        {
            LdapLog log = null;
            try
            {
                string query = "SELECT * FROM LdapLogs WHERE LogID=@LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", SqlDbType.Int) { Value = logId } };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new LdapLog(
                        (int)row["LdapLogID"],
                        (int)row["LogID"],
                        row["Operation"].ToString(),
                        row["DistinguishedName"].ToString(),
                        row["ResultCode"].ToString(),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString(),
                        Convert.ToDateTime(row["Timestamp"]),
                        row["SessionID"].ToString(),
                        row["Status"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching LDAP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}