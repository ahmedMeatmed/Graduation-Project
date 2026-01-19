using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling ICMP log-related operations
    /// </summary>
    internal class IcmpLogDal
    {
        /// <summary>
        /// Retrieves all ICMP logs from the database
        /// </summary>
        /// <returns>An IcmpLogCollection containing all ICMP logs</returns>
        public static IcmpLogCollection GetAll()
        {
            IcmpLogCollection list = new IcmpLogCollection();
            try
            {
                string query = "SELECT * FROM IcmpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    IcmpLog log = new IcmpLog(
                        (int)row["IcmpLogID"],
                        (int)row["LogID"],
                        Convert.ToInt32(row["Type"]),
                        Convert.ToInt32(row["Code"]),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching ICMP logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific ICMP log by its unique identifier
        /// </summary>
        /// <param name="id">The IcmpLogID of the ICMP log to retrieve</param>
        /// <returns>An IcmpLog object if found, otherwise null</returns>
        public static IcmpLog GetById(int id)
        {
            IcmpLog log = null;
            try
            {
                string query = "SELECT * FROM IcmpLogs WHERE IcmpLogID = @IcmpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@IcmpLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new IcmpLog(
                        (int)row["IcmpLogID"],
                        (int)row["LogID"],
                        Convert.ToInt32(row["Type"]),
                        Convert.ToInt32(row["Code"]),
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching ICMP log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new ICMP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="type">The ICMP message type (e.g., 0=Echo Reply, 8=Echo Request, 3=Destination Unreachable)</param>
        /// <param name="code">The ICMP message code (specific to each type, e.g., for type 3: 0=Net Unreachable, 1=Host Unreachable)</param>
        /// <param name="sourceIP">The source IP address of the ICMP packet</param>
        /// <param name="destIP">The destination IP address of the ICMP packet</param>
        /// <returns>The newly created IcmpLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, int type, int code, string sourceIP, string destIP)
        {
            try
            {
                string query = @"INSERT INTO IcmpLogs (LogID, Type, Code, SourceIP, DestinationIP)
                                 VALUES (@LogID, @Type, @Code, @SourceIP, @DestinationIP);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Type", SqlDbType.Int) { Value = type },
                    new SqlParameter("@Code", SqlDbType.Int) { Value = code },
                    new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
                    new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destIP }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting ICMP log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes an ICMP log from the database
        /// </summary>
        /// <param name="icmpLogId">The unique identifier of the ICMP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int icmpLogId)
        {
            try
            {
                string query = "DELETE FROM IcmpLogs WHERE IcmpLogID = @IcmpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@IcmpLogID", SqlDbType.Int) { Value = icmpLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting ICMP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing ICMP log in the database
        /// </summary>
        /// <param name="icmpLogId">The unique identifier of the ICMP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="type">The updated ICMP message type</param>
        /// <param name="code">The updated ICMP message code</param>
        /// <param name="sourceIP">The updated source IP address</param>
        /// <param name="destinationIP">The updated destination IP address</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int icmpLogId, int logId, int type, int code, string sourceIP, string destinationIP)
        {
            try
            {
                string queryStr = @"
            UPDATE IcmpLogs
            SET LogID = @LogID,
                Type = @Type,
                Code = @Code,
                SourceIP = @SourceIP,
                DestinationIP = @DestinationIP
            WHERE IcmpLogID = @IcmpLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@IcmpLogID", SqlDbType.Int) { Value = icmpLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@Type", SqlDbType.Int) { Value = type },
            new SqlParameter("@Code", SqlDbType.Int) { Value = code },
            new SqlParameter("@SourceIP", SqlDbType.NVarChar, 50) { Value = sourceIP },
            new SqlParameter("@DestinationIP", SqlDbType.NVarChar, 50) { Value = destinationIP }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating ICMP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an ICMP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An IcmpLog object if found, otherwise null</returns>
        public static IcmpLog GetByLogId(int logId)
        {
            IcmpLog log = null;
            try
            {
                string query = "SELECT * FROM IcmpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new IcmpLog(
                        (int)row["IcmpLogID"],
                        (int)row["LogID"],
                        (int)row["Type"],
                       (int)row["Code"],
                        row["SourceIP"].ToString(),
                        row["DestinationIP"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching ICMP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}