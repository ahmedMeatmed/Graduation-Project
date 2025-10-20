using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling DNS log-related operations
    /// </summary>
    internal class DnsLogDal
    {
        /// <summary>
        /// Retrieves all DNS logs from the database
        /// </summary>
        /// <returns>A DnsLogCollection containing all DNS logs</returns>
        public static DnsLogCollection GetAll()
        {
            DnsLogCollection list = new DnsLogCollection();
            try
            {
                string query = "SELECT * FROM DnsLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    DnsLog log = new DnsLog(
                        (int)row["DnsLogID"],
                        (int)row["LogID"],
                        row["Query"].ToString(),
                        row["QueryType"].ToString(),
                        row["Response"].ToString(),
                         (int)row["TTL"],
                        row["RecordType"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DNS logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific DNS log by its unique identifier
        /// </summary>
        /// <param name="id">The DnsLogID of the DNS log to retrieve</param>
        /// <returns>A DnsLog object if found, otherwise null</returns>
        public static DnsLog GetById(int id)
        {
            DnsLog log = null;
            try
            {
                string query = "SELECT * FROM DnsLogs WHERE DnsLogID = @DnsLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@DnsLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new DnsLog(
                        (int)row["DnsLogID"],
                        (int)row["LogID"],
                        row["Query"].ToString(),
                        row["QueryType"].ToString(),
                        row["Response"].ToString(),
                        (int)row["TTL"],
                        row["RecordType"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DNS log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new DNS log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="queryText">The DNS query domain name</param>
        /// <param name="queryType">The DNS query type (e.g., A, AAAA, CNAME, MX, TXT)</param>
        /// <param name="response">The DNS server response</param>
        /// <returns>The newly created DnsLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string queryText, string queryType, string response, int ttl, string recordType)
        {
            try
            {
                string query = @"INSERT INTO DnsLogs (LogID, Query, QueryType, Response,TTL,RecordType)
                                 VALUES (@LogID, @Query, @QueryType, @Response,@TTL,@RecordType);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Query", SqlDbType.NVarChar, 255) { Value = queryText },
                    new SqlParameter("@QueryType", SqlDbType.NVarChar, 20) { Value = queryType },
                    new SqlParameter("@Response", SqlDbType.NVarChar, 255) { Value = response },
                     new SqlParameter("@TTL", SqlDbType.Int) { Value = ttl },
                    new SqlParameter("@RecordType", SqlDbType.NVarChar, 255) { Value = recordType },
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting DNS log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes a DNS log from the database
        /// </summary>
        /// <param name="dnsLogId">The unique identifier of the DNS log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int dnsLogId)
        {
            try
            {
                string query = "DELETE FROM DnsLogs WHERE DnsLogID = @DnsLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@DnsLogID", SqlDbType.Int) { Value = dnsLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting DNS log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing DNS log in the database
        /// </summary>
        /// <param name="dnsLogId">The unique identifier of the DNS log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="query">The updated DNS query domain name</param>
        /// <param name="queryType">The updated DNS query type</param>
        /// <param name="response">The updated DNS server response</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int dnsLogId, int logId, string query, string queryType, string response,int ttl,string recordType)
        {
            try
            {
                string queryStr = @"
                    UPDATE DnsLogs
                    SET LogID = @LogID,
                        Query = @Query,
                        QueryType = @QueryType,
                        Response = @Response,
                        TTL=@TTL,
                        RecordType=@RecordType
                    WHERE DnsLogID = @DnsLogID";

                SqlParameter[] parameters = {
                    new SqlParameter("@DnsLogID", SqlDbType.Int) { Value = dnsLogId },
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@Query", SqlDbType.NVarChar, 255) { Value = query },
                    new SqlParameter("@QueryType", SqlDbType.NVarChar, 20) { Value = queryType },
                    new SqlParameter("@Response", SqlDbType.NVarChar, 255) { Value = response },
                    new SqlParameter("@TTL", SqlDbType.Int) { Value = ttl },
                    new SqlParameter("@RecordType", SqlDbType.NVarChar, 255) { Value = recordType },

                };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating DNS log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a DNS log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>A DnsLog object if found, otherwise null</returns>
        public static DnsLog GetByLogId(int logId)
        {
            DnsLog log = null;
            try
            {
                string query = "SELECT * FROM DnsLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new DnsLog(
                        (int)row["DnsLogID"],
                        (int)row["LogID"],
                        row["QueryName"].ToString(),
                        row["QueryType"].ToString(),
                        row["ResponseCode"].ToString(),
                        (int)row["TTL"],
                        row["RecordType"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching DNS log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}