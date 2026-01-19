using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Data Access Layer for handling HTTP log-related operations
    /// </summary>
    internal class HttpLogDal
    {
        /// <summary>
        /// Retrieves all HTTP logs from the database
        /// </summary>
        /// <returns>An HttpLogCollection containing all HTTP logs</returns>
        public static HttpLogCollection GetAll()
        {
            HttpLogCollection list = new HttpLogCollection();

            try
            {
                string query = "SELECT * FROM HttpLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    HttpLog log = new HttpLog(
                        (int)row["HttpLogID"],
                        (int)row["LogID"],
                        row["Method"].ToString(),
                        row["Url"].ToString(),
                        row["Host"].ToString(),
                        row["UserAgent"].ToString(),
                        Convert.ToInt32(row["StatusCode"]),
                        row["BodyDetection"].ToString(),
                        (int)row["RequestBodySize"],
                        (int)row["ResponseBodySize"]
                    );

                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching HTTP logs: " + ex.Message);
            }

            return list;
        }

        /// <summary>
        /// Retrieves a specific HTTP log by its unique identifier
        /// </summary>
        /// <param name="id">The HttpLogID of the HTTP log to retrieve</param>
        /// <returns>An HttpLog object if found, otherwise null</returns>
        public static HttpLog GetById(int id)
        {
            HttpLog log = null;

            try
            {
                string query = "SELECT * FROM HttpLogs WHERE HttpLogID = @HttpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@HttpLogID", SqlDbType.Int) { Value = id }
                };

                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new HttpLog(
                        (int)row["HttpLogID"],
                        (int)row["LogID"],
                        row["Method"].ToString(),
                        row["Url"].ToString(),
                        row["Host"].ToString(),
                        row["UserAgent"].ToString(),
                        Convert.ToInt32(row["StatusCode"]),
                        row["BodyDetection"].ToString(),
                        (int)row["RequestBodySize"],
                        (int)row["ResponseBodySize"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching HTTP log by ID: " + ex.Message);
            }

            return log;
        }

        /// <summary>
        /// Inserts a new HTTP log into the database
        /// </summary>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="method">The HTTP method (e.g., GET, POST, PUT, DELETE, PATCH)</param>
        /// <param name="url">The requested URL</param>
        /// <param name="host">The host header from the HTTP request</param>
        /// <param name="userAgent">The user agent string from the client</param>
        /// <param name="statusCode">The HTTP status code (e.g., 200, 404, 500)</param>
        /// <param name="bodyDetection">Detection information about the request/response body content</param>
        /// <param name="requestBodySize">The size of the request body in bytes</param>
        /// <param name="responseBodySize">The size of the response body in bytes</param>
        /// <returns>The newly created HttpLogID if successful, otherwise -1</returns>
        public static int Insert(int logId, string method, string url, string host, string userAgent, int statusCode, string bodyDetection, int requestBodySize, int responseBodySize)
        {
            try
            {
                string query = @"
INSERT INTO HttpLogs 
(LogID, Method, Url, Host, UserAgent, StatusCode, BodyDetection, RequestBodySize, ResponseBodySize)
VALUES 
(@LogID, @Method, @Url, @Host, @UserAgent, @StatusCode, @BodyDetection, @RequestBodySize, @ResponseBodySize);
SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@Method", SqlDbType.NVarChar, 10) { Value = (object)method ?? DBNull.Value },
            new SqlParameter("@Url", SqlDbType.NVarChar, 2048) { Value = (object)url ?? DBNull.Value },
            new SqlParameter("@Host", SqlDbType.NVarChar, 255) { Value = (object)host ?? DBNull.Value },
            new SqlParameter("@UserAgent", SqlDbType.NVarChar, 1024) { Value = (object)userAgent ?? DBNull.Value },
            new SqlParameter("@StatusCode", SqlDbType.Int) { Value = statusCode },
            new SqlParameter("@BodyDetection", SqlDbType.NVarChar, 50) { Value = (object)bodyDetection ?? DBNull.Value },
            new SqlParameter("@RequestBodySize", SqlDbType.Int) { Value = requestBodySize },
            new SqlParameter("@ResponseBodySize", SqlDbType.Int) { Value = responseBodySize }
        };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error inserting HTTP log: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Updates an existing HTTP log in the database
        /// </summary>
        /// <param name="httpLogId">The unique identifier of the HTTP log to update</param>
        /// <param name="logId">The associated log identifier</param>
        /// <param name="method">The updated HTTP method</param>
        /// <param name="url">The updated URL</param>
        /// <param name="host">The updated host header</param>
        /// <param name="userAgent">The updated user agent string</param>
        /// <param name="statusCode">The updated HTTP status code</param>
        /// <param name="bodyDetection">The updated body detection information</param>
        /// <param name="requestBodySize">The updated request body size in bytes</param>
        /// <param name="responseBodySize">The updated response body size in bytes</param>
        /// <returns>True if the update was successful, otherwise false</returns>
        public static bool Update(int httpLogId, int logId, string method, string url, string host, string userAgent, int statusCode, string bodyDetection, int requestBodySize, int responseBodySize)
        {
            try
            {
                string queryStr = @"
UPDATE HttpLogs
SET LogID = @LogID,
    Method = @Method,
    Url = @Url,
    Host = @Host,
    UserAgent = @UserAgent,
    StatusCode = @StatusCode,
    BodyDetection = @BodyDetection,
    RequestBodySize = @RequestBodySize,
    ResponseBodySize = @ResponseBodySize
WHERE HttpLogID = @HttpLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@HttpLogID", SqlDbType.Int) { Value = httpLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@Method", SqlDbType.NVarChar, 10) { Value = (object)method ?? DBNull.Value },
            new SqlParameter("@Url", SqlDbType.NVarChar, 2048) { Value = (object)url ?? DBNull.Value },
            new SqlParameter("@Host", SqlDbType.NVarChar, 255) { Value = (object)host ?? DBNull.Value },
            new SqlParameter("@UserAgent", SqlDbType.NVarChar, 1024) { Value = (object)userAgent ?? DBNull.Value },
            new SqlParameter("@StatusCode", SqlDbType.Int) { Value = statusCode },
            new SqlParameter("@BodyDetection", SqlDbType.NVarChar,50) { Value = (object)bodyDetection ?? DBNull.Value },
            new SqlParameter("@RequestBodySize", SqlDbType.Int) { Value = requestBodySize },
            new SqlParameter("@ResponseBodySize", SqlDbType.Int) { Value = responseBodySize }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating HTTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Deletes an HTTP log from the database
        /// </summary>
        /// <param name="httpLogId">The unique identifier of the HTTP log to delete</param>
        /// <returns>True if the deletion was successful, otherwise false</returns>
        public static bool Delete(int httpLogId)
        {
            try
            {
                string query = "DELETE FROM HttpLogs WHERE HttpLogID = @HttpLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@HttpLogID", SqlDbType.Int) { Value = httpLogId }
                };

                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting HTTP log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an HTTP log by its associated log identifier
        /// </summary>
        /// <param name="logId">The log identifier to search for</param>
        /// <returns>An HttpLog object if found, otherwise null</returns>
        public static HttpLog GetByLogId(int logId)
        {
            HttpLog log = null;
            try
            {
                string query = "SELECT * FROM HttpLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new HttpLog(
                        (int)row["HttpLogID"],
                        (int)row["LogID"],
                        row["Method"].ToString(),
                        row["Url"].ToString(),
                        row["Host"].ToString(),
                        row["UserAgent"].ToString(),
                        (int)row["StatusCode"],
                        row["BodyDetection"].ToString(),
                        (int)row["RequestBodySize"],
                        (int)row["ResponseBodySize"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching HTTP log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}