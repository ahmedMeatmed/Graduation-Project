using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for HTTP log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for HTTP log-related operations.
    /// </summary>
    internal class HttpLogBLL
    {
        /// <summary>
        /// Retrieves all HTTP logs from the system.
        /// </summary>
        /// <returns>A collection of HttpLog objects containing all HTTP logs in the system.</returns>
        public static HttpLogCollection GetAll()
        {
            return HttpLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific HTTP log by its unique identifier.
        /// </summary>
        /// <param name="id">The HttpLogID of the HTTP log to retrieve.</param>
        /// <returns>An HttpLog object if found; otherwise, null.</returns>
        public static HttpLog GetById(int id)
        {
            return HttpLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new HTTP log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
        /// <param name="method">The HTTP method used in the request (e.g., GET, POST, PUT, DELETE).</param>
        /// <param name="url">The URL that was requested.</param>
        /// <param name="host">The Host header value from the HTTP request.</param>
        /// <param name="userAgent">The User-Agent string identifying the client software.</param>
        /// <param name="statusCode">The HTTP status code returned by the server (e.g., 200, 404, 500).</param>
        /// <param name="bodyDetection">Detection results from analyzing the request/response body for suspicious content.</param>
        /// <param name="requestBodySize">The size of the request body in bytes.</param>
        /// <param name="responseBodySize">The size of the response body in bytes.</param>
        /// <returns>The newly created HttpLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string method, string url, string host, string userAgent, int statusCode, string bodyDetection, int requestBodySize, int responseBodySize)
        {
            return HttpLogDal.Insert(logId, method, url, host, userAgent, statusCode, bodyDetection, requestBodySize, responseBodySize);
        }

        /// <summary>
        /// Deletes a specific HTTP log from the system.
        /// </summary>
        /// <param name="httpLogId">The HttpLogID of the HTTP log to delete.</param>
        /// <returns>true if the HTTP log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int httpLogId)
        {
            return HttpLogDal.Delete(httpLogId);
        }

        /// <summary>
        /// Updates an existing HTTP log entry with new information.
        /// </summary>
        /// <param name="httpLogId">The HttpLogID of the HTTP log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="method">The updated HTTP method.</param>
        /// <param name="url">The updated URL.</param>
        /// <param name="host">The updated Host header value.</param>
        /// <param name="userAgent">The updated User-Agent string.</param>
        /// <param name="statusCode">The updated HTTP status code.</param>
        /// <param name="bodyDetection">The updated body detection results.</param>
        /// <param name="requestBodySize">The updated request body size in bytes.</param>
        /// <param name="responseBodySize">The updated response body size in bytes.</param>
        /// <returns>true if the HTTP log was successfully updated; otherwise, false.</returns>
        public static bool Update(int httpLogId, int logId, string method, string url, string host, string userAgent, int statusCode, string bodyDetection, int requestBodySize, int responseBodySize)
        {
            return HttpLogDal.Update(httpLogId, logId, method, url, host, userAgent, statusCode, bodyDetection, requestBodySize, responseBodySize);
        }
    }
}