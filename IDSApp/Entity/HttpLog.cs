using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents an HTTP (Hypertext Transfer Protocol) log entry captured by the Intrusion Detection System.
    /// Contains detailed information about web requests and responses for monitoring web traffic,
    /// detecting web-based attacks, and analyzing potential security threats.
    /// </summary>
    internal class HttpLog
    {
        int httpLogId;
        int logId;
        string method;
        string url;
        string host;
        string userAgent;
        int? statusCode;
        string bodyDetection;
        int requestBodySize;
        int responseBodySize;

        /// <summary>Unique identifier for the HTTP log entry</summary>
        public int HttpLogId { get => httpLogId; set => httpLogId = value; }

        /// <summary>Reference identifier linking to the main system log entry</summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>HTTP method used in the request (e.g., GET, POST, PUT, DELETE, HEAD, OPTIONS)</summary>
        public string Method { get => method; set => method = value; }

        /// <summary>Full URL or path that was requested</summary>
        public string Url { get => url; set => url = value; }

        /// <summary>Host header value from the HTTP request</summary>
        public string Host { get => host; set => host = value; }

        /// <summary>User-Agent string identifying the client software making the request</summary>
        public string UserAgent { get => userAgent; set => userAgent = value; }

        /// <summary>HTTP status code returned by the server (e.g., 200, 404, 500, 302, 403)</summary>
        public int? StatusCode { get => statusCode; set => statusCode = value; }

        /// <summary>Detection results from scanning request/response bodies for malicious content</summary>
        public string BodyDetection { get => bodyDetection; set => bodyDetection = value; }

        /// <summary>Size of the HTTP request body in bytes</summary>
        public int RequestBodySize { get => requestBodySize; set => requestBodySize = value; }

        /// <summary>Size of the HTTP response body in bytes</summary>
        public int ResponseBodySize { get => responseBodySize; set => responseBodySize = value; }

        /// <summary>
        /// Initializes a new instance of the HttpLog class with specified parameters.
        /// </summary>
        /// <param name="httpLogId">Unique identifier for the HTTP log entry</param>
        /// <param name="logId">Reference identifier linking to the main system log</param>
        /// <param name="method">HTTP method used in the request</param>
        /// <param name="url">Full URL or path that was requested</param>
        /// <param name="host">Host header value from the HTTP request</param>
        /// <param name="userAgent">User-Agent string identifying the client software</param>
        /// <param name="statusCode">HTTP status code returned by the server</param>
        /// <param name="bodyDetection">Detection results from scanning request/response bodies</param>
        /// <param name="requestBodySize">Size of the HTTP request body in bytes</param>
        /// <param name="responseBodySize">Size of the HTTP response body in bytes</param>
        internal HttpLog(int httpLogId, int logId, string method, string url, string host, string userAgent,
                        int? statusCode, string bodyDetection, int requestBodySize, int responseBodySize)
        {
            this.httpLogId = httpLogId;
            this.logId = logId;
            this.method = method;
            this.url = url;
            this.host = host;
            this.userAgent = userAgent;
            this.statusCode = statusCode;
            this.bodyDetection = bodyDetection;
            this.requestBodySize = requestBodySize;
            this.responseBodySize = responseBodySize;
        }

        /// <summary>
        /// Initializes a new instance of the HttpLog class as a copy of an existing HttpLog object.
        /// </summary>
        /// <param name="h">Source HttpLog object to copy from</param>
        internal HttpLog(HttpLog h)
            : this(h.httpLogId, h.logId, h.method, h.url, h.host, h.userAgent, h.statusCode,
                  h.bodyDetection, h.requestBodySize, h.responseBodySize)
        {
        }

        /// <summary>
        /// Creates a deep copy of the current HttpLog instance.
        /// </summary>
        /// <returns>A new HttpLog object that is an exact copy of the current instance</returns>
        public HttpLog Clone()
        {
            return new HttpLog(this);
        }
    }
}