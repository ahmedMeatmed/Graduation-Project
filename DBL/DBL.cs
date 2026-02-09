using System;
using System.Data;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.SqlClient;

namespace IDSApp.DBL
{
    /// <summary>
    /// Database & Redis helper.
    /// SQL methods are disabled (return dummy values) to avoid DB writes.
    /// Redis methods push logs to Laravel-compatible list.
    /// </summary>
    internal static class DBL
    {
        // --- Redis settings ---
        public static string RedisHost = "127.0.0.1";
        public static int RedisPort = 6379;
        public static int RedisDB = 0;
        // Redis DB index (matches SELECT in Laravel config)
        public static int RedisDb = 0;
        // Optional password for AUTH (set if your Redis requires a password)
        public static string RedisPassword = null;
        public static string RedisListKey = "aegis_database_ids_logs";

        /// <summary>
        /// Push a log string into Redis list
        /// </summary>
        public static int PushLog(string log)
        {
            return PushToRedis(RedisListKey, log);
        }

        private static int PushToRedis(string key, string value)
        {
            try
            {
                using var tcp = new TcpClient();
                tcp.Connect(RedisHost, RedisPort);
                var ns = tcp.GetStream();

                // If password provided, AUTH first
                if (!string.IsNullOrEmpty(RedisPassword))
                {
                    string authCmd = BuildRespArray(new[] { "AUTH", RedisPassword });
                    string authResp = WriteAndRead(ns, authCmd);
                    if (string.IsNullOrEmpty(authResp) || !(authResp.StartsWith("+OK") || authResp.StartsWith("+")))
                        throw new Exception("Redis AUTH failed: " + authResp);
                }

                // SELECT DB if not zero
                if (RedisDb != 0)
                {
                    string selCmd = BuildRespArray(new[] { "SELECT", RedisDb.ToString() });
                    string selResp = WriteAndRead(ns, selCmd);
                    if (string.IsNullOrEmpty(selResp) || !(selResp.StartsWith("+OK") || selResp.StartsWith(":")))
                        throw new Exception("Redis SELECT failed: " + selResp);
                }

                // Select DB
                string selectCmd = BuildRespArray(new[] { "SELECT", RedisDB.ToString() });
                ns.Write(Encoding.UTF8.GetBytes(selectCmd), 0, Encoding.UTF8.GetByteCount(selectCmd));
                ns.Read(new byte[1024], 0, 1024);

                // RPUSH
                string rpushCmd = BuildRespArray(new[] { "RPUSH", key, value });
                ns.Write(Encoding.UTF8.GetBytes(rpushCmd), 0, Encoding.UTF8.GetByteCount(rpushCmd));

                byte[] buf = new byte[1024];
                int read = ns.Read(buf, 0, buf.Length);
                if (read <= 0) return 0;

                string resp = Encoding.UTF8.GetString(buf, 0, read);
                return resp.Length > 0 && (resp[0] == '+' || resp[0] == ':') ? 1 : 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Redis push failed: " + ex.Message);
                return 0;
            }
        }

        private static string WriteAndRead(NetworkStream ns, string cmd)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(cmd);
            ns.Write(bytes, 0, bytes.Length);
            // Read reply (up to 8KB)
            byte[] buf = new byte[8192];
            int read = 0;
            // Wait briefly for reply data
            int timeoutMs = 500;
            DateTime start = DateTime.UtcNow;
            while (DateTime.UtcNow - start < TimeSpan.FromMilliseconds(timeoutMs))
            {
                if (ns.DataAvailable)
                {
                    read = ns.Read(buf, 0, buf.Length);
                    break;
                }
                Thread.Sleep(10);
            }
            if (read <= 0) return string.Empty;
            return Encoding.UTF8.GetString(buf, 0, read);
        }
        private static string BuildRespArray(string[] parts)
        {
            var sb = new StringBuilder();
            sb.Append("*").Append(parts.Length).Append("\r\n");
            foreach (var p in parts)
            {
                var bytes = Encoding.UTF8.GetBytes(p ?? string.Empty);
                sb.Append("$").Append(bytes.Length).Append("\r\n");
                sb.Append(p ?? string.Empty).Append("\r\n");
            }
            return sb.ToString();
        }

        // --- SQL Methods ---
        private static string conStr = "Data Source=DESKTOP-RL48M7M\\SQLEXPRESS;Initial Catalog=IDS;Integrated Security=True;Trust Server Certificate=True";

        /// <summary>
        /// Executes a SQL query and returns the result as a <see cref="DataTable"/>.
        /// </summary>
        /// <param name="command">The SQL query to execute.</param>
        /// <returns>A <see cref="DataTable"/> containing the query results.</returns>
        public static DataTable ExecuteQuery(string command)
        {
            DataTable dt = new DataTable();
            SqlDataAdapter adpt = new SqlDataAdapter(command, conStr);
            adpt.Fill(dt);
            return dt;
        }

        /// <summary>
        /// Executes a SQL non-query command (INSERT, UPDATE, DELETE) and returns the number of affected rows.
        /// </summary>
        /// <param name="command">The SQL command to execute.</param>
        /// <returns>The number of rows affected.</returns>
        public static int ExecuteNonQuery(string command)
            {
                using SqlConnection con = new SqlConnection(conStr);
                using SqlCommand cmd = new SqlCommand(command, con);
                con.Open();
                int noOfRows = cmd.ExecuteNonQuery();
                return noOfRows;
            }

        /// <summary>
        /// Executes a SQL query and returns the first row of the result, or null if no rows exist.
        /// </summary>
        /// <param name="command">The SQL query to execute.</param>
        /// <returns>The first row as an <see cref="object"/> or null if no rows exist.</returns>
        public static object ExecuteReader(string command)
        {
            DataTable dt = ExecuteQuery(command);
            object result = null;
            if (dt.Rows.Count > 0)
            {
                result = dt.Rows[0];
            }
            return result;
        }

        /// <summary>
        /// Executes a parameterized SQL query and returns the result as a <see cref="DataTable"/>.
        /// </summary>
        /// <param name="query">The SQL query to execute.</param>
        /// <param name="parameters">An array of <see cref="SqlParameter"/> objects.</param>
        /// <returns>A <see cref="DataTable"/> containing the query results.</returns>
        internal static DataTable ExecuteQueryWithParameters(string query, SqlParameter[] parameters)
        {
            DataTable dt = new DataTable();
            try
            {
                using SqlConnection con = new SqlConnection(conStr);
                using SqlDataAdapter adpt = new SqlDataAdapter(query, con);
                adpt.SelectCommand.Parameters.AddRange(parameters);
                adpt.Fill(dt);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error executing query: " + ex.Message);
            }
            return dt;
        }

        /// <summary>
        /// Executes a parameterized SQL non-query command (INSERT, UPDATE, DELETE) and returns the number of affected rows.
        /// </summary>
        /// <param name="query">The SQL command to execute.</param>
        /// <param name="parameters">An array of <see cref="SqlParameter"/> objects.</param>
        /// <returns>The number of rows affected.</returns>
        public static int ExecuteNonQueryWithParameters(string query, SqlParameter[] parameters)
        {
            using SqlConnection conn = new SqlConnection(conStr);
            using SqlCommand cmd = new SqlCommand(query, conn);
            cmd.Parameters.AddRange(parameters);
            conn.Open();
            return cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Executes a parameterized SQL scalar query and returns the first column of the first row in the result set.
        /// </summary>
        /// <param name="query">The SQL query to execute.</param>
        /// <param name="parameters">An array of <see cref="SqlParameter"/> objects.</param>
        /// <returns>The value of the first column in the first row, or null if an error occurs or no rows exist.</returns>
        internal static object ExecuteScalarWithParameters(string query, SqlParameter[] parameters)
        {
            const int maxRetries = 3;
            int attempt = 0;

            while (true)
            {
                try
                {
                    using (SqlConnection conn = new SqlConnection(conStr))
                    using (SqlCommand cmd = new SqlCommand(query, conn))
                    {
                        cmd.CommandType = CommandType.Text;
                        if (parameters != null)
                            cmd.Parameters.AddRange(parameters);

                        conn.Open();
                        return cmd.ExecuteScalar();
                    }
                }
                catch (SqlException ex)
                {
                    // سجل رقم الخطأ لتعرف السبب الحقيقي
                    OptimizedLogger.LogError(
                        $"[DBL] SQL Error (Number={ex.Number}, State={ex.State}): {ex.Message}"
                    );

                    // لو الخطأ مؤقت (timeouts أو deadlocks) نحاول تكرار العملية
                    if (ex.Number == -2 || ex.Number == 1205 || ex.Number == 4060 || ex.Number == 233)
                    {
                        attempt++;
                        if (attempt < maxRetries)
                        {
                            Thread.Sleep(200 * attempt); // تأخير متزايد بسيط
                            continue;
                        }
                    }

                    // بعد 3 محاولات أو خطأ غير مؤقت
                    return null;
                }
                catch (Exception ex)
                {
                    OptimizedLogger.LogError($"[DBL] General Error executing scalar query: {ex.Message}");
                    return null;
                }
            }
        }
    }
}
