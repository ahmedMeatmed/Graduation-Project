using IDSApp.Helper;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DBL
{
    /// <summary>
    /// Provides database helper methods for executing queries, non-queries, and parameterized commands.
    /// </summary>
    internal static class DBL
    {
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
