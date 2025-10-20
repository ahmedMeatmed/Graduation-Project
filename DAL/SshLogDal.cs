using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for SSH log operations in the database.
    /// </summary>
    internal class SshLogDal
    {
        /// <summary>
        /// Retrieves all SSH logs from the database.
        /// </summary>
        /// <returns>A collection of SshLog objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static SshLogCollection GetAll()
        {
            SshLogCollection list = new SshLogCollection();
            try
            {
                string query = "SELECT * FROM SshLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    SshLog log = new SshLog(
                        (int)row["SshLogID"],
                        (int)row["LogID"],
                        row["ClientVersion"].ToString(),
                        row["ServerVersion"].ToString(),
                        Convert.ToInt32(row["AuthAttempts"])
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SSH logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific SSH log by its unique identifier.
        /// </summary>
        /// <param name="id">The SshLogID of the record to retrieve.</param>
        /// <returns>An SshLog object if found; otherwise, null.</returns>
        public static SshLog GetById(int id)
        {
            SshLog log = null;
            try
            {
                string query = "SELECT * FROM SshLogs WHERE SshLogID = @SshLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SshLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new SshLog(
                        (int)row["SshLogID"],
                        (int)row["LogID"],
                        row["ClientVersion"].ToString(),
                        row["ServerVersion"].ToString(),
                        Convert.ToInt32(row["AuthAttempts"])
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SSH log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new SSH log record into the database.
        /// </summary>
        /// <param name="logId">The associated LogID.</param>
        /// <param name="clientVersion">The SSH client version string.</param>
        /// <param name="serverVersion">The SSH server version string.</param>
        /// <param name="authAttempts">The number of authentication attempts made.</param>
        /// <returns>The newly created SshLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string clientVersion, string serverVersion, int authAttempts)
        {
            try
            {
                string query = @"INSERT INTO SshLogs (LogID, ClientVersion, ServerVersion, AuthAttempts)
                                 VALUES (@LogID, @ClientVersion, @ServerVersion, @AuthAttempts);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@ClientVersion", SqlDbType.NVarChar, 255) { Value = clientVersion },
                    new SqlParameter("@ServerVersion", SqlDbType.NVarChar, 255) { Value = serverVersion },
                    new SqlParameter("@AuthAttempts", SqlDbType.Int) { Value = authAttempts }
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting SSH log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes a specific SSH log record from the database.
        /// </summary>
        /// <param name="sshLogId">The SshLogID of the record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int sshLogId)
        {
            try
            {
                string query = "DELETE FROM SshLogs WHERE SshLogID = @SshLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@SshLogID", SqlDbType.Int) { Value = sshLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting SSH log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing SSH log record in the database.
        /// </summary>
        /// <param name="sshLogId">The SshLogID of the record to update.</param>
        /// <param name="logId">The new LogID value.</param>
        /// <param name="clientVersion">The new SSH client version string.</param>
        /// <param name="serverVersion">The new SSH server version string.</param>
        /// <param name="authAttempts">The new number of authentication attempts.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int sshLogId, int logId, string clientVersion, string serverVersion, int authAttempts)
        {
            try
            {
                string queryStr = @"
            UPDATE SshLogs
            SET LogID = @LogID,
                ClientVersion = @ClientVersion,
                ServerVersion = @ServerVersion,
                AuthAttempts = @AuthAttempts
            WHERE SshLogID = @SshLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@SshLogID", SqlDbType.Int) { Value = sshLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@ClientVersion", SqlDbType.NVarChar, 255) { Value = clientVersion },
            new SqlParameter("@ServerVersion", SqlDbType.NVarChar, 255) { Value = serverVersion },
            new SqlParameter("@AuthAttempts", SqlDbType.Int) { Value = authAttempts }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating SSH log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves an SSH log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for.</param>
        /// <returns>An SshLog object if found; otherwise, null.</returns>
        public static SshLog GetByLogId(int logId)
        {
            SshLog log = null;
            try
            {
                string query = "SELECT * FROM SshLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new SshLog(
                        (int)row["SshLogID"],
                        (int)row["LogID"],
                        row["ClientVersion"].ToString(),
                        row["ServerVersion"].ToString(),
                        (int)row["AuthAttempts"]
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching SSH log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}