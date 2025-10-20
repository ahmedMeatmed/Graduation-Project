using IDSApp.Collection;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.DAL
{
    /// <summary>
    /// Provides data access methods for TLS (Transport Layer Security) log operations in the database.
    /// </summary>
    internal class TlsLogDal
    {
        /// <summary>
        /// Retrieves all TLS logs from the database.
        /// </summary>
        /// <returns>A collection of TlsLog objects. Returns an empty collection if no records are found or if an error occurs.</returns>
        public static TlsLogCollection GetAll()
        {
            TlsLogCollection list = new TlsLogCollection();
            try
            {
                string query = "SELECT * FROM TlsLogs";
                DataTable dt = DBL.DBL.ExecuteQuery(query);

                foreach (DataRow row in dt.Rows)
                {
                    TlsLog log = new TlsLog(
                        (int)row["TlsLogID"],
                        (int)row["LogID"],
                        row["SNI"].ToString(),
                        row["Version"].ToString(),
                        row["CipherSuite"].ToString(),
                        row["CertFingerprint"].ToString(),
                        row["Ja3Fingerprint"].ToString(),
                        row["CertCN"].ToString(),
                        row["Issuer"].ToString()
                    );
                    list.Add(log);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching TLS logs: " + ex.Message);
            }
            return list;
        }

        /// <summary>
        /// Retrieves a specific TLS log by its unique identifier.
        /// </summary>
        /// <param name="id">The TlsLogID of the record to retrieve.</param>
        /// <returns>A TlsLog object if found; otherwise, null.</returns>
        public static TlsLog GetById(int id)
        {
            TlsLog log = null;
            try
            {
                string query = "SELECT * FROM TlsLogs WHERE TlsLogID = @TlsLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@TlsLogID", SqlDbType.Int) { Value = id }
                };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new TlsLog(
                        (int)row["TlsLogID"],
                        (int)row["LogID"],
                        row["SNI"].ToString(),
                        row["Version"].ToString(),
                        row["CipherSuite"].ToString(),
                        row["CertFingerprint"].ToString(),
                        row["Ja3Fingerprint"].ToString(),
                        row["CertCN"].ToString(),
                        row["Issuer"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching TLS log by ID: " + ex.Message);
            }
            return log;
        }

        /// <summary>
        /// Inserts a new TLS log record into the database.
        /// </summary>
        /// <param name="logId">The associated LogID.</param>
        /// <param name="sni">The Server Name Indication (SNI) from the TLS handshake.</param>
        /// <param name="version">The TLS protocol version (e.g., TLS 1.2, TLS 1.3).</param>
        /// <param name="cipherSuite">The cipher suite negotiated for the connection.</param>
        /// <param name="certFingerprint">The fingerprint/hash of the server certificate.</param>
        /// <param name="ja3Fingerprint">The JA3 fingerprint for TLS client identification.</param>
        /// <param name="certCn">The Common Name (CN) from the server certificate.</param>
        /// <param name="issuer">The certificate issuer (Certificate Authority).</param>
        /// <returns>The newly created TlsLogID if successful; otherwise, -1.</returns>
        public static int Insert(int logId, string sni, string version, string cipherSuite, string certFingerprint, string ja3Fingerprint, string certCn, string issuer)
        {
            try
            {
                string query = @"INSERT INTO TlsLogs (LogID, SNI, Version, CipherSuite, CertFingerprint, Ja3Fingerprint, CertCN, Issuer)
                                 VALUES (@LogID, @SNI, @Version, @CipherSuite, @CertFingerprint, @Ja3Fingerprint, @CertCN, @Issuer);
                                 SELECT SCOPE_IDENTITY();";

                SqlParameter[] parameters = {
                    new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
                    new SqlParameter("@SNI", SqlDbType.NVarChar, 255) { Value = sni },
                    new SqlParameter("@Version", SqlDbType.NVarChar, 20) { Value = version },
                    new SqlParameter("@CipherSuite", SqlDbType.NVarChar, 255) { Value = cipherSuite },
                    new SqlParameter("@CertFingerprint", SqlDbType.NVarChar, 255) { Value = certFingerprint },
                    new SqlParameter("@Ja3Fingerprint", SqlDbType.NVarChar, 255) { Value = ja3Fingerprint },
                    new SqlParameter("@CertCN", SqlDbType.NVarChar, 255) { Value = certCn },
                    new SqlParameter("@Issuer", SqlDbType.NVarChar, 255) { Value = issuer },
                };

                object result = DBL.DBL.ExecuteScalarWithParameters(query, parameters);
                return Convert.ToInt32(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error inserting TLS log: " + ex.Message);
                return -1;
            }
        }

        /// <summary>
        /// Deletes a specific TLS log record from the database.
        /// </summary>
        /// <param name="tlsLogId">The TlsLogID of the record to delete.</param>
        /// <returns>true if the record was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int tlsLogId)
        {
            try
            {
                string query = "DELETE FROM TlsLogs WHERE TlsLogID = @TlsLogID";
                SqlParameter[] parameters = {
                    new SqlParameter("@TlsLogID", SqlDbType.Int) { Value = tlsLogId }
                };
                int rows = DBL.DBL.ExecuteNonQueryWithParameters(query, parameters);
                return rows > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error deleting TLS log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Updates an existing TLS log record in the database.
        /// </summary>
        /// <param name="tlsLogId">The TlsLogID of the record to update.</param>
        /// <param name="logId">The new LogID value.</param>
        /// <param name="sni">The new Server Name Indication (SNI).</param>
        /// <param name="version">The new TLS protocol version.</param>
        /// <param name="cipherSuite">The new cipher suite.</param>
        /// <param name="certFingerprint">The new certificate fingerprint.</param>
        /// <param name="ja3Fingerprint">The new JA3 fingerprint.</param>
        /// <param name="certCn">The new certificate Common Name.</param>
        /// <param name="issuer">The new certificate issuer.</param>
        /// <returns>true if the record was successfully updated; otherwise, false.</returns>
        public static bool Update(int tlsLogId, int logId, string sni, string version, string cipherSuite, string certFingerprint, string ja3Fingerprint, string certCn, string issuer)
        {
            try
            {
                string queryStr = @"
            UPDATE TlsLogs
            SET LogID = @LogID,
                SNI = @SNI,
                Version = @Version,
                CipherSuite = @CipherSuite,
                CertFingerprint = @CertFingerprint,
                Ja3Fingerprint = @Ja3Fingerprint,
                CertCN = @CertCN,
                Issuer = @Issuer
            WHERE TlsLogID = @TlsLogID";

                SqlParameter[] parameters = {
            new SqlParameter("@TlsLogID", SqlDbType.Int) { Value = tlsLogId },
            new SqlParameter("@LogID", SqlDbType.Int) { Value = logId },
            new SqlParameter("@SNI", SqlDbType.NVarChar, 255) { Value = sni },
            new SqlParameter("@Version", SqlDbType.NVarChar, 20) { Value = version },
            new SqlParameter("@CipherSuite", SqlDbType.NVarChar, 255) { Value = cipherSuite },
            new SqlParameter("@CertFingerprint", SqlDbType.NVarChar, 255) { Value = certFingerprint },
            new SqlParameter("@Ja3Fingerprint", SqlDbType.NVarChar, 255) { Value = ja3Fingerprint },
            new SqlParameter("@CertCN", SqlDbType.NVarChar, 255) { Value = certCn },
            new SqlParameter("@Issuer", SqlDbType.NVarChar, 255) { Value = issuer }
        };

                int rowsAffected = DBL.DBL.ExecuteNonQueryWithParameters(queryStr, parameters);
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error updating TLS log: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Retrieves a TLS log by its associated LogID.
        /// </summary>
        /// <param name="logId">The LogID to search for.</param>
        /// <returns>A TlsLog object if found; otherwise, null.</returns>
        public static TlsLog GetByLogId(int logId)
        {
            TlsLog log = null;
            try
            {
                string query = "SELECT * FROM TlsLogs WHERE LogID = @LogID";
                SqlParameter[] parameters = { new SqlParameter("@LogID", logId) };
                DataTable dt = DBL.DBL.ExecuteQueryWithParameters(query, parameters);

                if (dt.Rows.Count > 0)
                {
                    DataRow row = dt.Rows[0];
                    log = new TlsLog(
                        (int)row["TlsLogID"],
                        (int)row["LogID"],
                        row["SNI"].ToString(),
                        row["Version"].ToString(),
                        row["CipherSuite"].ToString(),
                        row["CertFingerprint"].ToString(),
                        row["Ja3Fingerprint"].ToString(),
                        row["CertCN"].ToString(),
                        row["Issuer"].ToString()
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching TLS log by LogID: " + ex.Message);
            }
            return log;
        }
    }
}