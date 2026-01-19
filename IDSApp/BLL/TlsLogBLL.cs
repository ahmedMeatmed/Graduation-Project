using IDSApp.Collection;
using IDSApp.DAL;
using IDSApp.Entity;
using Microsoft.Data.SqlClient;
using System;
using System.Data;

namespace IDSApp.BLL
{
    /// <summary>
    /// Provides business logic layer operations for TLS (Transport Layer Security) log management in the intrusion detection system.
    /// This class serves as a facade to the data access layer, providing a clean API for TLS log-related operations.
    /// </summary>
    internal class TlsLogBLL
    {
        /// <summary>
        /// Retrieves all TLS logs from the system.
        /// </summary>
        /// <returns>A collection of TlsLog objects containing all TLS logs in the system.</returns>
        public static TlsLogCollection GetAll()
        {
            return TlsLogDal.GetAll();
        }

        /// <summary>
        /// Retrieves a specific TLS log by its unique identifier.
        /// </summary>
        /// <param name="id">The TlsLogID of the TLS log to retrieve.</param>
        /// <returns>A TlsLog object if found; otherwise, null.</returns>
        public static TlsLog GetById(int id)
        {
            return TlsLogDal.GetById(id);
        }

        /// <summary>
        /// Creates a new TLS log entry in the system.
        /// </summary>
        /// <param name="logId">The associated LogID from the original log entry.</param>
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
            return TlsLogDal.Insert(logId, sni, version, cipherSuite, certFingerprint, ja3Fingerprint, certCn, issuer);
        }

        /// <summary>
        /// Deletes a specific TLS log from the system.
        /// </summary>
        /// <param name="tlsLogId">The TlsLogID of the TLS log to delete.</param>
        /// <returns>true if the TLS log was successfully deleted; otherwise, false.</returns>
        public static bool Delete(int tlsLogId)
        {
            return TlsLogDal.Delete(tlsLogId);
        }

        /// <summary>
        /// Updates an existing TLS log entry with new information.
        /// </summary>
        /// <param name="tlsLogId">The TlsLogID of the TLS log to update.</param>
        /// <param name="logId">The new associated LogID.</param>
        /// <param name="sni">The updated Server Name Indication.</param>
        /// <param name="version">The updated TLS protocol version.</param>
        /// <param name="cipherSuite">The updated cipher suite.</param>
        /// <param name="certFingerprint">The updated certificate fingerprint.</param>
        /// <param name="ja3Fingerprint">The updated JA3 fingerprint.</param>
        /// <param name="certCn">The updated certificate Common Name.</param>
        /// <param name="issuer">The updated certificate issuer.</param>
        /// <returns>true if the TLS log was successfully updated; otherwise, false.</returns>
        public static bool Update(int tlsLogId, int logId, string sni, string version, string cipherSuite, string certFingerprint, string ja3Fingerprint, string certCn, string issuer)
        {
            return TlsLogDal.Update(tlsLogId, logId, sni, version, cipherSuite, certFingerprint, ja3Fingerprint, certCn, issuer);
        }
    }
}