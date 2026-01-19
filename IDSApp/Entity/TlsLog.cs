using IDSApp.Collection;
using System;

namespace IDSApp.Entity
{
    /// <summary>
    /// Represents a log entry for TLS (Transport Layer Security) activity.
    /// Contains information about the SNI, TLS version, cipher suite, certificate details, and fingerprints.
    /// </summary>
    internal class TlsLog
    {
        private int tlsLogId;
        private int logId;
        private string sni;
        private string version;
        private string cipherSuite;
        private string certFingerprint;
        private string ja3Fingerprint;
        private string certCN;
        private string issuer;

        /// <summary>
        /// Gets or sets the unique identifier for this TLS log entry.
        /// </summary>
        public int TlsLogId { get => tlsLogId; set => tlsLogId = value; }

        /// <summary>
        /// Gets or sets the associated general log entry ID.
        /// </summary>
        public int LogId { get => logId; set => logId = value; }

        /// <summary>
        /// Gets or sets the Server Name Indication (SNI) for the TLS connection.
        /// </summary>
        public string SNI { get => sni; set => sni = value; }

        /// <summary>
        /// Gets or sets the TLS version used in the connection.
        /// </summary>
        public string Version { get => version; set => version = value; }

        /// <summary>
        /// Gets or sets the cipher suite negotiated during the TLS connection.
        /// </summary>
        public string CipherSuite { get => cipherSuite; set => cipherSuite = value; }

        /// <summary>
        /// Gets or sets the fingerprint of the certificate used in the TLS connection.
        /// </summary>
        public string CertFingerprint { get => certFingerprint; set => certFingerprint = value; }

        /// <summary>
        /// Gets or sets the JA3 fingerprint of the TLS client hello.
        /// </summary>
        public string Ja3Fingerprint { get => ja3Fingerprint; set => ja3Fingerprint = value; }

        /// <summary>
        /// Gets or sets the Common Name (CN) of the certificate.
        /// </summary>
        public string CertCN { get => certCN; set => certCN = value; }

        /// <summary>
        /// Gets or sets the issuer of the certificate.
        /// </summary>
        public string Issuer { get => issuer; set => issuer = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TlsLog"/> class with specified values.
        /// </summary>
        internal TlsLog(int tlsLogId, int logId, string sni, string version, string cipherSuite, string certFingerprint, string ja3Fingerprint, string certCN, string issuer)
        {
            this.tlsLogId = tlsLogId;
            this.logId = logId;
            this.sni = sni;
            this.version = version;
            this.cipherSuite = cipherSuite;
            this.certFingerprint = certFingerprint;
            this.ja3Fingerprint = ja3Fingerprint;
            this.certCN = certCN;
            this.issuer = issuer;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TlsLog"/> class by copying another instance.
        /// </summary>
        /// <param name="t">The <see cref="TlsLog"/> instance to copy.</param>
        internal TlsLog(TlsLog t) : this(t.tlsLogId, t.logId, t.sni, t.version, t.cipherSuite, t.certFingerprint, t.ja3Fingerprint, t.certCN, t.issuer) { }

        /// <summary>
        /// Creates a deep copy of the current <see cref="TlsLog"/> instance.
        /// </summary>
        /// <returns>A new <see cref="TlsLog"/> object identical to the current instance.</returns>
        public TlsLog Clone() => new TlsLog(this);
    }
}
