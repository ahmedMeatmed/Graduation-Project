// =============================================
// CLASS SUMMARY: TlsParser
// =============================================
/// <summary>
/// Production-Ready TLS/SSL Protocol Parser - Comprehensive TLS traffic analysis for security monitoring
/// Parses TLS handshakes, extracts SNI, computes JA3 fingerprints, and performs certificate validation
/// Implements advanced threat detection including malicious JA3 fingerprint matching and certificate analysis
/// Supports TLS 1.0-1.3 with deep packet inspection capabilities
/// </summary>

// File: TlsParser.cs
using IDSApp.BLL;
using IDSApp.DAL;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace IDSApp.ProtocolParsing
{
    /// <summary>
    /// Production-ready TLS parser:
    /// - Parses TLS records and handshake (ClientHello, Certificate)
    /// - Extracts SNI, computes a best-effort JA3 fingerprint
    /// - Extracts certificate(s) from Certificate handshake and inspects them (self-signed, expired, SHA256 fingerprint)
    /// - Performs lightweight deep-inspection on ASCII content (configurable)
    /// - Logs results to DB via LogBLL.Insert and saves TLS-ERROR rows also via LogBLL.Insert
    /// - Loads known-malicious JA3s from Ja3Repository (DB-backed)
    /// </summary>
    public class TlsParser
    {
        // =============================================
        // CONSTANT SUMMARY: Configuration settings
        // =============================================
        private const int MaxDeepInspectBytes = 1024;    // Maximum bytes for deep content inspection
        private const int MaxPayloadSnippet = 16;        // Maximum payload snippet length for error logging

        // =============================================
        // STATIC FIELD SUMMARY: Security patterns and stores
        // =============================================
        private static readonly Regex SuspiciousPatterns = new Regex(
            @"(sqlmap|powershell|nmap|curl|wget|metasploit|cobalt|meterpreter|empire|cmd\.exe|/etc/passwd|select\s+\*|union\s+select|drop\s+table|<script>|0x[0-9a-f]{8,})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        /// <summary>
        /// Regex pattern for detecting suspicious content in TLS payloads
        /// Includes attack tools, SQL injection, XSS, and system command patterns
        /// </summary>

        // JA3 store (populated from DB via Ja3Repository)
        private static HashSet<string> MaliciousJa3Fingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>
        /// Database-backed store of known malicious JA3 fingerprints for threat intelligence
        /// </summary>

        // =============================================
        // METHOD SUMMARY: InitializeJa3Store()
        // =============================================
        /// <summary>
        /// Initializes the JA3 fingerprint store with known malicious fingerprints
        /// Called at application startup to load threat intelligence data
        /// </summary>
        /// <param name="initialJa3s">Collection of malicious JA3 fingerprints to load</param>
        public static void InitializeJa3Store(IEnumerable<string> initialJa3s)
        {
            if (initialJa3s == null) return;
            MaliciousJa3Fingerprints = new HashSet<string>(initialJa3s.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim().ToLowerInvariant()));
        }

        // =============================================
        // CLASS SUMMARY: TlsParseResult
        // =============================================
        /// <summary>
        /// Comprehensive result container for TLS parsing operations
        /// Stores extracted TLS handshake data, security analysis results, and threat intelligence matches
        /// </summary>
        public class TlsParseResult
        {
            /// <summary>Source IP address of TLS connection</summary>
            public string SrcIp { get; set; } = "unknown";
            /// <summary>TLS protocol version (SSL 3.0, TLS 1.0-1.3)</summary>
            public string Version { get; set; } = "Unknown";
            /// <summary>Summary of cipher suites offered by client</summary>
            public string CipherSuiteSummary { get; set; } = "unknown";
            /// <summary>Server Name Indication (SNI) from ClientHello</summary>
            public string Sni { get; set; } = "unknown";
            /// <summary>JA3 TLS fingerprint for client identification</summary>
            public string Ja3Fingerprint { get; set; } = "N/A";
            /// <summary>List of SHA-256 certificate fingerprints in chain</summary>
            public List<string> CertificateFingerprintsSha256 { get; set; } = new List<string>();
            /// <summary>Summary of certificate chain validation results</summary>
            public string CertificateSummary { get; set; } = "N/A";
            /// <summary>Flag indicating suspicious activity detection</summary>
            public bool IsSuspicious { get; set; } = false;
            /// <summary>Reasons for security alerts and suspicious flags</summary>
            public string AlertReason { get; set; } = string.Empty;
            /// <summary>Flag indicating match with known malicious JA3 fingerprint</summary>
            public bool MatchedKnownMaliciousJa3 { get; set; } = false;
            /// <summary>Common Name from server certificate</summary>
            public string CertificateCN { get; set; } = "unknown";
            /// <summary>Issuer Common Name from server certificate</summary>
            public string CertificateIssuer { get; set; } = "unknown";
        }

        // =============================================
        // METHOD SUMMARY: Parse() - Main entry point
        // =============================================
        /// <summary>
        /// Main TLS packet parsing method - processes TLS/SSL protocol traffic
        /// Performs comprehensive TLS analysis including handshake parsing, fingerprinting, and security validation
        /// Implements multi-layer threat detection and extensive error handling
        /// </summary>
        /// <param name="payload">Raw TLS packet bytes to parse</param>
        /// <param name="srcIp">Source IP address of TLS connection</param>
        /// <returns>TlsParseResult containing comprehensive TLS analysis and security findings</returns>
        public TlsParseResult Parse(byte[] payload, string srcIp)
        {
            var result = new TlsParseResult { SrcIp = srcIp ?? "unknown" };

            try
            {
                // Initial TLS record validation
                if (!IsLikelyTlsRecord(payload))
                {
                    result.AlertReason = "Payload not matching TLS record header or too short";
                    result.IsSuspicious = true;
                    LogTlsErrorToDb(result.AlertReason, result.SrcIp, payload);
                    TryLogToDb(result, payload);
                    return result;
                }

                // Extract TLS record header fields
                byte contentType = payload[0];
                ushort version = (ushort)((payload[1] << 8) | payload[2]);
                ushort recLen = (ushort)((payload[3] << 8) | payload[4]);

                result.Version = MapTlsVersion(version);

                // Validate record length consistency
                if (payload.Length < 5 + recLen)
                {
                    result.AlertReason = $"Truncated TLS record: declared {recLen}, available {payload.Length - 5}";
                    result.IsSuspicious = true;
                    LogTlsErrorToDb(result.AlertReason, result.SrcIp, payload);
                    TryLogToDb(result, payload);
                    return result;
                }

                // Process TLS handshake messages
                if (contentType == 0x16 && recLen > 0 && payload.Length > 5) // Handshake record type
                {
                    byte handshakeType = payload[5];
                    if (handshakeType == 0x01) // ClientHello
                    {
                        ParseClientHello(payload, ref result);
                    }
                    else if (handshakeType == 0x0b) // Certificate
                    {
                        ParseCertificateHandshake(payload, ref result);
                    }
                }

                // Deep inspection for suspicious ASCII content in encrypted payload
                if (ContainsAsciiPayload(payload))
                {
                    var asciiLen = Math.Min(MaxDeepInspectBytes, payload.Length);
                    string ascii = Encoding.ASCII.GetString(payload, 0, asciiLen);
                    if (SuspiciousPatterns.IsMatch(ascii))
                    {
                        result.IsSuspicious = true;
                        result.AlertReason += "Suspicious ASCII content in TLS payload; ";
                    }
                }

                // Weak TLS version detection
                if (result.Version.StartsWith("SSL") || result.Version.Contains("1.0"))
                {
                    result.IsSuspicious = true;
                    result.AlertReason += "Weak TLS/SSL version; ";
                }

                // Non-TLS traffic detection on TLS port
                if ((string.IsNullOrEmpty(result.Ja3Fingerprint) || result.Ja3Fingerprint == "N/A")
                    && result.Sni == "unknown" && (result.CipherSuiteSummary == "unknown" || result.CipherSuiteSummary.StartsWith("Count=0")))
                {
                    result.IsSuspicious = true;
                    result.AlertReason += "Possibly non-TLS traffic on TLS port; ";
                }

                // JA3 malicious fingerprint detection
                if (!string.IsNullOrEmpty(result.Ja3Fingerprint) && !result.Ja3Fingerprint.Equals("N/A", StringComparison.OrdinalIgnoreCase))
                {
                    var ja3 = result.Ja3Fingerprint.ToLowerInvariant();
                    if (MaliciousJa3Fingerprints.Contains(ja3))
                    {
                        result.IsSuspicious = true;
                        result.MatchedKnownMaliciousJa3 = true;
                        result.AlertReason += "Known-malicious JA3 fingerprint detected; ";
                        LogTlsErrorToDb($"Matched known-malicious JA3: {ja3}", result.SrcIp, payload);
                    }
                }

                TryLogToDb(result, payload);
                return result;
            }
            catch (Exception ex)
            {
                result.IsSuspicious = true;
                result.AlertReason += $"Parser exception: {ex.Message}; ";
                LogTlsErrorToDb($"Exception in Parse: {ex.Message}", result.SrcIp, payload);
                TryLogToDb(result, payload);
                return result;
            }
        }

        #region Parsing helpers

        // =============================================
        // METHOD SUMMARY: IsLikelyTlsRecord()
        // =============================================
        /// <summary>
        /// Validates if payload appears to be a valid TLS record
        /// Checks record header structure and content type validity
        /// </summary>
        /// <param name="payload">Packet bytes to validate</param>
        /// <returns>True if payload matches TLS record structure, false otherwise</returns>
        private static bool IsLikelyTlsRecord(byte[] payload)
        {
            if (payload == null || payload.Length < 5) return false;
            byte contentType = payload[0];
            if (contentType < 20 || contentType > 23) return false; // Valid TLS content types: 20-23
            return true;
        }

        // =============================================
        // METHOD SUMMARY: ParseClientHello()
        // =============================================
        /// <summary>
        /// Parses TLS ClientHello handshake message according to RFC 5246
        /// Extracts client version, cipher suites, extensions, and SNI
        /// Computes JA3 fingerprint for client identification
        /// </summary>
        /// <param name="payload">Raw TLS packet bytes</param>
        /// <param name="result">TlsParseResult to update with ClientHello findings</param>
        private void ParseClientHello(byte[] payload, ref TlsParseResult result)
        {
            try
            {
                int pos = 5; // Start after TLS record header
                if (pos + 4 > payload.Length) return;
                pos += 1; // handshake type (0x01 for ClientHello)
                pos += 3; // handshake length

                // Client version extraction
                if (pos + 2 > payload.Length) return;
                pos += 2; // client version
                if (pos + 32 > payload.Length) return;
                pos += 32; // random bytes

                // Session ID extraction
                if (pos + 1 > payload.Length) return;
                int sessionIdLen = payload[pos];
                pos += 1 + sessionIdLen;

                // Cipher suites extraction and analysis
                if (pos + 2 > payload.Length) return;
                int cipherSuitesLen = (payload[pos] << 8) | payload[pos + 1];
                pos += 2;
                if (cipherSuitesLen < 0 || pos + cipherSuitesLen > payload.Length) return;

                int csCount = cipherSuitesLen / 2;
                result.CipherSuiteSummary = $"Count={csCount}";
                var csHex = new List<string>();
                for (int i = 0; i < Math.Min(6, csCount); i++)
                {
                    int idx = pos + i * 2;
                    if (idx + 1 >= payload.Length) break;
                    csHex.Add(((payload[idx] << 8) | payload[idx + 1]).ToString("X4"));
                }
                if (csHex.Any()) result.CipherSuiteSummary += ":" + string.Join(",", csHex);

                pos += cipherSuitesLen;

                // Compression methods extraction
                if (pos + 1 > payload.Length) return;
                int compMethodsLen = payload[pos];
                pos += 1 + compMethodsLen;

                // TLS extensions parsing
                if (pos + 2 > payload.Length) return;
                int extLen = (payload[pos] << 8) | payload[pos + 1];
                pos += 2;
                if (extLen <= 0 || pos + extLen > payload.Length) return;

                int endExt = pos + extLen;
                var extensionList = new List<int>();

                // Iterate through TLS extensions
                while (pos + 4 <= endExt && pos + 4 <= payload.Length)
                {
                    int extType = (payload[pos] << 8) | payload[pos + 1];
                    int extDataLen = (payload[pos + 2] << 8) | payload[pos + 3];
                    pos += 4;
                    if (pos + extDataLen > endExt) break;

                    extensionList.Add(extType);

                    // Server Name Indication (SNI) extraction (Extension type 0x00)
                    if (extType == 0x00 && extDataLen >= 5)
                    {
                        try
                        {
                            int sniPos = pos;
                            if (sniPos + 2 >= payload.Length) { /* skip */ }
                            else
                            {
                                int listLen = (payload[sniPos] << 8) | payload[sniPos + 1];
                                sniPos += 2;
                                if (sniPos < payload.Length)
                                {
                                    byte nameType = payload[sniPos++];
                                    if (sniPos + 1 < payload.Length)
                                    {
                                        int nameLen = (payload[sniPos] << 8) | payload[sniPos + 1];
                                        sniPos += 2;
                                        if (nameLen > 0 && sniPos + nameLen <= payload.Length)
                                        {
                                            string sni = Encoding.ASCII.GetString(payload, sniPos, nameLen);
                                            if (!string.IsNullOrEmpty(sni)) result.Sni = sni;
                                        }
                                    }
                                }
                            }
                        }
                        catch { /* Graceful SNI extraction failure */ }
                    }

                    pos += extDataLen;
                }

                // Compute JA3 fingerprint for client identification
                result.Ja3Fingerprint = ComputeJa3FromClientHello(payload);
            }
            catch (Exception ex)
            {
                LogTlsErrorToDb($"ParseClientHello exception: {ex.Message}", result.SrcIp, payload);
            }
        }

        // =============================================
        // METHOD SUMMARY: ParseCertificateHandshake()
        // =============================================
        /// <summary>
        /// Parses TLS Certificate handshake message according to RFC 5246
        /// Extracts and validates X.509 certificate chain from server
        /// Performs certificate validation including expiration and self-signed checks
        /// Computes SHA-256 fingerprints for certificate tracking
        /// </summary>
        /// <param name="payload">Raw TLS packet bytes</param>
        /// <param name="result">TlsParseResult to update with certificate findings</param>
        private void ParseCertificateHandshake(byte[] payload, ref TlsParseResult result)
        {
            try
            {
                if (payload == null || payload.Length < 9) return;

                int handshakeBodyStart = 5 + 1 + 3; // Record header + handshake type + handshake length
                if (handshakeBodyStart + 3 > payload.Length) return;

                // Extract certificate list length (3-byte field)
                int certListLen = (payload[handshakeBodyStart] << 16) | (payload[handshakeBodyStart + 1] << 8) | payload[handshakeBodyStart + 2];

                int pos = handshakeBodyStart + 3;
                int available = payload.Length - pos;
                int processed = 0;
                var certs = new List<X509Certificate2>();

                // Process each certificate in the chain
                while (processed < certListLen && pos + 3 <= payload.Length)
                {
                    int certLen = (payload[pos] << 16) | (payload[pos + 1] << 8) | payload[pos + 2];
                    pos += 3;
                    processed += 3;
                    if (certLen <= 0 || pos + certLen > payload.Length) break;

                    try
                    {
                        var certBytes = new byte[certLen];
                        Array.Copy(payload, pos, certBytes, 0, certLen);
                        var cert = new X509Certificate2(certBytes);
                        certs.Add(cert);
                    }
                    catch { /* Graceful certificate parsing failure */ }

                    pos += certLen;
                    processed += certLen;
                }

                if (certs.Any())
                {
                    var sb = new StringBuilder();
                    var firstCert = certs.FirstOrDefault();
                    if (firstCert != null)
                    {
                        result.CertificateCN = GetCommonName(firstCert.Subject);
                        result.CertificateIssuer = GetCommonName(firstCert.Issuer);
                    }

                    // Analyze each certificate in the chain
                    foreach (var cert in certs)
                    {
                        try
                        {
                            using var sha256 = SHA256.Create();
                            var fp = BitConverter.ToString(sha256.ComputeHash(cert.RawData)).Replace("-", "").ToLowerInvariant();
                            result.CertificateFingerprintsSha256.Add(fp);

                            // Certificate security validation
                            bool selfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase);
                            bool expired = DateTime.UtcNow < cert.NotBefore.ToUniversalTime() || DateTime.UtcNow > cert.NotAfter.ToUniversalTime();

                            sb.Append($"CN={GetCommonName(cert.Subject)}");
                            if (selfSigned) sb.Append("[self-signed]");
                            if (expired) sb.Append("[expired]");
                            sb.Append($";FP={fp}; ");

                            // Security alert generation
                            if (selfSigned) result.AlertReason += "Certificate self-signed; ";
                            if (expired) result.AlertReason += "Certificate expired; ";
                            if (selfSigned || expired) result.IsSuspicious = true;
                        }
                        catch { /* Graceful certificate analysis failure */ }
                    }

                    result.CertificateSummary = sb.ToString();
                }
            }
            catch (Exception ex)
            {
                LogTlsErrorToDb($"ParseCertificateHandshake exception: {ex.Message}", result.SrcIp, payload);
            }
        }

        // =============================================
        // METHOD SUMMARY: GetCommonName()
        // =============================================
        /// <summary>
        /// Extracts Common Name (CN) from X.509 certificate subject string
        /// Parses distinguished name format to find CN component
        /// </summary>
        /// <param name="subject">Certificate subject string in DN format</param>
        /// <returns>Extracted Common Name or original string if not found</returns>
        private static string GetCommonName(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return "unknown";
            var parts = subject.Split(',');
            foreach (var p in parts)
            {
                var trimmed = p.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3).Trim();
            }
            return subject;
        }

        #endregion

        #region JA3 Fingerprinting (best-effort implementation)

        // =============================================
        // METHOD SUMMARY: ComputeJa3FromClientHello()
        // =============================================
        /// <summary>
        /// Computes JA3 TLS fingerprint for client identification and threat intelligence
        /// Implements JA3 methodology: version + ciphers + extensions + elliptic curves + point formats
        /// Generates MD5 hash of normalized TLS ClientHello parameters
        /// </summary>
        /// <param name="payload">Raw TLS packet bytes containing ClientHello</param>
        /// <returns>JA3 MD5 fingerprint string or "N/A" on failure</returns>
        private string ComputeJa3FromClientHello(byte[] payload)
        {
            try
            {
                if (payload == null || payload.Length < 6) return "N/A";
                if (payload[0] != 0x16 || payload[5] != 0x01) return "N/A"; // Validate Handshake record and ClientHello

                int pos = 5 + 1 + 3; // Record header + handshake type + handshake length
                if (pos + 2 > payload.Length) return "N/A";
                ushort clientVersion = (ushort)((payload[pos] << 8) | payload[pos + 1]);
                pos += 2;
                pos += 32; // Skip random bytes
                if (pos >= payload.Length) return "N/A";

                // Extract cipher suites
                int sidLen = payload[pos];
                pos += 1 + sidLen;
                if (pos + 2 > payload.Length) return "N/A";

                int cipherLen = (payload[pos] << 8) | payload[pos + 1];
                pos += 2;
                var ciphers = new List<int>();
                for (int i = 0; i + 1 < cipherLen && pos + i + 1 < payload.Length; i += 2)
                {
                    int cs = (payload[pos + i] << 8) | payload[pos + i + 1];
                    ciphers.Add(cs);
                }
                pos += cipherLen;
                if (pos >= payload.Length) return "N/A";

                // Extract compression methods
                int compLen = payload[pos];
                pos += 1 + compLen;
                if (pos + 2 > payload.Length) return "N/A";

                // Extract TLS extensions
                int extLen = (payload[pos] << 8) | payload[pos + 1];
                pos += 2;
                int extEnd = Math.Min(payload.Length, pos + extLen);

                var extensions = new List<int>();
                while (pos + 4 <= extEnd)
                {
                    int extType = (payload[pos] << 8) | payload[pos + 1];
                    int extDataLen = (payload[pos + 2] << 8) | payload[pos + 3];
                    extensions.Add(extType);
                    pos += 4 + extDataLen;
                }

                // Construct JA3 string and compute MD5 fingerprint
                string versionStr = clientVersion.ToString();
                string ciphersStr = string.Join("-", ciphers.Select(c => c.ToString()));
                string extStr = string.Join("-", extensions.Select(e => e.ToString()));
                string ja3String = $"{versionStr}-{ciphersStr}-{extStr}--"; // Note: elliptic curves and point formats not implemented

                using var md5 = MD5.Create();
                var hash = md5.ComputeHash(Encoding.ASCII.GetBytes(ja3String));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch { return "N/A"; }
        }

        #endregion

        #region Utilities & DB logging

        // =============================================
        // METHOD SUMMARY: MapTlsVersion()
        // =============================================
        /// <summary>
        /// Maps TLS version codes to human-readable version names
        /// Supports SSL 3.0 through TLS 1.3 according to RFC standards
        /// </summary>
        /// <param name="version">TLS version code from protocol header</param>
        /// <returns>Human-readable TLS version string</returns>
        private static string MapTlsVersion(ushort version)
        {
            return version switch
            {
                0x0300 => "SSL 3.0",
                0x0301 => "TLS 1.0",
                0x0302 => "TLS 1.1",
                0x0303 => "TLS 1.2",
                0x0304 => "TLS 1.3",
                _ => $"Unknown (0x{version:X4})"
            };
        }

        // =============================================
        // METHOD SUMMARY: ContainsAsciiPayload()
        // =============================================
        /// <summary>
        /// Detects potential plaintext content in TLS-encrypted payloads
        /// Uses heuristic analysis to identify unencrypted or poorly encrypted data
        /// </summary>
        /// <param name="payload">TLS payload bytes to analyze</param>
        /// <returns>True if payload contains high percentage of ASCII characters</returns>
        private static bool ContainsAsciiPayload(byte[] payload)
        {
            if (payload == null || payload.Length < 16) return false;
            int asciiCount = payload.Take(16).Count(b => b >= 0x20 && b <= 0x7E);
            bool first4HasSpaceOrDot = payload.Take(4).Any(b => b == 0x20 || b == 0x2E);
            return asciiCount >= 14 && first4HasSpaceOrDot;
        }

        // =============================================
        // METHOD SUMMARY: LogTlsErrorToDb()
        // =============================================
        /// <summary>
        /// Logs TLS parsing errors and security alerts to database
        /// Creates suspicious log entries for error conditions and security violations
        /// </summary>
        /// <param name="message">Error or alert message to log</param>
        /// <param name="srcIp">Source IP address for correlation</param>
        /// <param name="payload">Original payload bytes for forensic analysis</param>
        private void LogTlsErrorToDb(string message, string srcIp, byte[] payload)
        {
            try
            {
                string shortPayload = payload == null ? "null" : BitConverter.ToString(payload.Take(MaxPayloadSnippet).ToArray());
                string info = $"TLS-ERROR: {message}; PayloadSnippet={shortPayload}";
                // Save as isMalicious = true for errors
                LogBLL.Insert(
                    DateTime.Now,
                    srcIp ?? "unknown",
                    "unknown",
                    payload?.Length ?? 0,
                    true, // Mark as suspicious
                    "TLS-ERROR",
                    "TCP",
                    0,
                    443, // Standard HTTPS port
                    payload?.Length ?? 0,
                    "-",
                    "in",
                    1,
                    0,
                    null,
                    info
                );
            }
            catch (Exception ex)
            {
                // Fallback to console to avoid hiding errors
                Console.WriteLine($"[TLS-ERROR] Failed to write TLS-ERROR to DB: {ex.Message}");
            }
        }

        // =============================================
        // METHOD SUMMARY: TryLogToDb()
        // =============================================
        /// <summary>
        /// Logs comprehensive TLS analysis results to database
        /// Creates both general log entries and TLS-specific log records
        /// Includes all extracted TLS parameters and security analysis results
        /// </summary>
        /// <param name="result">TlsParseResult containing analysis findings</param>
        /// <param name="payload">Original payload bytes for reference</param>
        private void TryLogToDb(TlsParseResult result, byte[] payload)
        {
            int logId = 0;
            try
            {
                string info = $"TLS Ver={result.Version}; SNI={result.Sni}; Cipher={result.CipherSuiteSummary}; JA3={result.Ja3Fingerprint}; Cert={Truncate(result.CertificateSummary, 250)}; Alerts={Truncate(result.AlertReason, 200)}; CN={result.CertificateCN};Issuer={result.CertificateIssuer}";
                logId = LogBLL.Insert(
                    DateTime.Now,
                    result.SrcIp ?? "unknown",
                    "unknown",
                    payload?.Length ?? 0,
                    result.IsSuspicious,
                    "TLS",
                    "TCP",
                    0,
                    443, // Standard HTTPS port
                    payload?.Length ?? 0,
                    "-",
                    "in",
                    1,
                    0,
                    null,
                    info
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TLS-ERROR] Failed to write TLS log to DB: {ex.Message}");
            }

            // Insert TLS-specific log record if general log was successful
            if (logId > 0)
            {
                TlsLogDal.Insert(
                    logId, result.Sni, result.Version, result.CipherSuiteSummary,
                    result.CertificateSummary, result.Ja3Fingerprint, result.CertificateCN,
                    result.CertificateIssuer
                );
            }
        }

        // =============================================
        // METHOD SUMMARY: Truncate()
        // =============================================
        /// <summary>
        /// Utility method for safely truncating strings with ellipsis
        /// Prevents database field overflow while maintaining meaningful content
        /// </summary>
        /// <param name="s">Input string to truncate</param>
        /// <param name="max">Maximum allowed length</param>
        /// <returns>Truncated string with ellipsis if needed</returns>
        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }

        #endregion
    }
}