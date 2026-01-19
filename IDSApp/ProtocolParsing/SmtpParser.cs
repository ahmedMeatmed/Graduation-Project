using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;

namespace IDSApp.ProtocolParsing
{
    /// <summary>
    /// Enhanced SMTP Parser with better session tracking and reduced false positives
    /// </summary>
    public class SmtpParser
    {
        private static readonly string[] SuspiciousKeywords =
            { "password", "urgent", "invoice", "bank", "login", "confidential", "verify", "phish", "alert" };

        private static readonly string[] SuspiciousExtensions =
            { ".exe", ".bat", ".cmd", ".js", ".vbs", ".scr", ".jar", ".ps1", ".hta", ".lnk" };

        private static readonly Regex MimeEncodedWordRegex =
            new(@"=\?([^?]+)\?([BbQq])\?([^?]+)\?=", RegexOptions.Compiled);

        private static readonly Regex Base64Regex =
            new(@"^[A-Za-z0-9+/]*={0,3}$", RegexOptions.Compiled);

        private static readonly Regex EmailAddressRegex =
            new(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled);

        // Session state tracking
        private readonly Dictionary<string, SmtpSession> _sessions = new();

        public SmtpParseResult Parse(byte[] payload, string srcIp, string dstIp, int srcPort, int dstPort)
        {
            var result = new SmtpParseResult();
            string sessionKey = $"{srcIp}:{srcPort}-{dstIp}:{dstPort}";

            try
            {
                if (payload == null || payload.Length == 0)
                {
                    result.Subject = "empty payload";
                    return result;
                }

                // Initialize or get session state
                if (!_sessions.ContainsKey(sessionKey))
                {
                    _sessions[sessionKey] = new SmtpSession();
                }
                var session = _sessions[sessionKey];

                // ============================================================
                // STEP 1: More accurate TLS detection
                // ============================================================
                if (IsTlsHandshake(payload))
                {
                    result.Subject = "Encrypted SMTP (TLS/SMTPS session)";
                    result.IsEncrypted = true;
                    result.FromAddress = "encrypted-session";
                    result.ToAddress = "encrypted-session";
                    session.IsEncrypted = true;
                    return result;
                }

                // If session is already encrypted, don't try to parse
                if (session.IsEncrypted)
                {
                    result.Subject = "Encrypted session data";
                    result.IsEncrypted = true;
                    result.FromAddress = "encrypted-session";
                    result.ToAddress = "encrypted-session";
                    return result;
                }

                // ============================================================
                // STEP 2: Improved text detection with better heuristics
                // ============================================================
                string text;
                try
                {
                    text = Encoding.UTF8.GetString(payload);
                }
                catch
                {
                    text = Encoding.ASCII.GetString(payload);
                }

                text = text.Trim();

                // More sophisticated text detection
                if (!IsLikelyText(payload, text))
                {
                    result.Subject = "Binary data";
                    result.IsEncrypted = false; // Don't assume it's encrypted
                    return result;
                }

                var lines = text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);
                var subjectLines = new List<string>();
                bool inHeaders = false;
                string currentHeader = null;

                // ============================================================
                // STEP 3: Enhanced SMTP command parsing
                // ============================================================
                foreach (var line in lines)
                {
                    string trimmed = line.Trim();

                    if (string.IsNullOrEmpty(trimmed))
                        continue;

                    // SMTP Commands (usually 4 letters followed by space)
                    if (trimmed.Length >= 4 && char.IsLetter(trimmed[0]) &&
                        char.IsLetter(trimmed[1]) && char.IsLetter(trimmed[2]) &&
                        char.IsLetter(trimmed[3]) && (trimmed.Length == 4 || trimmed[4] == ' '))
                    {
                        ParseSmtpCommand(trimmed, result, session);
                        inHeaders = false;
                        continue;
                    }

                    // Email headers (after DATA command)
                    if (inHeaders || session.InDataPhase)
                    {
                        ParseEmailHeader(trimmed, result, subjectLines, ref currentHeader);
                    }

                    // Response codes (3 digits)
                    if (trimmed.Length >= 3 && char.IsDigit(trimmed[0]) &&
                        char.IsDigit(trimmed[1]) && char.IsDigit(trimmed[2]))
                    {
                        ParseSmtpResponse(trimmed, session);
                    }
                }

                // ============================================================
                // STEP 4: Process extracted data
                // ============================================================
                result.Subject = ProcessSubject(subjectLines);

                // Use session data if command parsing didn't find addresses
                if (string.IsNullOrEmpty(result.FromAddress) && !string.IsNullOrEmpty(session.MailFrom))
                    result.FromAddress = session.MailFrom;

                if (string.IsNullOrEmpty(result.ToAddress) && session.RcptTo.Count > 0)
                    result.ToAddress = string.Join(";", session.RcptTo.Take(3)); // Limit to first 3

                PerformSecurityChecks(result);

                // Set defaults
                if (string.IsNullOrEmpty(result.FromAddress))
                    result.FromAddress = "unknown";
                if (string.IsNullOrEmpty(result.ToAddress))
                    result.ToAddress = "unknown";
                if (string.IsNullOrEmpty(result.Subject))
                    result.Subject = "none";

                // Clean up completed sessions
                if (session.IsComplete)
                {
                    _sessions.Remove(sessionKey);
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Subject = "SMTP Parse Error: " + ex.Message;
                result.IsSuspicious = false;
                return result;
            }
        }

        private bool IsTlsHandshake(byte[] payload)
        {
            if (payload.Length < 3) return false;

            // TLS handshake starts with 0x16 (handshake) followed by 0x03 (SSL/TLS version)
            if (payload[0] == 0x16 && (payload[1] == 0x03 || payload[1] == 0x02 || payload[1] == 0x01))
                return true;

            // Also check for application data (0x17)
            if (payload[0] == 0x17 && (payload[1] == 0x03 || payload[1] == 0x02 || payload[1] == 0x01))
                return true;

            return false;
        }

        private bool IsLikelyText(byte[] payload, string text)
        {
            if (payload.Length == 0) return false;

            int printable = 0;
            int control = 0;
            int nullBytes = 0;

            foreach (byte b in payload)
            {
                if (b == 0) nullBytes++;
                else if (b >= 32 && b <= 126) printable++;
                else if (b == 9 || b == 10 || b == 13) printable++; // tab, LF, CR
                else if (b < 32) control++;
            }

            // Too many null bytes suggests binary data
            if ((double)nullBytes / payload.Length > 0.1)
                return false;

            // Good ratio of printable characters
            double printableRatio = (double)printable / payload.Length;
            return printableRatio > 0.7; // More lenient threshold
        }

        private void ParseSmtpCommand(string line, SmtpParseResult result, SmtpSession session)
        {
            string upperLine = line.ToUpperInvariant();

            if (upperLine.StartsWith("EHLO") || upperLine.StartsWith("HELO"))
            {
                result.SessionInfo = line;
                session.HasHelo = true;
            }
            else if (upperLine.StartsWith("MAIL FROM:"))
            {
                string fromPart = line.Substring(10).Trim();
                var emailMatch = EmailAddressRegex.Match(fromPart);
                if (emailMatch.Success)
                {
                    result.FromAddress = emailMatch.Value;
                    session.MailFrom = emailMatch.Value;
                }
                else
                {
                    result.FromAddress = fromPart.Trim('<', '>', ' ');
                    session.MailFrom = fromPart.Trim('<', '>', ' ');
                }
            }
            else if (upperLine.StartsWith("RCPT TO:"))
            {
                string toPart = line.Substring(8).Trim();
                var emailMatch = EmailAddressRegex.Match(toPart);
                if (emailMatch.Success)
                {
                    session.RcptTo.Add(emailMatch.Value);
                }
                else
                {
                    session.RcptTo.Add(toPart.Trim('<', '>', ' '));
                }
            }
            else if (upperLine.StartsWith("DATA"))
            {
                session.InDataPhase = true;
            }
            else if (upperLine.StartsWith("QUIT"))
            {
                session.IsComplete = true;
            }
            else if (upperLine.StartsWith("AUTH"))
            {
                result.HasAuthAttempt = true;
                result.AuthCommand = line;
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("smtp_auth_detected");

                if (upperLine.Contains("LOGIN")) result.AuthMethod = "LOGIN";
                else if (upperLine.Contains("PLAIN")) result.AuthMethod = "PLAIN";
                else if (upperLine.Contains("XOAUTH2")) result.AuthMethod = "XOAUTH2";
                else result.AuthMethod = "OTHER";

                // Check for base64 credentials in AUTH PLAIN
                if (upperLine.StartsWith("AUTH PLAIN"))
                {
                    string[] parts = line.Split(' ');
                    if (parts.Length > 2 && Base64Regex.IsMatch(parts[2]))
                    {
                        string decoded = TryDecodeBase64(parts[2]);
                        if (!string.IsNullOrEmpty(decoded))
                        {
                            // PLAIN auth format: \0username\0password
                            string[] authParts = decoded.Split('\0');
                            if (authParts.Length >= 3)
                            {
                                result.DecodedCredentials["username"] = authParts[1];
                                result.DecodedCredentials["password"] = "(hidden)";
                                result.SuspicionReasons.Add("plain_auth_credentials");
                            }
                        }
                    }
                }
            }
            else if (upperLine.StartsWith("STARTTLS"))
            {
                result.IsStartTls = true;
                result.Subject = "STARTTLS negotiation";
                session.ExpectingStartTls = true;
            }
        }

        private void ParseEmailHeader(string line, SmtpParseResult result, List<string> subjectLines, ref string currentHeader)
        {
            if (line.Contains(":"))
            {
                int colonIndex = line.IndexOf(':');
                currentHeader = line.Substring(0, colonIndex).Trim();
                string value = line.Substring(colonIndex + 1).Trim();

                if (currentHeader.Equals("Subject", StringComparison.OrdinalIgnoreCase))
                {
                    subjectLines.Add(value);
                }
                else if (currentHeader.Equals("From", StringComparison.OrdinalIgnoreCase))
                {
                    var match = EmailAddressRegex.Match(value);
                    if (match.Success && string.IsNullOrEmpty(result.FromAddress))
                    {
                        result.FromAddress = match.Value;
                    }
                }
                else if (currentHeader.Equals("To", StringComparison.OrdinalIgnoreCase))
                {
                    var matches = EmailAddressRegex.Matches(value);
                    if (matches.Count > 0 && string.IsNullOrEmpty(result.ToAddress))
                    {
                        result.ToAddress = string.Join(";", matches.Cast<Match>().Select(m => m.Value));
                    }
                }
            }
            else if (currentHeader == "Subject" && (line.StartsWith(" ") || line.StartsWith("\t")))
            {
                subjectLines.Add(line.Trim());
            }
            else
            {
                currentHeader = null;
            }
        }

        private void ParseSmtpResponse(string line, SmtpSession session)
        {
            if (line.StartsWith("220") && session.ExpectingStartTls)
            {
                session.IsEncrypted = true;
                session.ExpectingStartTls = false;
            }
            else if (line.StartsWith("235")) // Authentication successful
            {
                session.IsAuthenticated = true;
            }
        }

        private string ProcessSubject(List<string> subjectLines)
        {
            if (subjectLines.Count == 0) return null;

            string combinedSubject = string.Join(" ", subjectLines);
            return DecodeMimeWords(combinedSubject);
        }

        // ============================================================
        // Existing helper methods (keep these from your original code)
        // ============================================================
        private static string TryDecodeBase64(string base64)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(base64);
                string decoded = Encoding.UTF8.GetString(bytes);
                if (decoded.Any(c => char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsWhiteSpace(c)))
                    return decoded;
            }
            catch { }
            return null;
        }

        private static string DecodeMimeWords(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return input ?? "";
            return MimeEncodedWordRegex.Replace(input, m =>
            {
                try
                {
                    string charset = m.Groups[1].Value;
                    string encoding = m.Groups[2].Value.ToUpperInvariant();
                    string encodedText = m.Groups[3].Value;
                    byte[] bytes = encoding == "B"
                        ? Convert.FromBase64String(encodedText)
                        : DecodeQuotedPrintable(encodedText);
                    Encoding enc = Encoding.GetEncoding(charset);
                    return enc.GetString(bytes);
                }
                catch { return m.Value; }
            });
        }

        private static byte[] DecodeQuotedPrintable(string input)
        {
            using var ms = new MemoryStream();
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == '=' && i + 2 < input.Length)
                {
                    string hex = input.Substring(i + 1, 2);
                    if (byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out byte val))
                        ms.WriteByte(val);
                    i += 2;
                }
                else ms.WriteByte((byte)input[i]);
            }
            return ms.ToArray();
        }

        private void PerformSecurityChecks(SmtpParseResult result)
        {
            string lower = result.Subject?.ToLowerInvariant() ?? "";
            foreach (var keyword in SuspiciousKeywords)
            {
                if (lower.Contains(keyword))
                {
                    result.IsSuspicious = true;
                    result.SuspicionReasons.Add($"keyword_in_subject:{keyword}");
                }
            }

            if (result.HasAuthAttempt && !result.IsEncrypted && !result.IsStartTls)
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("auth_without_tls");
            }
        }

        // Session state class to track SMTP conversation
        private class SmtpSession
        {
            public bool IsEncrypted { get; set; }
            public bool InDataPhase { get; set; }
            public bool HasHelo { get; set; }
            public bool IsAuthenticated { get; set; }
            public bool ExpectingStartTls { get; set; }
            public bool IsComplete { get; set; }
            public string MailFrom { get; set; } = "";
            public List<string> RcptTo { get; set; } = new List<string>();
        }
    }

    // Keep your existing SmtpParseResult class
    public class SmtpParseResult
    {
        public string FromAddress { get; set; } = "unknown";
        public string ToAddress { get; set; } = "unknown";
        public string Subject { get; set; } = "none";
        public string SessionInfo { get; set; } = "";
        public string AuthCommand { get; set; } = "";
        public string AuthMethod { get; set; } = "";
        public bool HasAuthAttempt { get; set; } = false;
        public bool IsStartTls { get; set; } = false;
        public bool IsEncrypted { get; set; } = false;
        public bool IsSuspicious { get; set; } = false;
        public Dictionary<string, string> DecodedCredentials { get; set; } = new();
        public List<string> SuspicionReasons { get; set; } = new();

        public override string ToString()
        {
            var creds = DecodedCredentials.Count > 0
                ? string.Join(", ", DecodedCredentials.Select(kv => $"{kv.Key}={kv.Value}"))
                : "none";

            return $"From={FromAddress}, To={ToAddress}, Subject={Subject}, Auth={AuthMethod}, Encrypted={IsEncrypted}, Suspicious={IsSuspicious}, Reasons=[{string.Join(',', SuspicionReasons)}], Credentials=[{creds}]";
        }
    }
}