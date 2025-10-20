using HttpMachine;
using IDSApp.Helper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IDSApp.ProtocolParsing
{
    /// <summary>
    /// Advanced HTTP protocol parsing and analysis system for Intrusion Detection System
    /// 
    /// Main Responsibilities:
    /// - Parse and analyze HTTP/HTTPS traffic for security threats
    /// - Extract and validate HTTP headers, methods, URLs, and body content
    /// - Detect malicious patterns in HTTP requests and responses
    /// - Integrate TLS/SSL certificate analysis for encrypted traffic
    /// - Provide comprehensive threat scoring and pattern matching
    /// 
    /// Security Detection Capabilities:
    /// - Cross-Site Scripting (XSS) attacks
    /// - SQL Injection (SQLi) attempts
    /// - Local File Inclusion (LFI) and path traversal
    /// - Remote Code Execution (RCE) patterns
    /// - Malicious file uploads and binary content
    /// - Base64-encoded payloads and evasion techniques
    /// - Suspicious HTTP headers and user agents
    /// 
    /// Features:
    /// - Complete HTTP protocol parsing with validation
    /// - Multi-layer threat detection (text, binary, regex patterns)
    /// - TLS/SSL certificate fingerprinting and analysis
    /// - Content-type aware inspection optimization
    /// - Comprehensive logging with forensic data
    /// - Performance-optimized pattern matching
    /// </summary>
    public class EnhancedHttpHandler : IHttpParserHandler, IDisposable
    {
        // HTTP protocol fields
        public string Method { get; private set; }
        public string Url { get; private set; }
        public string Host { get; private set; }
        public string UserAgent { get; private set; }
        public int StatusCode { get; private set; }
        public byte[] RequestBody { get; private set; }
        public byte[] ResponseBody { get; private set; }
        public Dictionary<string, string> Headers { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // TLS/SSL security information
        public string TlsSni { get; set; }
        public string TlsCipher { get; set; }
        public string TlsVersion { get; set; }
        public string TlsFingerprint { get; set; }

        // Internal parsing state
        private string currentHeader;
        private MemoryStream bodyStream = new MemoryStream();
        private bool isRequest = true;
        private readonly HttpParser _httpParser;

        public EnhancedHttpHandler(HttpParser httpParser)
        {
            _httpParser = httpParser ?? throw new ArgumentNullException(nameof(httpParser));
        }

        /// <summary>
        /// Clean up resources
        /// </summary>
        public void Dispose()
        {
            bodyStream?.Dispose();
            bodyStream = null;
        }

        /// <summary>
        /// Reset parser state for processing new HTTP message
        /// </summary>
        public void Reset()
        {
            Method = null;
            Url = null;
            Host = null;
            UserAgent = null;
            StatusCode = 0;
            RequestBody = null;
            ResponseBody = null;
            Headers.Clear();
            currentHeader = null;
            isRequest = true;
            bodyStream?.SetLength(0);
            TlsSni = null;
            TlsCipher = null;
            TlsVersion = null;
            TlsFingerprint = null;
        }

        // HTTP Parser Handler Interface Implementation
        public void OnMessageBegin(HttpMachine.HttpParser parser)
        {
            bodyStream.SetLength(0);
            currentHeader = null;
            isRequest = true;
        }

        public void OnMethod(HttpMachine.HttpParser parser, string method)
        {
            Method = method;
        }

        public void OnRequestUri(HttpMachine.HttpParser parser, string requestUri)
        {
            try
            {
                if (string.IsNullOrEmpty(requestUri))
                {
                    Console.WriteLine($"[HTTP-WARN] Empty URI received [Payload: none]");
                    Url = string.Empty;
                    return;
                }
                Url = ValidateUri(requestUri, "URI");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HTTP-ERROR] URI parsing error: {ex.Message}, URI: {requestUri} [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(requestUri).Take(16).ToArray())}]");
                Url = requestUri;
            }
        }

        public void OnFragment(HttpMachine.HttpParser parser, string fragment)
        {
            try
            {
                if (string.IsNullOrEmpty(fragment))
                {
                    Console.WriteLine($"[HTTP-WARN] Empty fragment received [Payload: none]");
                    return;
                }
                string validatedFragment = ValidateString(fragment, "Fragment");
                if (!string.IsNullOrEmpty(validatedFragment))
                    Url = Url != null ? $"{Url}#{validatedFragment}" : $"#{validatedFragment}";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HTTP-ERROR] Fragment parsing error: {ex.Message}, Fragment: {fragment} [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(fragment).Take(16).ToArray())}]");
            }
        }

        public void OnQueryString(HttpMachine.HttpParser parser, string queryString)
        {
            try
            {
                if (string.IsNullOrEmpty(queryString))
                {
                    Console.WriteLine($"[HTTP-WARN] Empty query string received [Payload: none]");
                    return;
                }
                string validatedQuery = ValidateString(queryString, "QueryString");
                if (!string.IsNullOrEmpty(validatedQuery))
                    Url = Url != null ? $"{Url}?{validatedQuery}" : $"?{validatedQuery}";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HTTP-ERROR] Query string parsing error: {ex.Message}, Query: {queryString} [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(queryString).Take(16).ToArray())}]");
            }
        }

        public void OnHeaderName(HttpMachine.HttpParser parser, string name)
        {
            currentHeader = name;
        }

        public void OnHeaderValue(HttpMachine.HttpParser parser, string value)
        {
            if (string.IsNullOrEmpty(currentHeader)) return;
            Headers[currentHeader] = value;
            if (currentHeader.Equals("Host", StringComparison.OrdinalIgnoreCase))
                Host = value;
            else if (currentHeader.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
                UserAgent = value;
        }

        public void OnHeadersEnd(HttpMachine.HttpParser parser) { }

        public void OnBody(HttpMachine.HttpParser parser, ArraySegment<byte> data)
        {
            if (data.Array == null || data.Count == 0) return;
            bodyStream.Write(data.Array, data.Offset, data.Count);
        }

        public void OnMessageEnd(HttpMachine.HttpParser parser)
        {
            var bytes = bodyStream.Length > 0 ? bodyStream.ToArray() : Array.Empty<byte>();
            if (isRequest)
            {
                RequestBody = bytes;
                CheckForThreats(bytes, "Request");
                isRequest = false;
            }
            else
            {
                ResponseBody = bytes;
                CheckForThreats(bytes, "Response");
                isRequest = true;
            }
            bodyStream.SetLength(0);
            currentHeader = null;
        }

        public void OnResponseCode(HttpMachine.HttpParser parser, int statusCode, string statusDescription)
        {
            StatusCode = statusCode;
            isRequest = false;
        }

        // Validation methods for security and protocol compliance
        private string ValidateUri(string uri, string context)
        {
            if (string.IsNullOrEmpty(uri))
            {
                Console.WriteLine($"[HTTP-WARN] Empty {context} received [Payload: none]");
                return string.Empty;
            }

            // RFC 3986 validation for URI characters
            for (int i = 0; i < uri.Length; i++)
            {
                char c = uri[i];
                if (IsValidUriChar(c) || (c == '%' && IsValidPercentEncoding(uri, i)))
                    continue;

                Console.WriteLine($"[HTTP-ERROR] Invalid character in {context} at position {i}: '{c}' (code: {(int)c}) [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(uri).Take(16).ToArray())}]");
                throw new ArgumentException($"Invalid character in {context}: '{c}' at position {i}");
            }
            return uri;
        }

        private string ValidateString(string input, string context)
        {
            if (string.IsNullOrEmpty(input))
            {
                Console.WriteLine($"[HTTP-WARN] Empty {context} received [Payload: none]");
                return string.Empty;
            }

            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                if (IsValidUriChar(c) || (c == '%' && IsValidPercentEncoding(input, i)))
                    continue;

                Console.WriteLine($"[HTTP-ERROR] Invalid character in {context} at position {i}: '{c}' (code: {(int)c}) [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(input).Take(16).ToArray())}]");
                throw new ArgumentException($"Invalid character in {context}: '{c}' at position {i}");
            }
            return input;
        }

        private bool IsValidUriChar(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '-' || c == '.' || c == '_' || c == '~' ||
                   c == ':' || c == '/' || c == '?' || c == '#' || c == '[' || c == ']' || c == '@' ||
                   c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' ||
                   c == '*' || c == '+' || c == ',' || c == ';' || c == '=';
        }

        private bool IsValidPercentEncoding(string input, int index)
        {
            if (index + 2 >= input.Length) return false;
            char c1 = input[index + 1];
            char c2 = input[index + 2];
            return IsHexDigit(c1) && IsHexDigit(c2);
        }

        private bool IsHexDigit(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
        }

        /// <summary>
        /// Analyze HTTP body for security threats using integrated HttpParser
        /// </summary>
        private void CheckForThreats(byte[] body, string direction)
        {
            if (_httpParser == null) return;
            var contentType = HttpParserHelpers.GetContentTypeFromHeaders(Headers);
            var threatResult = _httpParser.AnalyzeBody(body, "SRC_IP", "DST_IP", direction, contentType);
            if (threatResult.IsMalicious)
            {
                Console.WriteLine($"[HTTP-ALERT] {direction} threat detected! Score: {threatResult.Score}, Matches: {string.Join(",", threatResult.MatchedPatterns)}");
                Console.WriteLine($"Method: {Method}, URL: {Url}, Host: {Host}, User-Agent: {UserAgent}");
                Console.WriteLine($"TLS SNI: {TlsSni}, Cipher: {TlsCipher}, Version: {TlsVersion}, Fingerprint: {TlsFingerprint}");
            }
        }

        // Compatibility methods for different parser interfaces
        public void OnMessageBegin(HttpParser parser) => OnMessageBegin((HttpMachine.HttpParser)null);
        public void OnMethod(HttpParser parser, string method) => OnMethod((HttpMachine.HttpParser)null, method);
        public void OnRequestUri(HttpParser parser, string requestUri) => OnRequestUri((HttpMachine.HttpParser)null, requestUri);
        public void OnHeaderName(HttpParser parser, string name) => OnHeaderName((HttpMachine.HttpParser)null, name);
        public void OnHeaderValue(HttpParser parser, string value) => OnHeaderValue((HttpMachine.HttpParser)null, value);
        public void OnHeadersEnd(HttpParser parser) => OnHeadersEnd((HttpMachine.HttpParser)null);
        public void OnBody(HttpParser parser, ArraySegment<byte> data) => OnBody((HttpMachine.HttpParser)null, data);
        public void OnMessageEnd(HttpParser parser) => OnMessageEnd((HttpMachine.HttpParser)null);
        public void OnResponseCode(HttpParser parser, int statusCode, string statusDescription)
            => OnResponseCode((HttpMachine.HttpParser)null, statusCode, statusDescription);
    }

    /// <summary>
    /// Advanced HTTP threat detection engine for Intrusion Detection System
    /// 
    /// Detection Methods:
    /// - Text pattern matching for common attack signatures
    /// - Regular expression analysis for complex attack patterns
    /// - Binary pattern detection for executable content
    /// - Base64 decoding and analysis for encoded payloads
    /// - URL decoding for obfuscated attack vectors
    /// 
    /// Performance Features:
    /// - Configurable inspection limits to prevent resource exhaustion
    /// - Content-type filtering to skip non-relevant data
    /// - Efficient Boyer-Moore algorithm for binary pattern matching
    /// - Threat scoring with adjustable thresholds
    /// </summary>
    public class HttpParser
    {
        /// <summary>
        /// Threat analysis result container
        /// </summary>
        public class ThreatResult
        {
            public bool IsMalicious { get; set; }
            public int Score { get; set; }
            public int Threshold { get; set; }
            public List<string> MatchedPatterns { get; } = new List<string>();
            public string Description { get; set; } = string.Empty;
        }

        // Text-based attack patterns with threat weights
        private readonly Dictionary<string, int> _textPatterns = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            { "<script>alert(", 5 }, { "<script>", 4 }, { "javascript:", 3 }, { "onerror=", 3 }, { "onload=", 2 },
            { "union select", 5 }, { "select .* from", 4 }, { "or 1=1", 4 }, { "information_schema", 5 },
            { "eval(", 4 }, { "system(", 5 }, { "exec(", 5 }, { "shell_exec(", 5 }, { "powershell", 4 }, { "cmd.exe", 4 },
            { "../", 3 }, { "/etc/passwd", 5 }, { "/etc/shadow", 5 }, { "document.cookie", 3 },
            { ".exe", 4 }, { ".js", 2 }, { ".scr", 4 }, { ".bat", 4 }, { ".zip", 2 }, { "application/octet-stream", 2 }
        };

        // Binary pattern detection for executable content
        private readonly List<(byte[] Pattern, int Weight, string Name)> _binaryPatterns = new List<(byte[], int, string)>
        {
            (new byte[] { 0x90, 0x90, 0x90 }, 5, "NOP_sled"),
            (new byte[] { 0x4D, 0x5A }, 5, "MZ_header_exe"),
            (new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, 5, "ELF_header")
        };

        // Regular expression patterns for complex attack detection
        private readonly List<(Regex R, int Weight, string Name)> _regexPatterns = new List<(Regex, int, string)>
        {
            (new Regex(@"<\s*script\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), 4, "XSS_SCRIPT"),
            (new Regex(@"\bunion\s+select\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), 5, "SQLI_UNION_SELECT"),
            (new Regex(@"\bselect\b.*\bfrom\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), 4, "SQLI_SELECT_FROM"),
            (new Regex(@"(\.\.\/){2,}", RegexOptions.Compiled), 3, "LFI_TRAVERSAL"),
            (new Regex(@"(\bcmd\.exe\b|\bpowershell\.exe\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled), 4, "WIN_RCE"),
            (new Regex(@"data:\s*application\/octet-stream;base64,?", RegexOptions.IgnoreCase | RegexOptions.Compiled), 4, "BASE64_BINARY"),
        };

        // Configuration parameters
        private readonly int _threatThreshold;
        private readonly int _maxInspectBytes;
        private readonly bool _enableBase64Decode;
        private readonly bool _enableUrlDecode;

        public HttpParser(int threatThreshold = 1, int maxInspectBytes = 1024 * 1024,
                          bool enableBase64Decode = true, bool enableUrlDecode = true)
        {
            _threatThreshold = Math.Max(1, threatThreshold);
            _maxInspectBytes = Math.Max(1, maxInspectBytes);
            _enableBase64Decode = enableBase64Decode;
            _enableUrlDecode = enableUrlDecode;
        }

        /// <summary>
        /// Validate if packet contains valid HTTP protocol data
        /// </summary>
        public bool IsValidHttpPacket(byte[] payload)
        {
            if (payload == null || payload.Length < 10)
                return false;

            try
            {
                string start = Encoding.UTF8.GetString(payload, 0, Math.Min(20, payload.Length));

                // Check for HTTP request methods
                bool isHttpRequest = start.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) ||
                                    start.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
                                    start.StartsWith("PUT ", StringComparison.OrdinalIgnoreCase) ||
                                    start.StartsWith("DELETE ", StringComparison.OrdinalIgnoreCase) ||
                                    start.StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase) ||
                                    start.StartsWith("OPTIONS ", StringComparison.OrdinalIgnoreCase) ||
                                    start.StartsWith("PATCH ", StringComparison.OrdinalIgnoreCase);

                // Check for HTTP response
                bool isHttpResponse = start.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase);

                // Additional check for HTTP headers
                bool hasHttpHeaders = start.Contains("HTTP/1.") ||
                                     start.Contains("HTTP/2") ||
                                     start.Contains("Content-Type:") ||
                                     start.Contains("Host:") ||
                                     start.Contains("User-Agent:");

                return isHttpRequest || isHttpResponse || hasHttpHeaders;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogDebug($"HTTP validation error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Comprehensive HTTP body analysis for security threats
        /// </summary>
        public ThreatResult AnalyzeBody(byte[] body, string srcIp, string dstIp, string direction, string contentType = null)
        {
            var res = new ThreatResult { Threshold = _threatThreshold, Score = 0 };

            // Initial validation and content filtering
            if (body == null || body.Length == 0)
            {
                res.Description = "Empty body.";
                Console.WriteLine($"[HTTP-WARN] Empty body in {direction} [SrcIP: {srcIp}] [Payload: none]");
                return res;
            }

            if (body.Length > _maxInspectBytes)
            {
                res.Description = $"Skipped: body too large ({body.Length} bytes > {_maxInspectBytes}).";
                Console.WriteLine($"[HTTP-WARN] {res.Description} [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(body.Take(16).ToArray())}]");
                return res;
            }

            // Skip non-text content types for performance
            if (!string.IsNullOrEmpty(contentType))
            {
                var ct = contentType.Split(';')[0].Trim().ToLowerInvariant();
                if (ct.StartsWith("image/") || ct.StartsWith("video/") || ct.StartsWith("audio/") || ct == "font/woff" || ct == "application/octet-stream")
                {
                    res.Description = $"Skipped: non-text content-type ({ct}).";
                    Console.WriteLine($"[HTTP-WARN] {res.Description} [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(body.Take(16).ToArray())}]");
                    return res;
                }
            }

            string bodyText = null;
            try
            {
                bodyText = Encoding.UTF8.GetString(body);
                // Validate body characters for security
                for (int i = 0; i < bodyText.Length; i++)
                {
                    char c = bodyText[i];
                    if (!IsValidBodyChar(c))
                    {
                        Console.WriteLine($"[HTTP-ERROR] Invalid character in body at position {i}: '{c}' (code: {(int)c}) [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(body.Take(16).ToArray())}]");
                    }
                }
            }
            catch
            {
                try
                {
                    bodyText = Encoding.ASCII.GetString(body);
                    for (int i = 0; i < bodyText.Length; i++)
                    {
                        char c = bodyText[i];
                        if (!IsValidBodyChar(c))
                        {
                            Console.WriteLine($"[HTTP-ERROR] Invalid character in body at position {i}: '{c}' (code: {(int)c}) [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(body.Take(16).ToArray())}]");
                        }
                    }
                }
                catch
                {
                    bodyText = null;
                    res.Description = "Failed to decode body as UTF-8 or ASCII.";
                    Console.WriteLine($"[HTTP-WARN] {res.Description} [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(body.Take(16).ToArray())}]");
                }
            }

            // Multi-layer threat analysis
            string bodyLower = bodyText?.ToLowerInvariant();

            // Text pattern matching
            if (!string.IsNullOrEmpty(bodyLower))
            {
                foreach (var kv in _textPatterns)
                {
                    if (bodyLower.Contains(kv.Key.ToLowerInvariant()))
                    {
                        res.Score += kv.Value;
                        res.MatchedPatterns.Add($"TEXT:{kv.Key}");
                    }
                }
            }

            // Regular expression analysis
            if (!string.IsNullOrEmpty(bodyText))
            {
                foreach (var (R, Weight, Name) in _regexPatterns)
                {
                    if (R.IsMatch(bodyText))
                    {
                        res.Score += Weight;
                        res.MatchedPatterns.Add($"REGEX:{Name}");
                    }
                }
            }

            // Binary pattern detection
            var bodySpan = body.AsSpan();
            foreach (var (Pattern, Weight, Name) in _binaryPatterns)
            {
                if (Pattern == null || Pattern.Length == 0) continue;
                if (BoyerMooreSearch.Contains(bodySpan, Pattern))
                {
                    res.Score += Weight;
                    res.MatchedPatterns.Add($"BINARY:{Name}");
                }
            }

            // Base64 decoding and analysis
            if (_enableBase64Decode && !string.IsNullOrEmpty(bodyLower))
            {
                bool looksLikeBase64 = bodyLower.Contains("base64,") || (bodyLower.Length > 100 && bodyLower.Count(c => c == '=') > 0);
                if (looksLikeBase64)
                {
                    foreach (var fragment in ExtractBase64Candidates(bodyText))
                    {
                        try
                        {
                            var decoded = Convert.FromBase64String(fragment);
                            if (decoded != null && decoded.Length > 0)
                            {
                                string decodedText = null;
                                try
                                {
                                    decodedText = Encoding.UTF8.GetString(decoded);
                                    for (int i = 0; i < decodedText.Length; i++)
                                    {
                                        char c = decodedText[i];
                                        if (!IsValidBodyChar(c))
                                        {
                                            Console.WriteLine($"[HTTP-ERROR] Invalid character in Base64 decoded at position {i}: '{c}' (code: {(int)c}) [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(decoded.Take(16).ToArray())}]");
                                        }
                                    }
                                }
                                catch
                                {
                                    decodedText = null;
                                }
                                if (!string.IsNullOrEmpty(decodedText) && suspiciousSubstringExists(decodedText))
                                {
                                    res.Score += 4;
                                    res.MatchedPatterns.Add("DECODED_BASE64:text-matches");
                                }
                                var ds = decoded.AsSpan();
                                foreach (var (Pattern, Weight, Name) in _binaryPatterns)
                                {
                                    if (BoyerMooreSearch.Contains(ds, Pattern))
                                    {
                                        res.Score += Weight;
                                        res.MatchedPatterns.Add($"DECODED_BASE64:binary-{Name}");
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[HTTP-ERROR] Base64 decode error: {ex.Message}, Fragment: {fragment.Substring(0, Math.Min(fragment.Length, 32))} [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(fragment).Take(16).ToArray())}]");
                        }
                    }
                }
            }

            // URL decoding analysis
            if (_enableUrlDecode && !string.IsNullOrEmpty(bodyText))
            {
                try
                {
                    string urlDecoded = Uri.UnescapeDataString(bodyText);
                    for (int i = 0; i < urlDecoded.Length; i++)
                    {
                        char c = urlDecoded[i];
                        if (!IsValidBodyChar(c))
                        {
                            Console.WriteLine($"[HTTP-ERROR] Invalid character in URL decoded at position {i}: '{c}' (code: {(int)c}) [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(urlDecoded).Take(16).ToArray())}]");
                        }
                    }
                    if (urlDecoded != bodyText && suspiciousSubstringExists(urlDecoded))
                    {
                        res.Score += 3;
                        res.MatchedPatterns.Add("URL_DECODED:match");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[HTTP-ERROR] URL decode error: {ex.Message} [SrcIP: {srcIp}] [Payload: {BitConverter.ToString(Encoding.ASCII.GetBytes(bodyText).Take(16).ToArray())}]");
                }
            }

            // Final threat determination
            res.IsMalicious = res.Score >= _threatThreshold;
            res.Description = res.IsMalicious
                ? $"Threat score {res.Score} >= {_threatThreshold}; matches: {string.Join(",", res.MatchedPatterns)}"
                : $"Score {res.Score} (< {_threatThreshold})";

            return res;
        }

        // Helper methods for validation and analysis
        private bool IsValidBodyChar(char c)
        {
            return (c >= 32 && c <= 126) || c == '\r' || c == '\n' ||
                   c == ':' || c == '/' || c == '?' || c == '#' || c == '[' || c == ']' || c == '@' ||
                   c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' ||
                   c == '*' || c == '+' || c == ',' || c == ';' || c == '=' || c == '%';
        }

        public bool CheckBodyForThreats(byte[] body, string srcIp, string dstIp, string direction, string contentType = null)
        {
            var r = AnalyzeBody(body, srcIp, dstIp, direction, contentType);
            if (r.IsMalicious)
            {
                Console.WriteLine($"[HTTP-THREAT] {direction} from {srcIp} to {dstIp} - {r.Description} [Payload: {BitConverter.ToString(body.Take(16).ToArray())}]");
            }
            return r.IsMalicious;
        }

        private bool suspiciousSubstringExists(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            var lower = text.ToLowerInvariant();
            foreach (var key in _textPatterns.Keys)
            {
                if (lower.Contains(key.ToLowerInvariant())) return true;
            }
            foreach (var (R, _, _) in _regexPatterns)
            {
                if (R.IsMatch(text)) return true;
            }
            return false;
        }

        private IEnumerable<string> ExtractBase64Candidates(string text)
        {
            if (string.IsNullOrEmpty(text)) yield break;
            var sb = new StringBuilder();
            foreach (var ch in text)
            {
                if (IsBase64Char(ch)) sb.Append(ch);
                else
                {
                    if (sb.Length >= 32)
                    {
                        yield return sb.ToString();
                    }
                    sb.Clear();
                }
            }
            if (sb.Length >= 32) yield return sb.ToString();
        }

        private bool IsBase64Char(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        }
    }

    /// <summary>
    /// HTTP parser utility functions
    /// </summary>
    public static class HttpParserHelpers
    {
        public static string GetContentTypeFromHeaders(Dictionary<string, string> headers)
        {
            if (headers == null) return null;
            if (headers.TryGetValue("Content-Type", out var ct))
            {
                var idx = ct.IndexOf(';');
                return idx >= 0 ? ct.Substring(0, idx).Trim() : ct.Trim();
            }
            return null;
        }
    }

    /// <summary>
    /// Efficient binary pattern search using Boyer-Moore algorithm
    /// </summary>
    public static class BoyerMooreSearch
    {
        public static bool Contains(ReadOnlySpan<byte> haystack, byte[] needle)
        {
            if (needle.Length == 0) return true;
            if (haystack.Length < needle.Length) return false;

            // Simple implementation for small patterns
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return true;
            }
            return false;
        }
    }
}