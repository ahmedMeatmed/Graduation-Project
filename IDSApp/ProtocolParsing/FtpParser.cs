using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace IDSApp.ProtocolParsing
{
    /// <summary>
    /// Advanced FTP protocol parser for Intrusion Detection System
    /// 
    /// Main Responsibilities:
    /// - Parse and analyze FTP (File Transfer Protocol) commands and transactions
    /// - Extract filenames, paths, and command arguments with security context
    /// - Detect suspicious FTP activities and potential attack patterns
    /// - Normalize paths and identify path traversal attempts
    /// - Flag credential exposure in FTP sessions
    /// 
    /// Security Detection Capabilities:
    /// - Path traversal attacks using "../" and absolute paths
    /// - Suspicious file extensions indicating malware/scripts
    /// - Base64-encoded payloads in filenames or arguments
    /// - Suspicious keywords (shell, cmd, webshell, etc.)
    /// - Credential exposure in PASS commands
    /// - Long filenames potentially hiding malicious content
    /// - Percent-encoding evasion techniques
    /// 
    /// Features:
    /// - Comprehensive FTP command parsing with argument extraction
    /// - Path normalization and traversal detection
    /// - File operation classification (RETR, STOR, DELE, etc.)
    /// - Multiple encoding detection and handling
    /// - Suspicious pattern matching with detailed reasoning
    /// </summary>
    public class FtpParser
    {
        // FTP commands that operate on files
        private static readonly HashSet<string> FileCommands =
            new(StringComparer.OrdinalIgnoreCase)
            { "RETR", "STOR", "DELE", "APPE", "RNFR", "RNTO", "MKD", "RMD" };

        // Encoding for FTP protocol (typically UTF-8 or ASCII)
        private static readonly Encoding FtpEncoding = Encoding.UTF8;

        // Suspicious file extensions that might indicate malware or attack scripts
        private static readonly string[] SuspiciousExtensions = new[]
        {
            ".exe", ".dll", ".php", ".asp", ".aspx", ".jsp", ".sh", ".bat", ".pl", ".py", ".jar"
        };

        // Regex to detect base64-like payloads or long encoded strings in arguments
        private static readonly Regex Base64Like = new(@"^[A-Za-z0-9+/=\s]{40,}$", RegexOptions.Compiled);

        // Regex to capture FTP command and argument while preserving quoted filenames
        private static readonly Regex CommandArgRegex = new(@"^(?<cmd>\S+)(?:\s+(?<arg>.+))?$", RegexOptions.Compiled);

        /// <summary>
        /// Parse FTP protocol payload and extract security-relevant information
        /// 
        /// Processing Steps:
        /// 1. Decode payload using UTF-8 with ASCII fallback
        /// 2. Extract command and argument using regex
        /// 3. Handle quoted filenames and path normalization
        /// 4. Analyze for suspicious patterns and security threats
        /// 5. Return comprehensive parsing results with security flags
        /// 
        /// Supported Analysis:
        /// - File operation detection and filename extraction
        /// - Path traversal and directory climbing attempts
        /// - Suspicious file extensions and encoded payloads
        /// - Credential exposure in authentication commands
        /// - Evasion technique detection
        /// </summary>
        public FtpParseResult Parse(byte[] payload)
        {
            var result = new FtpParseResult();

            if (payload == null || payload.Length == 0)
            {
                result.Command = "UNKNOWN";
                return result;
            }

            string text;
            try
            {
                text = FtpEncoding.GetString(payload).Trim();
            }
            catch
            {
                text = Encoding.ASCII.GetString(payload).Trim();
            }

            if (string.IsNullOrEmpty(text))
            {
                result.Command = "UNKNOWN";
                return result;
            }

            // Match the command and argument (if any)
            var m = CommandArgRegex.Match(text);
            if (!m.Success)
            {
                result.Command = text; // fallback
                return result;
            }

            result.Command = m.Groups["cmd"].Value.ToUpperInvariant();
            string rawArg = m.Groups["arg"].Success ? m.Groups["arg"].Value.Trim() : string.Empty;

            // If argument exists, try to extract filename (handles quotes)
            if (!string.IsNullOrEmpty(rawArg))
            {
                string filename = ExtractFilename(rawArg);
                result.RawArgument = rawArg;
                result.IsFileOperation = FileCommands.Contains(result.Command);

                if (result.IsFileOperation)
                {
                    result.Filename = filename ?? "<unknown>";
                    result.NormalizedFilename = NormalizePath(result.Filename);
                    AnalyzeFilename(result);
                }
            }

            // Additional quick checks useful for IDS
            if (text.IndexOf("PASS ", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.ContainsCredentials = true;
            }

            return result;
        }

        /// <summary>
        /// Extract filename from FTP command argument
        /// Handles quoted filenames and whitespace separation
        /// </summary>
        private static string ExtractFilename(string arg)
        {
            // Remove starting and trailing quotes if present
            if ((arg.StartsWith("\"") && arg.EndsWith("\"")) || (arg.StartsWith("'") && arg.EndsWith("'")))
            {
                return arg.Substring(1, arg.Length - 2);
            }

            // If there's whitespace, many commands accept only the first token as filename
            var parts = arg.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length > 0 ? parts[0] : arg;
        }

        /// <summary>
        /// Normalize file path for security analysis
        /// Handles URL decoding, path separator normalization, and traversal resolution
        /// </summary>
        private static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;

            // Handle URL-encoding
            try
            {
                path = Uri.UnescapeDataString(path);
            }
            catch { /* ignore malformed escapes */ }

            // Replace backslashes with forward slashes for normalization
            path = path.Replace('\\', '/');

            // Remove leading drive letters (C:/) and leading slashes while preserving '/'-relative
            path = Regex.Replace(path, "^[A-Za-z]:/", string.Empty);

            // Collapse redundant slashes
            while (path.Contains("//")) path = path.Replace("//", "/");

            // Resolve '.' and '..' segments safely
            var segments = new List<string>();
            foreach (var seg in path.Split('/'))
            {
                if (seg == "" || seg == ".") continue;
                if (seg == "..")
                {
                    if (segments.Count > 0) segments.RemoveAt(segments.Count - 1);
                    else
                    {
                        // Leading .. -> keep as is to indicate traversal above root
                        segments.Add("..");
                    }
                }
                else
                {
                    segments.Add(seg);
                }
            }

            return string.Join('/', segments);
        }

        /// <summary>
        /// Analyze filename for suspicious patterns and security threats
        /// Sets suspicion flags and reasons based on detected patterns
        /// </summary>
        private static void AnalyzeFilename(FtpParseResult result)
        {
            if (string.IsNullOrEmpty(result.Filename)) return;

            // Check for path traversal attempts
            if (result.Filename.Contains("..") || result.Filename.StartsWith("/") || result.Filename.StartsWith("\\"))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("path_traversal_or_absolute_path");
            }

            // Check for suspicious extensions
            string ext = Path.GetExtension(result.Filename).ToLowerInvariant();
            if (!string.IsNullOrEmpty(ext) && SuspiciousExtensions.Contains(ext))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("suspicious_extension:" + ext);
            }

            // Long base64-like arguments (could be disguised payload)
            if (Base64Like.IsMatch(result.Filename))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("base64_like_payload");
            }

            // Suspicious characters often used in exploits
            if (result.Filename.IndexOf('<') >= 0 || result.Filename.IndexOf('>') >= 0 || result.Filename.IndexOf('\0') >= 0)
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("suspicious_characters");
            }

            // Check for percent-encoding in path (could hide traversal or payload)
            if (result.Filename.Contains("%"))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("percent_encoded");
            }

            // Filename length checks
            if (result.Filename.Length > 200)
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("very_long_filename");
            }

            // Heuristic: many upload attacks include "shell", "cmd", "php" in filename
            var lower = result.Filename.ToLowerInvariant();
            if (lower.Contains("shell") || lower.Contains("cmd") || lower.Contains("php") || lower.Contains("webshell"))
            {
                result.IsSuspicious = true;
                result.SuspicionReasons.Add("suspicious_keyword");
            }
        }
    }

    /// <summary>
    /// Comprehensive result container for FTP parsing analysis
    /// Contains parsed command information and security assessment flags
    /// </summary>
    public class FtpParseResult
    {
        /// <summary>
        /// FTP command extracted from payload (e.g., RETR, STOR, PASS)
        /// </summary>
        public string Command { get; set; } = "";

        /// <summary>
        /// Raw argument string from the FTP command
        /// </summary>
        public string RawArgument { get; set; } = "";

        /// <summary>
        /// Indicates if this command operates on files
        /// </summary>
        public bool IsFileOperation { get; set; } = false;

        /// <summary>
        /// Extracted filename from file operations
        /// </summary>
        public string Filename { get; set; } = string.Empty;

        /// <summary>
        /// Normalized and sanitized file path for analysis
        /// </summary>
        public string NormalizedFilename { get; set; } = string.Empty;

        /// <summary>
        /// Flag indicating suspicious activity detected
        /// </summary>
        public bool IsSuspicious { get; set; } = false;

        /// <summary>
        /// List of reasons why the activity is considered suspicious
        /// </summary>
        public List<string> SuspicionReasons { get; set; } = new List<string>();

        /// <summary>
        /// Flag indicating potential credential exposure
        /// </summary>
        public bool ContainsCredentials { get; set; } = false;

        public override string ToString()
        {
            return $"Cmd={Command}, FileOp={IsFileOperation}, Filename={Filename}, Suspicious={IsSuspicious}, Reasons=[{string.Join(',', SuspicionReasons)}]";
        }
    }
}