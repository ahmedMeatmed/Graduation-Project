
using dnYara;
using IDSApp.BLL;
using PacketDotNet;
using PCRE;
using Renci.SshNet.Messages;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using static Org.BouncyCastle.Math.EC.ECCurve;
namespace IDSApp.Helper
{



    public class EnhancedPcreValidator
    {
        private static readonly HashSet<string> _invalidPatterns = new HashSet<string>
        {
            "//", "**", "??", "++", "{{", "}}", "[]", "()", "||", ".."
        };

        private static readonly Dictionary<string, string> _commonPatternFixes = new Dictionary<string, string>
        {
            { "/*", "/.*" },
            { "*/", ".*/" },
            { "/+", "/.+" },
            { "?-", "\\?-" },
            { "\\x", "\\\\x" },
            { "../", "\\\\.\\\\./" },
            { "./", "\\\\./" }
        };

        private static readonly HashSet<string> _commonFalsePositives = new HashSet<string>
        {
            "XPM", "VODKA", "reedjoll", "km0ae9gr6m", "c3284d", "0c0896", "F0C4~1"
        };

        public static (bool isValid, string cleanedPattern, string recoveryAction) ValidateAndFixPcrePattern(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                return (false, pattern, "empty");

            string originalPattern = pattern;
            string cleaned = pattern.Trim();

            // 🔧 FIX: قائمة بالأنماط القصيرة المفيدة التي يجب ألا نتخطاها
            string[] usefulShortPatterns = {
        "cmd.exe", "whoami", "net user", "passwd", "sudo", "admin",
        "root", "shell", "exec", "eval", "system", "chmod 777",
        "union", "select", "insert", "update", "delete", "drop", "create",
        "script", "alert", "onload", "onerror", "<script", "</script>",
        "javascript:", "vbscript:", "onclick", "onmouseover",
        "../", "..\\", "./", ".\\", "/..", "\\..",
        "<?php", "<?=", "?>", "<%", "%>",
        "document.cookie", "localStorage", "sessionStorage",
        "base64_decode", "base64_encode", "eval(", "exec(",
        "system(", "passthru(", "shell_exec(", "proc_open",
        "popen(", "assert(", "include(", "require(",
        "include_once", "require_once", "file_get_contents",
        "file_put_contents", "unlink(", "rmdir(", "mkdir(",
        "chmod(", "chown(", "copy(", "move_uploaded_file",
        "readfile(", "fopen(", "fwrite(", "fclose(",
        "header(", "setcookie(", "session_start(",
        "mysql_", "mysqli_", "pg_", "mssql_", "oci_",
        "OR 1=1", "OR '1'='1", "UNION SELECT", "UNION ALL SELECT",
        "SELECT * FROM", "INSERT INTO", "UPDATE SET", "DELETE FROM",
        "DROP TABLE", "CREATE TABLE", "ALTER TABLE",
        "xp_cmdshell", "sp_", "dbo.", "sysadmin",
        "<iframe", "<embed", "<object", "<applet",
        "victim", "attack", "exploit", "payload", "malware",
        "ransomware", "trojan", "backdoor", "keylogger",
        "botnet", "crypto", "miner", "coin", "bitcoin",
        "ether", "monero", "xmr", "btc", "eth"
    };

            // 🔧 FIX: التحقق إذا كان النمط قصيراً لكن مفيداً
            if (cleaned.Length < 15) // زيادة الحد إلى 15 حرف
            {
                string cleanedLower = cleaned.ToLower();
                foreach (var usefulPattern in usefulShortPatterns)
                {
                    if (cleanedLower.Contains(usefulPattern.ToLower()))
                    {
                        return (true, Regex.Escape(cleaned), "useful_short_pattern");
                    }
                }

                // 🔧 FIX: التحقق من الأنماط التي تحتوي على أحرف خاصة قد تكون هجومية
                if (cleaned.Contains("..") || cleaned.Contains("--") || cleaned.Contains("/*") ||
                    cleaned.Contains("*/") || cleaned.Contains("<?") || cleaned.Contains("?>") ||
                    cleaned.Contains("<%") || cleaned.Contains("%>") || cleaned.Contains("${") ||
                    cleaned.Contains("#{") || cleaned.Contains("${") || cleaned.Contains("&lt;") ||
                    cleaned.Contains("&gt;") || cleaned.Contains("%20") || cleaned.Contains("%00"))
                {
                    return (true, Regex.Escape(cleaned), "suspicious_short_pattern");
                }
            }

            bool hasSlashes = cleaned.StartsWith("/") && cleaned.EndsWith("/");

            // Remove slashes for processing
            string patternWithoutSlashes = cleaned;
            if (hasSlashes && cleaned.Length >= 3)
            {
                patternWithoutSlashes = cleaned.Substring(1, cleaned.Length - 2);
            }

            // Quick check for common false positives
            if (IsCommonFalsePositive(patternWithoutSlashes))
                return (false, patternWithoutSlashes, "common_false_positive");

            // Check for completely invalid patterns
            if (_invalidPatterns.Any(invalid => patternWithoutSlashes.Contains(invalid)))
                return (false, patternWithoutSlashes, "invalid_chars");

            // Check for excessive repetition
            if (HasExcessiveRepetition(patternWithoutSlashes))
                return (false, patternWithoutSlashes, "excessive_repetition");

            // Try to fix common pattern issues
            var fixResult = FixCommonPatternIssues(patternWithoutSlashes);
            string fixedPattern = fixResult.pattern;
            string fixAction = fixResult.action;

            // Quick validation for simple patterns
            if (IsSimpleTextPattern(fixedPattern))
            {
                return (true, Regex.Escape(fixedPattern), "simple_text");
            }

            try
            {
                // Test compile the pattern
                var regex = new PcreRegex(fixedPattern, PcreOptions.None);
                return (true, fixedPattern, fixAction);
            }
            catch (PcreException ex)
            {
                // For specific error types, use appropriate recovery
                if (ex.Message.Contains("quantifier") || ex.Message.Contains("repeatable"))
                {
                    string recoveredPattern = RecoverQuantifierError(fixedPattern);
                    try
                    {
                        var recoveredRegex = new PcreRegex(recoveredPattern, PcreOptions.None);
                        return (true, recoveredPattern, $"quantifier_recovery");
                    }
                    catch
                    {
                        return (false, recoveredPattern, "quantifier_recovery_failed");
                    }
                }

                // General recovery for other errors
                string generalRecovery = SmartPatternRecovery(fixedPattern);
                try
                {
                    var generalRegex = new PcreRegex(generalRecovery, PcreOptions.None);
                    return (true, generalRecovery, $"general_recovery");
                }
                catch
                {
                    return (false, generalRecovery, "recovery_failed");
                }
            }
            catch
            {
                return (false, fixedPattern, "compilation_failed");
            }
        }
        private static bool IsCommonFalsePositive(string pattern)
        {
            return _commonFalsePositives.Any(fp =>
                pattern.Contains(fp, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsSimpleTextPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return false;

            // Patterns without regex special characters are simple text
            string regexSpecials = @"*?+[](){}\|^$.";
            return !pattern.Any(c => regexSpecials.Contains(c)) &&
                   pattern.Length > 2 && pattern.Length < 100;
        }

        private static string RecoverQuantifierError(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return ".*";

            // Remove leading quantifiers
            string cleaned = pattern.TrimStart('*', '?', '+');

            // Escape problematic sequences
            cleaned = Regex.Replace(cleaned, @"(\*|\+|\?)", "\\$1");

            // Ensure we have a valid pattern
            if (string.IsNullOrEmpty(cleaned) || cleaned == "\\*")
                return ".*";

            return cleaned;
        }

        public static string SmartPatternRecovery(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return "";

            // Handle very short patterns
            if (pattern.Length <= 2)
            {
                return HandleVeryShortPattern(pattern);
            }

            // Check if this looks like a file path or URL pattern
            if (LooksLikeFilePath(pattern))
            {
                return HandleFilePathPattern(pattern);
            }

            // Check if this looks like a command or script pattern
            if (LooksLikeCommandPattern(pattern))
            {
                return HandleCommandPattern(pattern);
            }

            // Check if this is a simple text pattern that should be literal
            if (ShouldBeLiteralPattern(pattern))
            {
                return Regex.Escape(pattern);
            }

            // Try to extract meaningful content
            string meaningfulContent = ExtractMeaningfulContent(pattern);
            if (!string.IsNullOrEmpty(meaningfulContent) && meaningfulContent.Length >= 3)
            {
                return ".*" + Regex.Escape(meaningfulContent) + ".*";
            }

            // Final fallback - safe wildcard
            return ".*";
        }

        private static string HandleVeryShortPattern(string pattern)
        {
            if (pattern.Length == 1)
            {
                // Single character patterns
                if ("*?+.[](){}\\|^$".Contains(pattern))
                    return "\\" + pattern;
                return pattern;
            }

            if (pattern.Length == 2)
            {
                // Common 2-character patterns
                if (pattern == "//") return "/";
                if (pattern == "..") return "\\.";
                if (pattern == ".*") return pattern;
                if (pattern == "./") return "\\./";
                if (pattern == "../") return "\\.\\./";

                return Regex.Escape(pattern);
            }

            return pattern;
        }

        private static bool LooksLikeFilePath(string pattern)
        {
            return pattern.Contains("/") || pattern.Contains("\\") ||
                   pattern.Contains(".") && !pattern.Contains(".*");
        }

        private static string HandleFilePathPattern(string pattern)
        {
            // Clean up file path patterns
            string cleaned = pattern;

            // Fix common path issues
            cleaned = cleaned.Replace("//", "/");
            cleaned = cleaned.Replace("../", "\\\\.\\\\./");
            cleaned = cleaned.Replace("./", "\\\\./");

            // Escape dots that are likely path separators, not wildcards
            if (cleaned.Contains(".") && !cleaned.Contains(".*"))
            {
                cleaned = Regex.Replace(cleaned, @"(?<!/)\.(?!\*)", "\\.");
            }

            return cleaned;
        }

        private static bool LooksLikeCommandPattern(string pattern)
        {
            return pattern.Contains("cmd") || pattern.Contains("exec") ||
                   pattern.Contains("system") || pattern.Contains("eval") ||
                   pattern.Contains("$_") || pattern.Contains("${");
        }

        private static string HandleCommandPattern(string pattern)
        {
            // For command patterns, be more conservative with wildcards
            string cleaned = pattern;

            // Preserve command structure but escape special characters
            cleaned = Regex.Escape(cleaned);

            // Allow some wildcards for command arguments
            cleaned = cleaned.Replace("\\.\\*", ".*");
            cleaned = cleaned.Replace("\\\\\\?", "\\?");

            return cleaned;
        }

        private static (string pattern, string action) FixCommonPatternIssues(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return (".*", "empty_fallback");

            string fixedPattern = pattern;
            string action = "no_change";

            // Apply common fixes
            foreach (var fix in _commonPatternFixes)
            {
                if (fixedPattern.Contains(fix.Key))
                {
                    fixedPattern = fixedPattern.Replace(fix.Key, fix.Value);
                    action = $"fixed_{fix.Key.Replace("/", "slash").Replace("\\", "backslash")}";
                }
            }

            // Fix patterns starting with quantifiers
            if (fixedPattern.StartsWith("*") || fixedPattern.StartsWith("?") || fixedPattern.StartsWith("+"))
            {
                fixedPattern = fixedPattern.Substring(1);
                action = "removed_leading_quantifier";
            }

            // Fix unescaped special characters at the beginning
            if (fixedPattern.StartsWith("?") && fixedPattern.Length > 1)
            {
                fixedPattern = "\\" + fixedPattern;
                action = "escaped_leading_question";
            }

            // Remove excessive wildcards
            fixedPattern = RemoveExcessiveWildcards(fixedPattern);
            if (fixedPattern != pattern)
            {
                action = "reduced_wildcards";
            }

            // Ensure the pattern is not empty after cleaning
            if (string.IsNullOrEmpty(fixedPattern))
            {
                fixedPattern = ".*";
                action = "empty_fallback";
            }

            return (fixedPattern, action);
        }

        private static string RemoveExcessiveWildcards(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return pattern;

            // Replace multiple consecutive .* with single .*
            string result = Regex.Replace(pattern, @"(\.\*){2,}", ".*");

            // Replace multiple consecutive wildcards
            result = Regex.Replace(result, @"\*+", "*");
            result = Regex.Replace(result, @"\?+", "?");
            result = Regex.Replace(result, @"\.+", ".");

            return result;
        }

        private static bool HasExcessiveRepetition(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return false;

            // Check for excessive wildcards
            int wildcardCount = pattern.Count(c => c == '*' || c == '?' || c == '.');
            if ((double)wildcardCount / pattern.Length > 0.7)
                return true;

            // Check for repeated sequences
            if (pattern.Count(c => c == '/') > 10)
                return true;

            return false;
        }

        private static bool ShouldBeLiteralPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return false;

            // If pattern has no regex special characters, it's probably meant to be literal
            string regexSpecials = @"*?+[](){}\|^$";
            bool hasRegexSpecials = pattern.Any(c => regexSpecials.Contains(c));

            // But if it has meaningful regex constructs, it might be intentional
            bool hasMeaningfulRegex = pattern.Contains(".*") || pattern.Contains(".+") ||
                                     pattern.Contains("\\d") || pattern.Contains("\\w") ||
                                     pattern.Contains("^") || pattern.Contains("$");

            return !hasRegexSpecials || (!hasMeaningfulRegex && pattern.Length < 15);
        }

        private static string ExtractMeaningfulContent(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return pattern;

            // Extract alphanumeric sequences of reasonable length
            var matches = Regex.Matches(pattern, @"[a-zA-Z0-9_-]{3,}");
            if (matches.Count > 0)
            {
                // Return the longest meaningful sequence
                return matches.Cast<System.Text.RegularExpressions.Match>().OrderByDescending(m => m.Length).First().Value;
            }

            // Look for common file extensions
            var extMatches = Regex.Matches(pattern, @"\.[a-z]{2,4}", RegexOptions.IgnoreCase);
            if (extMatches.Count > 0)
            {
                return extMatches.Cast<System.Text.RegularExpressions.Match>().Last().Value.TrimStart('.');
            }

            // Fallback: return first meaningful chunk
            var words = pattern.Split(new[] { '*', '?', '.', '/', '\\', ' ', '\t' },
                                    StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 0)
            {
                return words.OrderByDescending(w => w.Length).First();
            }

            return pattern.Length <= 10 ? pattern : pattern.Substring(0, 10);
        }

        public static bool IsPatternTooShort(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return true;

            string cleaned = pattern.Trim('/', '\\', ' ', '\t');
            return cleaned.Length < 2;
        }

        public static bool IsPatternMeaningful(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return false;

            string cleaned = pattern.Trim('/', '\\', ' ', '\t');

            // Patterns that are just wildcards or very short aren't meaningful
            if (cleaned.All(c => c == '*' || c == '?' || c == '.' || c == ' ' || c == '/'))
                return false;

            // Patterns shorter than 2 characters after cleaning aren't meaningful
            if (cleaned.Length < 2)
                return false;

            // Patterns with excessive repetition aren't meaningful
            if (HasExcessiveRepetition(cleaned))
                return false;

            return true;
        }

        public static string CleanPcrePattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return pattern;

            string cleaned = pattern.Trim('/', '\\');

            if (string.IsNullOrEmpty(cleaned) || cleaned.Length < 2)
                return "";

            cleaned = Regex.Replace(cleaned, @"\*+", "*");
            cleaned = Regex.Replace(cleaned, @"\?+", "?");
            cleaned = Regex.Replace(cleaned, @"\/+", "/");
            cleaned = Regex.Replace(cleaned, @"\.+", ".");

            return cleaned;
        }
    }


    /// <summary>
    /// Enhanced rule engine for signature-based threat detection with support for
    /// multiple rule formats, performance optimizations, and advanced pattern matching.
    /// Provides fast packet inspection using bloom filters and rule prioritization.
    /// 
    /// Features:
    /// - PCRE pattern matching with validation and recovery
    /// - Protocol-specific rule optimization and indexing
    /// - Rule conflict resolution and prioritization
    /// - Performance monitoring and statistical analysis
    /// - Fast-path optimization using bloom filters
    /// - Multi-threaded rule checking with load balancing
    /// - Comprehensive error handling and validation
    /// </summary>
    public class EnhancedSignatureRuleEngine
    {
        private long _rulesMatched = 0;
        private long _rulesChecked = 0;
        private long _packetsProcessed = 0;
        private long _totalRulesChecked = 0;
        private long _rulesFilteredByPrecheck = 0;
        private long _fastPathOptimizations = 0;

        /// <summary>
        /// PCRE-based content matcher implementation for regex pattern matching
        /// </summary>
        public class PcreContentMatcher : IContentMatcher
        {
            private readonly PcreRegex _regex;

            /// <summary>
            /// Initializes a new PCRE content matcher with compiled regex pattern
            /// </summary>
            /// <param name="regex">Compiled PCRE regex pattern for efficient matching</param>
            public PcreContentMatcher(PcreRegex regex)
            {
                _regex = regex ?? throw new ArgumentNullException(nameof(regex));
            }

            /// <summary>
            /// Matches payload against the PCRE pattern using UTF-8 encoding
            /// </summary>
            /// <param name="payload">Binary payload to inspect</param>
            /// <returns>True if pattern matches any part of the payload</returns>
            public bool IsMatch(byte[] payload)
            {
                if (payload == null || payload.Length == 0)
                    return false;
                string text = Encoding.UTF8.GetString(payload);
                return _regex.IsMatch(text);
            }

            /// <summary>
            /// Interface implementation for protocol-aware content matching
            /// </summary>
            public bool Match(byte[] payload, string protocol)
            {
                return IsMatch(payload);
            }
        }

        private List<Entity.Signatures> _activeRules = new List<Entity.Signatures>();
        private readonly EnhancedRuleParser _ruleParser = new EnhancedRuleParser();
        private readonly DynamicWhitelist _whitelist = new DynamicWhitelist();
        private readonly RulePriorityManager _priorityManager = new RulePriorityManager();
        private readonly RuleStatistics _statistics = new RuleStatistics();
        private readonly RuleFastPathOptimizer _fastPathOptimizer = new RuleFastPathOptimizer(true);

        // Rule indexing structures for optimized access
        private Dictionary<string, List<Entity.Signatures>> _rulesByProtocol = new Dictionary<string, List<Entity.Signatures>>();
        private Dictionary<int, List<Entity.Signatures>> _rulesByDestPort = new Dictionary<int, List<Entity.Signatures>>();
        private Dictionary<string, List<Entity.Signatures>> _rulesByContent = new Dictionary<string, List<Entity.Signatures>>();
        private List<Entity.Signatures> _rulesWithoutContent = new List<Entity.Signatures>();

        private readonly PerformanceSettings _perfSettings = PerformanceSettings.LoadFromSettings();
        private readonly ConcurrentDictionary<string, DateTime> _recentRuleChecks = new();
        private readonly TimeSpan _ruleCacheWindow = TimeSpan.FromSeconds(2);
       // private readonly bool _enableDiagnosticLogging = false;
        private readonly DynamicIDSConfig _config = new DynamicIDSConfig();

        /// <summary>
        /// Initializes a new enhanced signature rule engine with default configuration
        /// </summary>
        public EnhancedSignatureRuleEngine()
        {
            
        }

        /// <summary>
        /// Loads and initializes detection rules from the database, building optimized
        /// indexes for fast packet inspection. Validates rule syntax and organizes rules
        /// by protocol, port, and content patterns for efficient matching.
        /// </summary>
        /// <remarks>
        /// Rule Loading Process:
        /// 1. Load rules from database and backup sources with error handling
        /// 2. Validate PCRE patterns and apply automatic fixes for common issues
        /// 3. Build protocol-based, port-based, and content-based indexes
        /// 4. Initialize bloom filters for fast-path optimization
        /// 5. Analyze rule conflicts and establish priority hierarchy
        /// 6. Generate comprehensive rule statistics and validation reports
        /// </remarks>
        public void LoadRules()
        {
            try
            {
                _activeRules.Clear();
                _rulesByProtocol.Clear();
                _rulesByDestPort.Clear();
                _rulesByContent.Clear();
                _rulesWithoutContent.Clear();

                OptimizedLogger.LogImportant("[RULES] Loading detection rules...");

                var allRules = new List<Entity.Signatures>();

                // Load rules from primary database source
                var dbRules = SignatureBLL.GetSnortRules() ?? new List<Entity.Signatures>();
                allRules.AddRange(dbRules);

                if (!allRules.Any())
                {
                    OptimizedLogger.LogError("[RULE_ENGINE] CRITICAL: No rules available from database! Loading backup rules...");
                    allRules = LoadBackupRules();
                }

                ProcessSignaturesFast(allRules, "All Sources");
                BuildRuleIndexes();

                _priorityManager.AnalyzeRuleConflicts(_activeRules);

                if (_fastPathOptimizer != null)
                {
                    _fastPathOptimizer.BuildBloomFilters(_activeRules);
                    OptimizedLogger.LogImportant($"[RULES] Bloom filters built with {_activeRules.Count} rules");
                }
                else
                {
                    OptimizedLogger.LogError("[RULES] FastPathOptimizer is null - bloom filters not built!");
                }

                OptimizedLogger.LogImportant($"[RULES] Successfully loaded {_activeRules.Count} active rules.");
                PrintRuleStatistics();

                var sampleRules = _activeRules.Take(5).Select(r =>
                    $"{r.SignatureId}: {r.AttackName} (Proto: {r.Protocol}, Port: {r.DestPort}, Content: {r.ContentPattern?.Substring(0, Math.Min(30, r.ContentPattern.Length)) ?? "None"})"
                ).ToList();

                OptimizedLogger.LogImportant("[RULES] Sample rules loaded:");
                foreach (var ruleInfo in sampleRules)
                {
                    OptimizedLogger.LogImportant($"[RULES]   - {ruleInfo}");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[RULE_ENGINE] Error loading rules: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Loads backup rules when primary rule source is unavailable
        /// </summary>
        /// <returns>List of basic detection rules for essential threat detection</returns>
        private List<Entity.Signatures> LoadBackupRules()
        {
            var backupRules = new List<Entity.Signatures>();

            // Essential detection rules for common attacks
            backupRules.Add(new Entity.Signatures
            {
                SignatureId = 999001,
                AttackName = "TEST SQL Injection",
                Protocol = "tcp",
                DestPort = "80",
                ContentPattern = "union select",
                Engine = "snort"
            });

            backupRules.Add(new Entity.Signatures
            {
                SignatureId = 999002,
                AttackName = "TEST XSS Attempt",
                Protocol = "tcp",
                DestPort = "80",
                ContentPattern = "script>alert",
                Engine = "snort"
            });

            OptimizedLogger.LogImportant("[RULES] Loaded backup test rules");
            return backupRules;
        }

        /// <summary>
        /// Processes signature rules in batches with parallel validation and optimization
        /// </summary>
        /// <param name="signatures">List of signatures to process</param>
        /// <param name="format">Source format description for logging</param>
        private void ProcessSignaturesFast(List<Entity.Signatures> signatures, string format)
        {
            if (signatures == null || signatures.Count == 0)
            {
                OptimizedLogger.LogError($"[RULES] No signatures to process for {format}");
                return;
            }

            int validRules = 0;
            int skippedRules = 0;
            int batchSize = _perfSettings.BatchProcessingSize;

            OptimizedLogger.LogImportant($"[RULES] Processing {signatures.Count} signatures in batches of {batchSize}");

            for (int i = 0; i < signatures.Count; i += batchSize)
            {
                var batch = signatures.Skip(i).Take(batchSize).ToList();

                Parallel.ForEach(batch, sig =>
                {
                    try
                    {
                        // Validate and fix PCRE patterns
                        if (!string.IsNullOrEmpty(sig.ContentPattern))
                        {
                            var validationResult = EnhancedPcreValidator.ValidateAndFixPcrePattern(sig.ContentPattern);
                            if (!validationResult.isValid)
                            {
                                if (_perfSettings.EnableDiagnosticLogging && skippedRules < 10)
                                {
                                    OptimizedLogger.LogDebug($"[RULES] Skipped invalid pattern: {sig.ContentPattern} -> {validationResult.recoveryAction}");
                                }
                                Interlocked.Increment(ref skippedRules);
                                return;
                            }

                            sig.ContentPattern = validationResult.cleanedPattern;
                        }

                        lock (_activeRules)
                        {
                            _activeRules.Add(sig);
                        }
                        Interlocked.Increment(ref validRules);
                    }
                    catch (Exception ex)
                    {
                        OptimizedLogger.LogError($"[RULES] Error processing rule {sig.SignatureId}: {ex.Message}");
                        Interlocked.Increment(ref skippedRules);
                    }
                });
            }

            OptimizedLogger.LogDebug($"[RULES] {format}: Processed {signatures.Count} rules, {validRules} valid, {skippedRules} skipped");

            // Log sample of loaded rules for verification
            if (validRules > 0)
            {
                var sampleRules = _activeRules.Take(5).Select(r => $"{r.SignatureId}:{r.AttackName}").ToList();
                OptimizedLogger.LogImportant($"[RULES] Sample loaded rules: {string.Join(", ", sampleRules)}");
            }
        }


        /// <summary>
        /// Inspects a network packet against loaded detection rules to identify
        /// malicious activity. Uses multiple optimization techniques to ensure
        /// high-performance inspection even with large rule sets.
        /// </summary>
        /// <param name="ipPacket">IP packet to inspect for threats</param>
        /// <param name="payload">Packet payload data for content inspection</param>
        /// <param name="srcIp">Source IP address for contextual analysis</param>
        /// <param name="dstIp">Destination IP address for contextual analysis</param>
        /// <param name="srcPort">Source port number for protocol analysis</param>
        /// <param name="dstPort">Destination port number for protocol analysis</param>
        /// <param name="protocolName">Network protocol name for rule filtering</param>
        /// <returns>List of matched signature rules describing detected threats</returns>
        /// <remarks>
        /// Inspection Pipeline:
        /// 1. Pre-filtering using bloom filters and whitelists
        /// 2. Protocol and port-based rule selection
        /// 3. Content pattern matching with PCRE
        /// 4. Rule prioritization and conflict resolution
        /// 5. Statistical tracking and performance monitoring
        /// 6. Result deduplication and optimization
        /// </remarks>
        public List<Entity.Signatures> CheckPacket(IPPacket ipPacket, byte[] payload,
            string srcIp, string dstIp, int srcPort, int dstPort, string protocolName)
        {
            Interlocked.Increment(ref _packetsProcessed);
            var stopwatch = Stopwatch.StartNew();

            try
            {
                bool shouldLogDiagnostics = _perfSettings.EnableDiagnosticLogging &&
                    (_packetsProcessed <= 20 || _packetsProcessed % 500 == 0);

                if (shouldLogDiagnostics)
                {
                    OptimizedLogger.LogDebug($"[RULES] === Checking packet {_packetsProcessed} ===");
                    OptimizedLogger.LogDebug($"[RULES] {protocolName} {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                    OptimizedLogger.LogDebug($"[RULES] Payload: {payload?.Length ?? 0} bytes");
                }

                // Handle empty rules gracefully
                if (_activeRules == null || _activeRules.Count == 0)
                {
                    if (_packetsProcessed % 100 == 0)
                    {
                        OptimizedLogger.LogError("[RULES] Engine has no active rules!");
                    }
                    return new List<Entity.Signatures>();
                }

                // Safe fast path optimization with error handling
                bool shouldCheckRules = true; // Default to true for safety

                if (_fastPathOptimizer != null)
                {
                    try
                    {
                        shouldCheckRules = _fastPathOptimizer.ShouldCheckRules(
                            protocolName, dstPort, payload?.Length ?? 0, "default", srcPort, "");
                    }
                    catch (Exception ex)
                    {
                        // If fast path fails, default to checking rules for safety
                        OptimizedLogger.LogError($"[RULES] FastPath error in CheckPacket: {ex.Message}");
                        shouldCheckRules = true;
                        // Note: No _errorCount field available, just log the error
                    }
                }
                else
                {
                    // Log warning if optimizer is null but don't block packet processing
                    if (_packetsProcessed % 1000 == 0)
                    {
                        OptimizedLogger.LogImportant("[RULES] FastPathOptimizer is null - checking all packets");
                    }
                }

                if (!shouldCheckRules)
                {
                    Interlocked.Increment(ref _fastPathOptimizations);
                    if (shouldLogDiagnostics)
                    {
                        OptimizedLogger.LogDebug($"[RULES] FastPath skipped rules checking for {protocolName}:{dstPort}");
                    }
                    return new List<Entity.Signatures>();
                }

                // Better packet worthiness checking
                if (!IsPacketWorthInspecting(ipPacket, payload, srcIp, dstIp, srcPort, dstPort, protocolName))
                {
                    if (shouldLogDiagnostics)
                    {
                        OptimizedLogger.LogDebug($"[RULES] Packet not worth inspecting - skipping");
                    }
                    return new List<Entity.Signatures>();
                }

                // Enhanced packet deduplication with better hashing
                var packetHash = GetPacketHash(srcIp, dstIp, srcPort, dstPort, protocolName, payload?.Length ?? 0);
                if (_recentRuleChecks.TryGetValue(packetHash, out var lastCheck) &&
                    DateTime.Now - lastCheck < _ruleCacheWindow)
                {
                    return new List<Entity.Signatures>();
                }
                _recentRuleChecks[packetHash] = DateTime.Now;

                var matches = new List<Entity.Signatures>();

                // Safe rule retrieval with error handling
                List<Entity.Signatures> relevantRules;
                try
                {
                    relevantRules = GetRelevantRulesForTraffic(protocolName, dstPort, srcIp, dstIp, payload?.Length ?? 0);
                }
                catch (Exception ex)
                {
                    OptimizedLogger.LogError($"[RULES] Error getting relevant rules: {ex.Message}");
                    relevantRules = _activeRules.Take(_perfSettings.MaxRulesPerPacket).ToList();
                }

                if (shouldLogDiagnostics)
                {
                    LogPacketDiagnostics(protocolName, dstPort, payload, relevantRules);
                }

                if (relevantRules == null || relevantRules.Count == 0)
                {
                    if (shouldLogDiagnostics)
                    {
                        OptimizedLogger.LogDebug($"[RULES] No relevant rules for {protocolName}:{dstPort}");
                    }
                    return matches;
                }

                // Limit rules to check with bounds checking
                int rulesToCheck = Math.Min(relevantRules.Count, _perfSettings.MaxRulesPerPacket);
                var limitedRules = relevantRules.Take(rulesToCheck).ToList();

                if (shouldLogDiagnostics)
                {
                    OptimizedLogger.LogDebug($"[RULES] Will check {limitedRules.Count}/{relevantRules.Count} rules");
                }

                Interlocked.Add(ref _totalRulesChecked, limitedRules.Count);
                Interlocked.Add(ref _rulesChecked, limitedRules.Count);

                // Safe pre-filtering
                List<Entity.Signatures> filteredRules;
                try
                {
                    filteredRules = PreFilterRules(limitedRules, protocolName, srcPort, dstPort);
                }
                catch (Exception ex)
                {
                    OptimizedLogger.LogError($"[RULES] Error in pre-filtering: {ex.Message}");
                    filteredRules = limitedRules; // Fallback to checking all limited rules
                }

                if (shouldLogDiagnostics && filteredRules.Count > 0)
                {
                    OptimizedLogger.LogDebug($"[RULES] After pre-filter: {filteredRules.Count} rules to check");

                    var sampleRules = filteredRules.Take(3).Select(r =>
                        $"{r.SignatureId}: {r.AttackName} (Port: {r.DestPort}, Content: {r.ContentPattern?.Substring(0, Math.Min(30, r.ContentPattern.Length)) ?? "None"})"
                    ).ToList();

                    OptimizedLogger.LogDebug($"[RULES] Sample rules to check:");
                    foreach (var ruleInfo in sampleRules)
                    {
                        OptimizedLogger.LogDebug($"[RULES]   - {ruleInfo}");
                    }
                }

                int matchCount = 0;
                int checkedRules = 0;
                int rulesWithErrors = 0;

                // Enhanced rule checking with comprehensive error handling
                foreach (var rule in filteredRules)
                {
                    checkedRules++;

                    try
                    {
                        // Quick pre-check with error handling
                        bool shouldCheckRule;
                        try
                        {
                            shouldCheckRule = QuickPreCheck(rule, protocolName, dstPort, payload);
                        }
                        catch (Exception ex)
                        {
                            OptimizedLogger.LogDebug($"[RULES] Error in QuickPreCheck for rule {rule.SignatureId}: {ex.Message}");
                            shouldCheckRule = true; // Check the rule if pre-check fails
                        }

                        if (!shouldCheckRule)
                        {
                            Interlocked.Increment(ref _rulesFilteredByPrecheck);
                            continue;
                        }

                        // Perform actual rule matching
                        bool isMatch;
                        try
                        {
                            isMatch = MatchesRuleFast(rule, ipPacket, payload, srcIp, dstIp, srcPort, dstPort, protocolName);
                        }
                        catch (Exception ex)
                        {
                            OptimizedLogger.LogError($"[RULES] Error matching rule {rule.SignatureId}: {ex.Message}");
                            rulesWithErrors++;
                            continue; // Skip this rule on error
                        }

                        if (shouldLogDiagnostics && checkedRules <= 5)
                        {
                            string matchStatus = isMatch ? "MATCH" : "no match";
                            string contentInfo = !string.IsNullOrEmpty(rule.ContentPattern) ?
                                $"Content: '{rule.ContentPattern.Substring(0, Math.Min(50, rule.ContentPattern.Length))}'" :
                                "No content";

                            OptimizedLogger.LogDebug($"[RULES] Checked rule {rule.SignatureId}: {matchStatus}, {contentInfo}");
                        }

                        if (isMatch)
                        {
                            matches.Add(rule);
                            matchCount++;

                            OptimizedLogger.LogImportant($"[RULE_MATCH] {rule.AttackName} from {srcIp}:{srcPort} to {dstIp}:{dstPort}");
                            OptimizedLogger.LogImportant($"[RULE_DETAILS] Rule ID: {rule.SignatureId}, Protocol: {rule.Protocol}, Port: {rule.DestPort}");

                            if (!string.IsNullOrEmpty(rule.ContentPattern))
                            {
                                OptimizedLogger.LogImportant($"[RULE_CONTENT] Pattern: {rule.ContentPattern}");

                                // Extract and log matched content for analysis
                                if (payload != null && payload.Length > 0)
                                {
                                    string payloadText = Encoding.UTF8.GetString(payload);
                                    var validationResult = EnhancedPcreValidator.ValidateAndFixPcrePattern(rule.ContentPattern);
                                    try
                                    {
                                        var regex = new PcreRegex(validationResult.cleanedPattern, PcreOptions.None);
                                        var match = regex.Match(payloadText);
                                        if (match.Success)
                                        {
                                            string matchedText = match.Value;
                                            if (matchedText.Length > 100) matchedText = matchedText.Substring(0, 100) + "...";
                                            OptimizedLogger.LogImportant($"[MATCHED_CONTENT] '{matchedText}'");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        OptimizedLogger.LogDebug($"[RULES] Error extracting matched content: {ex.Message}");
                                    }
                                }
                            }

                            // Record rule hit in statistics if available
                            try
                            {
                                _statistics.RecordRuleHit(rule.SignatureId, rule.AttackName, true, stopwatch.ElapsedMilliseconds);
                            }
                            catch (Exception ex)
                            {
                                OptimizedLogger.LogDebug($"[RULES] Error recording rule hit: {ex.Message}");
                            }

                            if (_perfSettings.StopAfterFirstMatch && matches.Count > 0)
                            {
                                break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Catch any unexpected errors during rule processing
                        OptimizedLogger.LogError($"[RULES] Unexpected error processing rule {rule.SignatureId}: {ex.Message}");
                        rulesWithErrors++;
                    }
                }

                Interlocked.Add(ref _rulesMatched, matches.Count);

                // Enhanced logging with error tracking
                if (matchCount > 0)
                {
                    try
                    {
                        int matchLogId = LogBLL.Insert(
                            DateTime.Now,
                            srcIp,
                            dstIp,
                            payload?.Length ?? 0,
                            true,
                            "SIGNATURE_MATCHES",
                            protocolName,
                            srcPort, dstPort, payload?.Length ?? 0, "",
                            GetDirection(srcIp, dstIp),
                            matchCount, stopwatch.ElapsedMilliseconds, null,
                            $"Found {matchCount} rule matches in packet inspection"
                        );

                        if (matchLogId <= 0)
                        {
                            OptimizedLogger.LogDebug($"[RULES] Failed to insert match log entry");
                        }
                    }
                    catch (Exception ex)
                    {
                        OptimizedLogger.LogError($"[RULES] Error inserting match log: {ex.Message}");
                    }
                }
                else if (shouldLogDiagnostics)
                {
                    OptimizedLogger.LogDebug($"[RULES] No matches in packet {_packetsProcessed} after checking {filteredRules.Count} rules (errors: {rulesWithErrors})");

                    // Analyze why no matches were found
                    if (payload != null && payload.Length > 0)
                    {
                        try
                        {
                            string payloadText = Encoding.UTF8.GetString(payload);
                            OptimizedLogger.LogDebug($"[RULES] Payload analysis:");
                            OptimizedLogger.LogDebug($"[RULES]   Length: {payloadText.Length} characters");
                            OptimizedLogger.LogDebug($"[RULES]   First 100 chars: {payloadText.Substring(0, Math.Min(100, payloadText.Length))}");

                            string[] commonWords = { "the", "and", "get", "post", "http", "html", "body", "div", "script" };
                            var foundWords = commonWords.Where(w => payloadText.ToLower().Contains(w)).Take(5);
                            if (foundWords.Any())
                            {
                                OptimizedLogger.LogDebug($"[RULES]   Common words found: {string.Join(", ", foundWords)}");
                            }
                        }
                        catch (Exception ex)
                        {
                            OptimizedLogger.LogDebug($"[RULES] Error analyzing payload: {ex.Message}");
                        }
                    }
                }

                // Log performance issues
                if (rulesWithErrors > 0)
                {
                    OptimizedLogger.LogImportant($"[RULES] Packet {_packetsProcessed} had {rulesWithErrors} rule processing errors");
                }

                return matches;
            }
            catch (Exception ex)
            {
                // Top-level error handling to prevent crashes
                OptimizedLogger.LogError($"[RULES] Critical error in CheckPacket: {ex.Message}");
                // Note: No _errorCount field available, just log the error
                return new List<Entity.Signatures>();
            }
            finally
            {
                stopwatch.Stop();

                // Enhanced performance logging
                if (stopwatch.ElapsedMilliseconds > 100)
                {
                    OptimizedLogger.LogPerformance($"[RULES] Packet {_packetsProcessed} processing took {stopwatch.ElapsedMilliseconds}ms");
                }

                // Periodic statistics logging
                if (_packetsProcessed % 1000 == 0)
                {
                    LogInternalStats();
                }
            }
        }
        /// <summary>
        /// Determines traffic direction
        /// </summary>
        public string GetDirection(string src, string dst)
        {
            var prefixes = _config.InternalIpPrefix.Split(',').Select(p => p.Trim()).ToList();
            bool srcInt = IsInternal(src, prefixes);
            bool dstInt = IsInternal(dst, prefixes);
            if (srcInt && !dstInt) return "outbound";
            if (!srcInt && dstInt) return "inbound";
            if (srcInt && dstInt) return "internal";
            return "external";
        }

        /// <summary>
        /// Determines if an IP address belongs to internal network ranges
        /// </summary>
        public bool IsInternal(string ip, List<string> cidrList)
        {
            if (!IPAddress.TryParse(ip, out var addr)) return false;
            foreach (var cidr in cidrList)
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2) continue;
                if (!IPAddress.TryParse(parts[0], out var network)) continue;
                if (!int.TryParse(parts[1], out int prefix)) continue;
                var addrBytes = addr.GetAddressBytes();
                var netBytes = network.GetAddressBytes();
                int byteCount = prefix / 8;
                int bitCount = prefix % 8;
                bool match = true;
                for (int i = 0; i < byteCount; i++)
                    if (addrBytes[i] != netBytes[i]) { match = false; break; }
                if (match && bitCount > 0)
                {
                    int mask = ~(0xFF >> bitCount) & 0xFF;
                    if ((addrBytes[byteCount] & mask) != (netBytes[byteCount] & mask)) match = false;
                }
                if (match) return true;
            }
            return false;
        }

        // Replace the current QuickPreCheck method:

        /// <summary>
        /// Performs quick preliminary checks to filter out obviously non-matching rules
        /// </summary>
        private bool QuickPreCheck(Entity.Signatures rule, string protocol, int dstPort, byte[] payload)
        {
            // 1. Protocol check
            if (!QuickProtocolMatch(rule.Protocol, protocol))
                return false;

            // 2. Port check - more strict
            if (!QuickPortMatch(rule.DestPort, dstPort))
                return false;

            // 3. Content pattern feasibility check
            if (!string.IsNullOrEmpty(rule.ContentPattern))
            {
                // Skip rules with obviously invalid patterns
                if (!EnhancedPcreValidator.IsPatternMeaningful(rule.ContentPattern))
                    return false;

                // Skip content matching for empty payloads unless specifically designed for it
                if (payload == null || payload.Length == 0)
                {
                    return rule.ContentPattern.Contains("^$") ||
                           rule.ContentPattern.Contains("\\x00") ||
                           IsSuspiciousEmptyPacketRule(rule);
                }

                // Skip if pattern is longer than payload
                var cleanPattern = EnhancedPcreValidator.CleanPcrePattern(rule.ContentPattern);
                if (cleanPattern.Length > payload.Length * 2) // Allow for encoding overhead
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Identifies rules specifically designed to detect suspicious empty packets
        /// </summary>
        private bool IsSuspiciousEmptyPacketRule(Entity.Signatures rule)
        {
            string[] suspiciousEmptyPatterns = {
                "^\x00", "^$", "\\x00\\x00", "null", "empty", "zero"
            };

            if (string.IsNullOrEmpty(rule.ContentPattern))
                return false;

            return suspiciousEmptyPatterns.Any(pattern =>
                rule.ContentPattern.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Determines if a packet is worth detailed inspection based on various heuristics
        /// </summary>
        private bool IsPacketWorthInspecting(IPPacket ipPacket, byte[] payload,
            string srcIp, string dstIp, int srcPort, int dstPort, string protocolName)
        {
            if (payload == null || payload.Length == 0)
            {
                return IsSuspiciousEmptyPacket(ipPacket);
            }

            return true;
        }

        /// <summary>
        /// Retrieves rules relevant to the specific traffic characteristics
        /// </summary>
        private List<Entity.Signatures> GetRelevantRulesForTraffic(string protocol, int dstPort, string srcIp, string dstIp, int payloadLength)
        {
            var relevantRules = new List<Entity.Signatures>();

            try
            {
                var protocolKey = protocol?.ToLower() ?? "any";

                // Get protocol-specific rules
                if (_rulesByProtocol.TryGetValue(protocolKey, out var protocolRules))
                {
                    relevantRules.AddRange(protocolRules);
                }

                // Add related protocol rules
                if (protocolKey == "http" || protocolKey == "https" || protocolKey == "ftp" || protocolKey == "ssh" || protocolKey == "smtp")
                {
                    if (_rulesByProtocol.TryGetValue("tcp", out var tcpRules))
                    {
                        relevantRules.AddRange(tcpRules);
                    }
                }
                else if (protocolKey == "dns" || protocolKey == "dhcp")
                {
                    if (_rulesByProtocol.TryGetValue("udp", out var udpRules))
                    {
                        relevantRules.AddRange(udpRules);
                    }
                }

                // Fallback to generic rules if no specific rules found
                if (relevantRules.Count == 0 && _rulesByProtocol.TryGetValue("any", out var anyRules))
                {
                    relevantRules.AddRange(anyRules);
                }

                // Filter by destination port
                if (dstPort > 0)
                {
                    var portFilteredRules = new List<Entity.Signatures>();

                    if (_rulesByDestPort.TryGetValue(dstPort, out var portRules))
                    {
                        portFilteredRules.AddRange(portRules);
                    }

                    if (_rulesByDestPort.TryGetValue(-1, out var generalRules))
                    {
                        portFilteredRules.AddRange(generalRules);
                    }

                    if (_rulesByDestPort.TryGetValue(-2, out var complexRules))
                    {
                        portFilteredRules.AddRange(complexRules);
                    }

                    if (portFilteredRules.Count > 0)
                    {
                        relevantRules = relevantRules.Intersect(portFilteredRules).ToList();
                    }
                }

                return relevantRules.Distinct().Take(_perfSettings.MaxRulesPerPacket).ToList();
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[RULES] Error getting relevant rules: {ex.Message}");
                return _activeRules.Take(_perfSettings.MaxRulesPerPacket).ToList();
            }
        }

        /// <summary>
        /// Builds optimized indexes for fast rule retrieval based on protocol, port, and content
        /// </summary>
        private void BuildRuleIndexes()
        {
            try
            {
                _rulesByProtocol = new Dictionary<string, List<Entity.Signatures>>();
                _rulesByDestPort = new Dictionary<int, List<Entity.Signatures>>();
                _rulesByContent = new Dictionary<string, List<Entity.Signatures>>();
                _rulesWithoutContent = new List<Entity.Signatures>();

                if (_activeRules == null || !_activeRules.Any())
                {
                    OptimizedLogger.LogError("[RULES] No active rules to index!");
                    return;
                }

                OptimizedLogger.LogImportant($"[RULES] Building indexes for {_activeRules.Count} rules...");

                int rulesWithValidPorts = 0;
                int rulesWithComplexPorts = 0;

                foreach (var rule in _activeRules)
                {
                    // Index by protocol
                    var protocolKey = (rule.Protocol ?? "any").ToLower();
                    if (!_rulesByProtocol.ContainsKey(protocolKey))
                        _rulesByProtocol[protocolKey] = new List<Entity.Signatures>();
                    _rulesByProtocol[protocolKey].Add(rule);

                    // Index by port with complex port handling
                    if (!string.IsNullOrEmpty(rule.DestPort) && rule.DestPort != "any")
                    {
                        var ports = ResolveSnortPortVariableToList(rule.DestPort);
                        if (ports.Any() && ports.Count <= 50) // LIMIT: Only index rules with <= 50 ports
                        {
                            rulesWithValidPorts++;
                            foreach (var port in ports)
                            {
                                if (!_rulesByDestPort.ContainsKey(port))
                                    _rulesByDestPort[port] = new List<Entity.Signatures>();
                                _rulesByDestPort[port].Add(rule);
                            }
                        }
                        else
                        {
                            rulesWithComplexPorts++;
                            // Store complex port rules separately
                            if (!_rulesByDestPort.ContainsKey(-2))
                                _rulesByDestPort[-2] = new List<Entity.Signatures>();
                            _rulesByDestPort[-2].Add(rule);
                        }
                    }
                    else
                    {
                        if (!_rulesByDestPort.ContainsKey(-1))
                            _rulesByDestPort[-1] = new List<Entity.Signatures>();
                        _rulesByDestPort[-1].Add(rule);
                    }

                    // Index by content category
                    if (!string.IsNullOrEmpty(rule.ContentPattern))
                    {
                        var contentKey = GetContentCategory(rule.ContentPattern);
                        if (!_rulesByContent.ContainsKey(contentKey))
                            _rulesByContent[contentKey] = new List<Entity.Signatures>();
                        _rulesByContent[contentKey].Add(rule);
                    }
                    else
                    {
                        _rulesWithoutContent.Add(rule);
                    }
                }

                OptimizedLogger.LogImportant($"[RULES] Indexing completed: {_rulesByProtocol.Count} protocols, {_rulesByDestPort.Count} ports, {_rulesByContent.Count} content categories");
                OptimizedLogger.LogImportant($"[RULES] Rules with valid ports: {rulesWithValidPorts}, Rules with complex ports: {rulesWithComplexPorts}");

                var topProtocols = _rulesByProtocol.OrderByDescending(kvp => kvp.Value.Count).Take(5);
                OptimizedLogger.LogImportant($"[RULES] Top protocols: {string.Join(", ", topProtocols.Select(kvp => $"{kvp.Key}:{kvp.Value.Count}"))}");

                var topPorts = _rulesByDestPort.Where(kvp => kvp.Key > 0).OrderByDescending(kvp => kvp.Value.Count).Take(5);
                OptimizedLogger.LogImportant($"[RULES] Top ports: {string.Join(", ", topPorts.Select(kvp => $"{kvp.Key}:{kvp.Value.Count}"))}");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[RULES] Critical error building indexes: {ex.Message}");
                _rulesByProtocol = new Dictionary<string, List<Entity.Signatures>>
                {
                    ["any"] = _activeRules,
                    ["tcp"] = _activeRules.Where(r => string.IsNullOrEmpty(r.Protocol) || r.Protocol == "any" || r.Protocol.ToLower() == "tcp").ToList(),
                    ["udp"] = _activeRules.Where(r => r.Protocol?.ToLower() == "udp").ToList()
                };
            }
        }

        /// <summary>
        /// Resolves Snort-style port variables to concrete port numbers
        /// </summary>
        private List<int> ResolveSnortPortVariableToList(string variable)
        {
            var ports = new List<int>();

            if (string.IsNullOrEmpty(variable) || variable == "any")
                return ports;

            variable = variable.Trim().Trim('[', ']', ' ').Trim();

            try
            {
                // Handle port ranges
                if (variable.Contains(":"))
                {
                    var rangeParts = variable.Split(':');
                    if (rangeParts.Length == 2)
                    {
                        string startStr = rangeParts[0].Trim();
                        string endStr = rangeParts[1].Trim();

                        if (string.IsNullOrEmpty(endStr) && int.TryParse(startStr, out int startOnly))
                        {
                            for (int i = startOnly; i <= 65535; i++)
                            {
                                ports.Add(i);
                            }
                            return ports;
                        }

                        if (int.TryParse(startStr, out int start) && int.TryParse(endStr, out int end))
                        {
                            for (int i = start; i <= end; i++)
                            {
                                ports.Add(i);
                            }
                            return ports;
                        }
                    }
                }

                // Handle port lists
                if (variable.Contains(","))
                {
                    var portStrings = variable.Split(',');
                    foreach (var portStr in portStrings)
                    {
                        var cleanPort = portStr.Trim().Trim('[', ']', ' ');
                        if (int.TryParse(cleanPort, out int port))
                        {
                            ports.Add(port);
                        }
                    }
                    return ports;
                }

                // Handle negated ports
                if (variable.StartsWith("!"))
                {
                    return ports;
                }

                // Handle single port
                if (int.TryParse(variable, out int singlePort))
                {
                    ports.Add(singlePort);
                    return ports;
                }

                // Handle Snort predefined port variables
                switch (variable.ToUpper())
                {
                    case "$HTTP_PORTS":
                        ports.AddRange(new[] { 80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888 });
                        break;
                    case "$FILE_DATA_PORTS":
                        ports.AddRange(new[] { 80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 21, 22, 25, 110, 143, 993, 995 });
                        break;
                    case "$SIP_PORTS":
                        ports.AddRange(new[] { 5060, 5061, 5062, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070 });
                        break;
                    case "$ORACLE_PORTS":
                        ports.AddRange(new[] { 1521, 1522, 1523, 1524, 1525, 1526, 1527, 1528, 1529, 1530 });
                        break;
                    case "$SSH_PORTS":
                        ports.AddRange(new[] { 22, 2222, 22222 });
                        break;
                    case "$FTP_PORTS":
                        ports.AddRange(new[] { 21, 2121 });
                        break;
                    case "$SHELLCODE_PORTS":
                        ports.AddRange(new[] { 80, 81, 443, 1433, 1521, 1723, 2301, 3128, 3306, 3389, 4899, 8080, 8081 });
                        break;
                    case "$DNS_PORTS":
                        ports.AddRange(new[] { 53, 5353 });
                        break;
                    case "$SMTP_PORTS":
                        ports.AddRange(new[] { 25, 465, 587, 2525 });
                        break;
                    default:
                        OptimizedLogger.LogDebug($"[RULES] Unknown Snort port variable '{variable}', returning empty ports");
                        break;
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[RULES] Error parsing port variable '{variable}': {ex.Message}");
            }

            return ports;
        }

        /// <summary>
        /// Categorizes content patterns for optimized rule grouping
        /// </summary>
        private string GetContentCategory(string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return "empty";

            pattern = pattern.ToLower();
            if (pattern.Contains("select") || pattern.Contains("union") || pattern.Contains("insert"))
                return "sql";
            if (pattern.Contains("script") || pattern.Contains("alert(") || pattern.Contains("eval("))
                return "xss";
            if (pattern.Contains("cmd.exe") || pattern.Contains("/bin/sh") || pattern.Contains("system("))
                return "command";
            if (pattern.Length < 10) return "short";

            return "general";
        }

        /// <summary>
        /// Performs quick protocol matching with protocol relationship awareness
        /// </summary>
        private bool QuickProtocolMatch(string ruleProtocol, string packetProtocol)
        {
            if (string.IsNullOrEmpty(ruleProtocol) || ruleProtocol == "any")
                return true;

            var ruleLower = ruleProtocol.ToLower();
            var packetLower = packetProtocol?.ToLower() ?? "";

            // Handle protocol relationships
            if (ruleLower == "tcp" && (packetLower == "tcp" || packetLower == "http" || packetLower == "https" ||
                packetLower == "ftp" || packetLower == "ssh" || packetLower == "smtp"))
                return true;

            if (ruleLower == "udp" && (packetLower == "udp" || packetLower == "dns"))
                return true;

            return ruleLower == packetLower;
        }

        /// <summary>
        /// Performs quick port matching with support for complex port specifications
        /// </summary>
        private bool QuickPortMatch(string rulePort, int packetPort)
        {
            if (string.IsNullOrEmpty(rulePort) || rulePort == "any")
                return true;

            if (rulePort == "-1")
                return true;

            if (rulePort.StartsWith("$") || rulePort.Contains(",") || rulePort.Contains(":") || rulePort.Contains("[") || rulePort.Contains("!"))
            {
                var ports = ResolveSnortPortVariableToList(rulePort);
                return ports.Contains(packetPort);
            }

            if (int.TryParse(rulePort, out int rulePortNum))
                return rulePortNum == packetPort;

            return true;
        }

        /// <summary>
        /// Pre-filters rules based on basic criteria before detailed inspection
        /// </summary>
        private List<Entity.Signatures> PreFilterRules(List<Entity.Signatures> rules, string protocol, int srcPort, int dstPort)
        {
            return rules.Where(rule =>
            {
                if (!QuickProtocolMatch(rule.Protocol, protocol))
                    return false;

                if (!QuickPortMatch(rule.DestPort, dstPort))
                    return false;

                return true;
            }).ToList();
        }

        /// <summary>
        /// Performs fast rule matching using optimized comparison techniques
        /// </summary>
        private bool MatchesRuleFast(Entity.Signatures rule, IPPacket ipPacket, byte[] payload,
                    string srcIp, string dstIp, int srcPort, int dstPort, string protocolName)
        {
            try
            {
                if (!MatchesProtocol(rule.Protocol, protocolName))
                    return false;

                if (!MatchesPort(rule.DestPort, dstPort))
                    return false;

                if (!string.IsNullOrEmpty(rule.ContentPattern) && payload != null && payload.Length > 0)
                {
                    if (!MatchesContentPattern(rule.ContentPattern, payload))
                        return false;
                }

                if (_perfSettings.EnableDiagnosticLogging)
                {
                    OptimizedLogger.LogDebug($"[RULE_MATCH] Rule {rule.SignatureId} matched for {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                }

                return true;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[RULE_MATCH] Error matching rule {rule.SignatureId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Matches content patterns against packet payload using PCRE
        /// </summary>
        private bool MatchesContentPattern(string pattern, byte[] payload)
        {
            if (payload == null || payload.Length == 0)
                return false;

            try
            {
                var validationResult = EnhancedPcreValidator.ValidateAndFixPcrePattern(pattern);
                if (!validationResult.isValid)
                {
                    OptimizedLogger.LogDebug($"[PCRE] Invalid pattern: {pattern} -> {validationResult.recoveryAction}");
                    return false;
                }

                var text = Encoding.UTF8.GetString(payload);

                // Direct text matching for simple patterns
                if (validationResult.recoveryAction == "simple_text")
                {
                    bool directMatch = text.Contains(validationResult.cleanedPattern);
                    if (directMatch && _perfSettings.EnableDiagnosticLogging)
                    {
                        OptimizedLogger.LogDebug($"[PCRE] Direct text match: '{validationResult.cleanedPattern}'");
                    }
                    return directMatch;
                }

                var regex = new PcreRegex(validationResult.cleanedPattern, PcreOptions.None);
                bool isMatch = regex.IsMatch(text);

                if (isMatch && _perfSettings.EnableDiagnosticLogging)
                {
                    OptimizedLogger.LogDebug($"[PCRE] Regex pattern matched: {validationResult.cleanedPattern}");

                    var match = regex.Match(text);
                    if (match.Success)
                    {
                        string matchedText = match.Value;
                        if (matchedText.Length > 50) matchedText = matchedText.Substring(0, 50) + "...";
                        OptimizedLogger.LogDebug($"[PCRE] Matched text: '{matchedText}'");
                    }
                }

                return isMatch;
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogDebug($"[PCRE] Match failed for pattern '{pattern}': {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Matches protocol with awareness of protocol relationships
        /// </summary>
        private bool MatchesProtocol(string ruleProtocol, string packetProtocol)
        {
            if (string.IsNullOrEmpty(ruleProtocol) || ruleProtocol.Equals("any", StringComparison.OrdinalIgnoreCase))
                return true;

            string ruleLower = ruleProtocol.ToLower();
            string packetLower = packetProtocol?.ToLower() ?? "";

            return ruleLower switch
            {
                "tcp" => packetLower == "tcp" || packetLower == "http" || packetLower == "https" ||
                         packetLower == "ftp" || packetLower == "ssh" || packetLower == "smtp",
                "udp" => packetLower == "udp" || packetLower == "dns",
                "icmp" => packetLower == "icmp",
                "http" => packetLower == "tcp",
                "tls" => packetLower == "tcp",
                _ => ruleLower == packetLower
            };
        }

        /// <summary>
        /// Matches port numbers with support for complex port specifications
        /// </summary>
        private bool MatchesPort(string rulePort, int packetPort)
        {
            if (string.IsNullOrEmpty(rulePort) || rulePort == "any")
                return true;

            if (rulePort.StartsWith("$"))
            {
                var ports = ResolveSnortPortVariableToList(rulePort);
                return ports.Contains(packetPort);
            }

            return int.TryParse(rulePort, out int rulePortNum) && rulePortNum == packetPort;
        }

        /// <summary>
        /// Generates a unique hash for packet deduplication
        /// </summary>
        private string GetPacketHash(string srcIp, string dstIp, int srcPort, int dstPort, string protocol, int payloadLength)
        {
            var payloadCategory = payloadLength switch
            {
                0 => "empty",
                < 50 => "small",
                < 200 => "medium",
                < 1000 => "large",
                _ => "xlarge"
            };

            return $"{srcIp}:{srcPort}-{dstIp}:{dstPort}-{protocol}-{payloadCategory}";
        }

        /// <summary>
        /// Logs internal engine statistics for monitoring and optimization
        /// </summary>
        public void LogInternalStats()
        {
            try
            {
                OptimizedLogger.LogImportant($"[RULES_STATS] === Internal Rule Engine Statistics ===");
                OptimizedLogger.LogImportant($"[RULES_STATS] Total Packets Processed: {_packetsProcessed}");
                OptimizedLogger.LogImportant($"[RULES_STATS] Total Rules Checked: {_rulesChecked}");
                OptimizedLogger.LogImportant($"[RULES_STATS] Total Rules Matched: {_rulesMatched}");
                OptimizedLogger.LogImportant($"[RULES_STATS] Rules Filtered by Precheck: {_rulesFilteredByPrecheck}");

                if (_rulesChecked > 0)
                {
                    double matchRate = (double)_rulesMatched / _rulesChecked * 100;
                    double filterRate = (double)_rulesFilteredByPrecheck / (_rulesChecked + _rulesFilteredByPrecheck) * 100;
                    OptimizedLogger.LogImportant($"[RULES_STATS] Match Rate: {matchRate:F2}%");
                    OptimizedLogger.LogImportant($"[RULES_STATS] Pre-filter Rate: {filterRate:F2}%");
                }

                OptimizedLogger.LogImportant($"[RULES_STATS] Active Rules: {_activeRules.Count}");

                if (_rulesByProtocol != null)
                {
                    OptimizedLogger.LogImportant($"[RULES_STATS] Protocols Indexed: {_rulesByProtocol.Count}");
                    var topProtocols = _rulesByProtocol.OrderByDescending(kvp => kvp.Value.Count).Take(3);
                    foreach (var proto in topProtocols)
                    {
                        OptimizedLogger.LogImportant($"[RULES_STATS]   {proto.Key}: {proto.Value.Count} rules");
                    }
                }

                if (_rulesByDestPort != null)
                {
                    OptimizedLogger.LogImportant($"[RULES_STATS] Ports Indexed: {_rulesByDestPort.Count}");
                    var topPorts = _rulesByDestPort.Where(kvp => kvp.Key > 0).OrderByDescending(kvp => kvp.Value.Count).Take(3);
                    foreach (var port in topPorts)
                    {
                        OptimizedLogger.LogImportant($"[RULES_STATS]   {port.Key}: {port.Value.Count} rules");
                    }
                }

                OptimizedLogger.LogImportant($"[RULES_STATS] ======================================");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[RULES_STATS] Error logging internal stats: {ex.Message}");
            }
        }

        /// <summary>
        /// Logs detailed packet diagnostics for troubleshooting and analysis
        /// </summary>
        private void LogPacketDiagnostics(string protocol, int dstPort, byte[] payload, List<Entity.Signatures> relevantRules)
        {
            if (!_perfSettings.EnableDiagnosticLogging) return;

            try
            {
                OptimizedLogger.LogDebug($"[DIAG] === PACKET DIAGNOSTICS ===");
                OptimizedLogger.LogDebug($"[DIAG] Protocol: {protocol}, Port: {dstPort}, Payload: {payload?.Length ?? 0} bytes");

                if (payload != null && payload.Length > 0)
                {
                    string payloadText = Encoding.UTF8.GetString(payload);
                    OptimizedLogger.LogDebug($"[DIAG] Payload preview (first 200 chars): {payloadText.Substring(0, Math.Min(200, payloadText.Length))}");

                    string[] commonPatterns = { "union", "select", "script", "eval", "exec", "system", "cmd", "admin", "password" };
                    foreach (var pattern in commonPatterns)
                    {
                        if (payloadText.ToLower().Contains(pattern))
                        {
                            OptimizedLogger.LogDebug($"[DIAG] Found common pattern in payload: '{pattern}'");
                        }
                    }
                }

                OptimizedLogger.LogDebug($"[DIAG] Relevant rules found: {relevantRules?.Count ?? 0}");

                if (relevantRules != null && relevantRules.Any())
                {
                    var sampleRules = relevantRules.Take(3).Select(r =>
                        $"{r.SignatureId}: {r.AttackName} (Proto: {r.Protocol}, Port: {r.DestPort}, Content: {(!string.IsNullOrEmpty(r.ContentPattern) ? "Yes" : "No")})"
                    ).ToList();

                    OptimizedLogger.LogDebug($"[DIAG] Sample relevant rules:");
                    foreach (var ruleInfo in sampleRules)
                    {
                        OptimizedLogger.LogDebug($"[DIAG]   - {ruleInfo}");
                    }
                }

                OptimizedLogger.LogDebug($"[DIAG] Active rules by protocol:");
                foreach (var proto in _rulesByProtocol.OrderByDescending(kvp => kvp.Value.Count).Take(5))
                {
                    OptimizedLogger.LogDebug($"[DIAG]   {proto.Key}: {proto.Value.Count} rules");
                }

                OptimizedLogger.LogDebug($"[DIAG] ===========================");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogDebug($"[DIAG] Error in diagnostics: {ex.Message}");
            }
        }

        /// <summary>
        /// Clears all loaded rules and resets the engine to initial state
        /// </summary>
        public void ClearRules()
        {
            _activeRules.Clear();
            _rulesByProtocol?.Clear();
            _rulesByDestPort?.Clear();
            _rulesByContent?.Clear();
            _rulesWithoutContent?.Clear();
            _recentRuleChecks.Clear();

            OptimizedLogger.LogImportant("[RULES] All rules cleared from engine");
        }

        /// <summary>
        /// Gets the number of currently active rules
        /// </summary>
        public int GetActiveRulesCount()
        {
            return _activeRules.Count;
        }

        /// <summary>
        /// Prints comprehensive performance statistics including rule matching rates,
        /// processing times, and optimization effectiveness for system monitoring
        /// </summary>
        public void PrintPerformanceStats()
        {
            double efficiency = _totalRulesChecked > 0 ?
                (double)_rulesFilteredByPrecheck / (_totalRulesChecked + _rulesFilteredByPrecheck) * 100.0 : 0;

            double matchRate = _rulesChecked > 0 ?
                (double)_rulesMatched / _rulesChecked * 100.0 : 0;

            OptimizedLogger.LogImportant($"=== RULE ENGINE PERFORMANCE ===");
            OptimizedLogger.LogImportant($"Packets Processed: {_packetsProcessed}");
            OptimizedLogger.LogImportant($"Rules Checked: {_rulesChecked}");
            OptimizedLogger.LogImportant($"Rules Matched: {_rulesMatched} (Rate: {matchRate:F2}%)");
            OptimizedLogger.LogImportant($"Rules Filtered: {_rulesFilteredByPrecheck} (Efficiency: {efficiency:F2}%)");
            OptimizedLogger.LogImportant($"FastPath Optimizations: {_fastPathOptimizations}"); // 🔥 أضف هذا السطر
            OptimizedLogger.LogImportant($"Active Rules: {_activeRules.Count}");
            OptimizedLogger.LogImportant($"=================================");

            LogInternalStats();
        }

        /// <summary>
        /// Enhanced performance statistics with additional metrics and analysis
        /// </summary>
        public void PrintEnhancedPerformanceStats()
        {
            PrintPerformanceStats();
        }

        /// <summary>
        /// Prints detailed rule statistics including distribution by protocol,
        /// port, and content patterns for system analysis and optimization
        /// </summary>
        public void PrintRuleStatistics()
        {
            try
            {
                var protocolStats = _rulesByProtocol?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Count) ?? new Dictionary<string, int>();
                var portStats = _rulesByDestPort?.ToDictionary(kvp => kvp.Key.ToString(), kvp => kvp.Value.Count) ?? new Dictionary<string, int>();

                OptimizedLogger.LogImportant("=== RULE STATISTICS ===");
                OptimizedLogger.LogImportant($"Total Rules: {_activeRules.Count}");
                OptimizedLogger.LogImportant($"Rules with Content: {_activeRules.Count(r => !string.IsNullOrEmpty(r.ContentPattern))}");
                OptimizedLogger.LogImportant($"Rules without Content: {_activeRules.Count(r => string.IsNullOrEmpty(r.ContentPattern))}");

                OptimizedLogger.LogImportant("Protocol Distribution:");
                foreach (var stat in protocolStats.OrderByDescending(s => s.Value).Take(10))
                {
                    OptimizedLogger.LogImportant($"  {stat.Key}: {stat.Value} rules");
                }

                OptimizedLogger.LogImportant("Port Distribution (Top 10):");
                foreach (var stat in portStats.Where(s => s.Key != "-1").OrderByDescending(s => s.Value).Take(10))
                {
                    OptimizedLogger.LogImportant($"  {stat.Key}: {stat.Value} rules");
                }
                OptimizedLogger.LogImportant("=======================");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[STATS] Error printing rule statistics: {ex.Message}");
            }
        }

        /// <summary>
        /// Determines if traffic between two IP addresses is internal network traffic
        /// </summary>
        public bool IsInternalTraffic(string srcIp, string dstIp)
        {
            if (string.IsNullOrEmpty(srcIp) || string.IsNullOrEmpty(dstIp))
                return false;

            string[] internalRanges = {
                "192.168.", "10.",
                "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.",
                "127.0.0.1", "::1"
            };

            bool srcInternal = internalRanges.Any(range => srcIp.StartsWith(range));
            bool dstInternal = internalRanges.Any(range => dstIp.StartsWith(range));

            return srcInternal && dstInternal;
        }

        /// <summary>
        /// Identifies suspicious small packets that may indicate scanning or attacks
        /// </summary>
        public bool IsSuspiciousSmallPacket(IPPacket ipPacket)
        {
            if (ipPacket == null) return false;

            if (ipPacket.Protocol == ProtocolType.Icmp)
                return true;

            if (ipPacket.PayloadPacket is TcpPacket tcp)
            {
                if (tcp.Synchronize && !tcp.Acknowledgment)
                    return true;
                if (tcp.Finished)
                    return true;
                if (tcp.Reset)
                    return true;
                if (tcp.Urgent)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Identifies suspicious empty packets that may indicate protocol anomalies
        /// </summary>
        public bool IsSuspiciousEmptyPacket(IPPacket ipPacket)
        {
            if (ipPacket == null) return false;

            if (ipPacket.Protocol == ProtocolType.Icmp)
                return true;

            if (ipPacket.PayloadPacket is TcpPacket tcp)
            {
                if (tcp.Synchronize && !tcp.Acknowledgment)
                    return true;
                if (tcp.Finished)
                    return true;
                if (tcp.Reset)
                    return true;
                if (tcp.Urgent)
                    return true;

                int[] suspiciousPorts = { 22, 23, 135, 139, 445, 1433, 3389 };
                if (suspiciousPorts.Contains(tcp.DestinationPort) || suspiciousPorts.Contains(tcp.SourcePort))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Retrieves a rule by its signature ID for detailed analysis
        /// </summary>
        public Entity.Signatures GetRuleById(int signatureId)
        {
            return _activeRules.FirstOrDefault(rule => rule.SignatureId == signatureId);
        }
    }
}



