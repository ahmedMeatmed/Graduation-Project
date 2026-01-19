using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using IDSApp.BLL;
using IDSApp.Entity;

namespace IDSApp.Helper
{
    /// <summary>
    /// High-performance rule checking optimization system using Bloom Filters technology
    /// 
    /// Main Responsibilities:
    /// - Create and manage Bloom Filters for fast rule filtering
    /// - Reduce number of rules needing detailed inspection
    /// - Provide automatic performance statistics and optimization
    /// - Manage cache for inspection results
    /// 
    /// How It Works:
    /// 1. Group rules by protocol and common ports
    /// 2. Build Bloom Filters for each rule group
    /// 3. Use filters for quick match possibility checking
    /// 4. Skip detailed inspection when filters confirm no possible match
    /// 
    /// Features:
    /// - Significant rule inspection performance improvement
    /// - Automatic adaptation to rule changes
    /// - Continuous system accuracy monitoring
    /// - Automatic rebuild when efficiency decreases
    /// </summary>
    public class RuleFastPathOptimizer
    {
        private readonly ConcurrentDictionary<string, RuleBloomFilter> _bloomFilters = new();
        private readonly ConcurrentDictionary<string, RuleGroup> _ruleGroups = new();
        private readonly System.Timers.Timer _statsTimer;
        private DateTime _lastBuildTime = DateTime.MinValue;
        private readonly bool _debug;
        private readonly int _rebuildIntervalMinutes;
        private readonly double _fppThresholdPercent;

        private readonly ConcurrentDictionary<string, (bool Result, DateTime Expiry)> _matchCache = new();
        private readonly TimeSpan _cacheTtl = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Initialize Rule Fast Path Optimizer
        /// </summary>
        /// <param name="debug">Enable debug mode for detailed logging</param>
        /// <param name="rebuildIntervalMinutes">Auto-rebuild interval in minutes</param>
        /// <param name="fppThresholdPercent">False positive rate threshold before rebuild</param>
        public RuleFastPathOptimizer(bool debug = false, int rebuildIntervalMinutes = 10, double fppThresholdPercent = 5.0)
        {
            _debug = debug;
            _rebuildIntervalMinutes = rebuildIntervalMinutes;
            _fppThresholdPercent = fppThresholdPercent;

            _statsTimer = new System.Timers.Timer(TimeSpan.FromMinutes(1).TotalMilliseconds);
            _statsTimer.Elapsed += (_, __) => SaveOptimizationStats();
            _statsTimer.AutoReset = true;
            _statsTimer.Start();
        }

        /// <summary>
        /// Build Bloom Filters from provided rules
        /// Groups rules by protocol and creates filters for common ports
        /// </summary>
        /// <param name="rules">List of security rules to optimize</param>
        // ✅ IMPROVED BLOOM FILTER CONSTRUCTION:
        public void BuildBloomFilters(List<Entity.Signatures> rules)
        {
            if (rules == null || !rules.Any())
            {
                LogDebug("No rules provided for bloom filter building");

                // ✅ FIX: Create at least a basic "any" filter to prevent total blocking
                CreateFallbackFilters();
                return;
            }

            _bloomFilters.Clear();
            _ruleGroups.Clear();

            try
            {
                int estimatedRules = Math.Max(1, rules.Count);
                int filterSize = CalculateOptimalFilterSize(estimatedRules);

                // Group by protocol with fallback
                var protocolGroups = rules.GroupBy(r => GetProtocolKey(r));

                foreach (var group in protocolGroups)
                {
                    if (group.Any())
                    {
                        var bloomFilter = new RuleBloomFilter(filterSize);
                        var ruleGroup = new RuleGroup { Protocol = group.Key };

                        foreach (var rule in group)
                        {
                            bloomFilter.AddRule(rule);
                            ruleGroup.Rules.Add(rule);
                        }

                        _bloomFilters[group.Key] = bloomFilter;
                        _ruleGroups[group.Key] = ruleGroup;

                        LogDebug($"Built filter for {group.Key}: {group.Count()} rules");
                    }
                }

                // Always build common port filters
                BuildCommonPortFilters(rules, filterSize);

                // ✅ CRITICAL: Ensure we always have at least basic filters
                if (!_bloomFilters.Any())
                {
                    CreateFallbackFilters();
                }

                LogDebug($"Built {_bloomFilters.Count} bloom filters for rule optimization");
                _lastBuildTime = DateTime.UtcNow;
                SaveOptimizationStats();
            }
            catch (Exception ex)
            {
                LogDebug($"Error building bloom filters: {ex.Message}");
                CreateFallbackFilters(); // Ensure basic functionality
            }
        }
        private int CalculateOptimalFilterSize(int estimatedRules)
        {
            // Use optimal bloom filter sizing formula: m = -n * ln(p) / (ln(2))^2
            // Where n = number of items, p = desired false positive probability
            double desiredFpp = 0.01; // 1% false positive rate
            int optimalSize = (int)Math.Ceiling(-estimatedRules * Math.Log(desiredFpp) / Math.Pow(Math.Log(2), 2));

            // Round up to nearest power of 2 for better performance
            int size = 1024;
            while (size < optimalSize && size < 16777216) // Max 16MB filter
            {
                size <<= 1;
            }

            LogDebug($"Calculated filter size: {size} for {estimatedRules} rules (optimal: {optimalSize})");
            return Math.Max(1024, Math.Min(size, 16777216));
        }
        private void CreateFallbackFilters()
        {
            // Create basic fallback filters to prevent total blocking
            var fallbackFilter = new RuleBloomFilter(1024);
            _bloomFilters["any"] = fallbackFilter;
            _ruleGroups["any"] = new RuleGroup { Protocol = "any" };

            LogDebug("Created fallback bloom filters");
        }

        private string GetProtocolKey(Entity.Signatures rule)
        {
            string protocol = rule.Protocol?.ToLower()?.Trim();
            return string.IsNullOrEmpty(protocol) || protocol == "any" ? "any" : protocol;
        }
        /// <summary>
        /// Build special Bloom Filters for common network ports
        /// Optimizes checking for frequently used ports like HTTP, HTTPS, SSH, etc.
        /// </summary>
        private void BuildCommonPortFilters(List<Entity.Signatures> rules, int filterSize)
        {
            int[] commonPorts = { 80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3389, 8080, 8443 };

            foreach (int port in commonPorts)
            {
                var portRules = rules.Where(r =>
                    (r.DestPort == port.ToString()) ||
                    (r.DestPort == "any") ||
                    (r.DestPort?.Contains(port.ToString()) == true)
                ).ToList();

                if (portRules.Any())
                {
                    var filter = new RuleBloomFilter(filterSize);
                    foreach (var rule in portRules)
                    {
                        filter.AddRule(rule);
                    }
                    string portKey = $"port_{port}";
                    _bloomFilters[portKey] = filter;
                    _ruleGroups[portKey] = new RuleGroup { Protocol = portKey, Rules = portRules };
                    LogDebug($"Built port filter {portKey}: {portRules.Count} rules");
                }
            }
        }


        /// <summary>
        /// Determine if rules should be checked for given network parameters
        /// Uses Bloom Filters for fast path optimization
        /// </summary>
        // ✅ CORRECTED VERSION:
        public bool ShouldCheckRules(string protocol, int dstPort, int payloadLength,
            string ruleGroup, int srcPort = 0, string flowDirection = "")
        {
            protocol = (protocol ?? "any").ToLower();

            // ✅ FIX: Only skip zero-length payload for protocols where it's truly invalid
            if (payloadLength == 0 && !IsProtocolWithZeroLengthValid(protocol))
            {
                // For protocols like TCP/UDP, empty payload might be normal (ACK packets, etc.)
                // Don't automatically skip - let the rule engine decide
                if (_debug)
                {
                    Console.WriteLine($"[ShouldCheckRules] Zero-length {protocol} packet - allowing inspection");
                }
            }

            string cacheKey = $"{protocol}|{dstPort}|{payloadLength}|{srcPort}|{flowDirection}";

            // Check cache
            if (_matchCache.TryGetValue(cacheKey, out var cached) && cached.Expiry > DateTime.UtcNow)
                return cached.Result;

            bool mightMatch = true;

            // ✅ CRITICAL FIX: If no bloom filters built, ALWAYS check rules
            if (!_bloomFilters.Any())
            {
                mightMatch = true;
                if (_debug)
                {
                    Console.WriteLine($"[ShouldCheckRules] No bloom filters - defaulting to true");
                }
            }
            else
            {
                mightMatch = false; // Start false, prove otherwise

                // Check protocol filter
                if (_bloomFilters.TryGetValue(protocol, out var protoFilter))
                {
                    mightMatch = protoFilter.MightMatch(protocol, dstPort, payloadLength, srcPort, flowDirection);
                }

                // Check port filter if protocol filter didn't match
                if (!mightMatch && _bloomFilters.TryGetValue($"port_{dstPort}", out var portFilter))
                {
                    mightMatch = portFilter.MightMatch(protocol, dstPort, payloadLength, srcPort, flowDirection);
                }

                // Check "any" filter as final fallback
                if (!mightMatch && _bloomFilters.TryGetValue("any", out var anyFilter))
                {
                    mightMatch = anyFilter.MightMatch(protocol, dstPort, payloadLength, srcPort, flowDirection);
                }
            }

            // Cache the result
            _matchCache[cacheKey] = (mightMatch, DateTime.UtcNow + _cacheTtl);

            if (_debug)
            {
                Console.WriteLine($"[ShouldCheckRules] protocol={protocol}, dstPort={dstPort}, " +
                                 $"payload={payloadLength}, mightMatch={mightMatch}, " +
                                 $"filtersCount={_bloomFilters.Count}");
            }

            return mightMatch;
        }
        // ✅ IMPROVED PROTOCOL VALIDATION:
        private bool IsProtocolWithZeroLengthValid(string protocol)
        {
            // Allow zero-length payload for these common scenarios:
            string[] validProtocols = {
        "tcp", "udp", "icmp", "http", "https", "dns", "ftp", "ssh",
        "smtp", "telnet", "rdp", "arp", "ip", "ipv6", "icmpv6"
    };

            // Also allow any protocol that starts with common prefixes
            return validProtocols.Contains(protocol?.ToLower() ?? "") ||
                   protocol?.StartsWith("tcp") == true ||
                   protocol?.StartsWith("udp") == true ||
                   protocol?.StartsWith("ip") == true;
        }


        /// <summary>
        /// Get current optimization statistics
        /// </summary>
        public RuleOptimizationStats GetOptimizationStats()
        {
            var stats = new RuleOptimizationStats();
            double totalFpp = 0;
            foreach (var filter in _bloomFilters)
            {
                stats.TotalFilters++;
                if (_ruleGroups.TryGetValue(filter.Key, out var ruleGroup))
                {
                    stats.TotalRules += ruleGroup.Rules.Count;
                }
                stats.MemoryUsage += filter.Value.GetMemoryUsage();
                totalFpp += filter.Value.GetFalsePositiveProbability();
            }
            stats.FalsePositiveEstimate = stats.TotalFilters > 0 ? totalFpp / stats.TotalFilters : 0;
            return stats;
        }

        /// <summary>
        /// Print optimization information to console
        /// </summary>
        public void PrintOptimizationInfo()
        {
            var stats = GetOptimizationStats();
            Console.WriteLine($"Rule Optimization: {stats.TotalFilters} filters, {stats.TotalRules} rules, {stats.MemoryUsage} bytes memory, FPP={stats.FalsePositiveEstimate:F2}%");
            SaveOptimizationStats();
        }

        /// <summary>
        /// Save optimization statistics to database and trigger adaptive rebuild if needed
        /// </summary>
        private void SaveOptimizationStats()
        {
            try
            {
                var stats = GetOptimizationStats();

                if (stats.FalsePositiveEstimate > _fppThresholdPercent ||
                    (DateTime.UtcNow - _lastBuildTime).TotalMinutes > _rebuildIntervalMinutes)
                {
                    LogDebug("Adaptive rebuild triggered due to high FPP or rebuild interval");
                    var rules = SignatureBLL.GetAll();
                    BuildBloomFilters(rules);
                    stats = GetOptimizationStats();
                }

                int id = RuleOptimizationStatsHistoryBLL.Insert(
                    stats.TotalFilters,
                    stats.TotalRules,
                    stats.MemoryUsage,
                    stats.FalsePositiveEstimate,
                    DateTime.Now
                );

                if (id > 0)
                {
                    LogDebug($"Successfully saved optimization stats (ID: {id}): {stats.TotalFilters} filters, {stats.TotalRules} rules, {stats.MemoryUsage} bytes, FPP: {stats.FalsePositiveEstimate:F2}%");
                }
                else
                {
                    LogDebug("Failed to save optimization stats: No ID returned");
                }

                CleanupCache();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving optimization stats to database: {ex.Message}");
            }
        }

        private void CleanupCache()
        {
            var now = DateTime.UtcNow;
            foreach (var kvp in _matchCache)
            {
                if (kvp.Value.Expiry <= now)
                    _matchCache.TryRemove(kvp.Key, out _);
            }
        }

        private void LogDebug(string msg)
        {
            if (_debug)
                Console.WriteLine($"[RuleFastPathOptimizer][DEBUG] {msg}");
        }

        private int CalculateFilterSize(int estimatedRules)
        {
            int baseSize = Math.Max(16384, estimatedRules * 16);
            int size = 1;
            while (size < baseSize) size <<= 1;
            return size;
        }
    }

    /// <summary>
    /// Bloom Filter implementation specialized for security rules
    /// Uses multiple hash functions to represent rules in compact bit array
    /// </summary>
    public class RuleBloomFilter
    {
        private readonly BitArrayWrapper _bits;
        private int _ruleCount = 0;
        private readonly int _filterSize;
        private readonly int _hashFunctionCount = 3;

        public RuleBloomFilter(int filterSize = 16384)
        {
            _filterSize = Math.Max(1024, filterSize);
            _bits = new BitArrayWrapper(_filterSize);
        }

        /// <summary>
        /// Add a security rule to the Bloom Filter
        /// </summary>
        public void AddRule(Entity.Signatures rule)
        {
            Interlocked.Increment(ref _ruleCount);

            var hashes = GetRuleHashes(rule);
            foreach (var hash in hashes)
            {
                int idx = Math.Abs(hash % _filterSize);
                _bits.Set(idx);
            }
        }

        /// <summary>
        /// Check if network parameters might match any rule in this filter
        /// Returns false for definite non-matches, true for possible matches
        /// </summary>
        public bool MightMatch(string protocol, int port, int payloadLength, int srcPort = 0, string flowDirection = "")
        {
            // ✅ FIX: If no rules in filter, return true to allow checking
            if (_ruleCount == 0)
            {
                return true; // No rules means we can't definitively say no
            }

            var testHashes = GetTestHashes(protocol, port, payloadLength, srcPort, flowDirection);

            foreach (var hash in testHashes)
            {
                int idx = Math.Abs(hash % _filterSize);
                if (!_bits.Get(idx))
                {
                    // One hash misses = definitely no match
                    return false;
                }
            }

            // All hashes hit = possible match
            return true;
        }

        // Enhanced hash generation
        private int[] GetTestHashes(string protocol, int port, int payloadLength, int srcPort, string flowDirection)
        {
            var hashes = new List<int>
        {
            GetStringHash((protocol ?? "any").ToLower()),
            GetPortHash(port),
            GetPayloadLengthHash(payloadLength)
        };

            // Include source port if specified
            if (srcPort != 0)
                hashes.Add(GetPortHash(srcPort));

            // Include flow direction if specified
            if (!string.IsNullOrEmpty(flowDirection))
                hashes.Add(GetStringHash(flowDirection.ToLower()));

            return hashes.ToArray();
        }

        private int GetPayloadLengthHash(int length)
        {
            // Categorize payload length for better hashing
            string category = length switch
            {
                0 => "empty",
                < 50 => "small",
                < 200 => "medium",
                < 1000 => "large",
                _ => "xlarge"
            };
            return GetStringHash(category);
        }

        private int[] GetRuleHashes(Entity.Signatures rule)
        {
            var hashes = new List<int>
            {
                GetStringHash(rule.Protocol?.ToLower() ?? "any"),
                !string.IsNullOrEmpty(rule.DestPort) && rule.DestPort != "any" && int.TryParse(rule.DestPort, out int p) ? GetPortHash(p) : GetStringHash(rule.DestPort ?? "any_port"),
                GetStringHash(GetContentKey(rule))
            };

            if (!string.IsNullOrEmpty(rule.SrcPort))
                hashes.Add(GetStringHash(rule.SrcPort));

            return hashes.ToArray();
        }


        private string GetContentKey(Entity.Signatures rule)
        {
            if (string.IsNullOrEmpty(rule.ContentPattern))
                return "no_content";

            int length = rule.ContentPattern.Length;
            if (length <= 10) return "very_short";
            if (length <= 50) return "short";
            if (length <= 200) return "medium";
            return "long";
        }

        private string GetPayloadKey(int payloadLength)
        {
            if (payloadLength == 0) return "no_payload";
            if (payloadLength <= 10) return "very_short";
            if (payloadLength <= 50) return "short";
            if (payloadLength <= 200) return "medium";
            return "long";
        }

        private int GetPortHash(int port)
        {
            unchecked
            {
                return port * 2654435761.GetHashCode();
            }
        }

        private int GetStringHash(string input)
        {
            if (string.IsNullOrEmpty(input))
                return 0;
            unchecked
            {
                int hash = (int)2166136261;
                foreach (char c in input)
                {
                    hash = (hash ^ c) * 16777619;
                }
                return hash;
            }
        }

        /// <summary>
        /// Get memory usage of this Bloom Filter in bytes
        /// </summary>
        public long GetMemoryUsage()
        {
            return _filterSize / 8L;
        }

        /// <summary>
        /// Calculate estimated false positive probability percentage
        /// </summary>
        public double GetFalsePositiveProbability()
        {
            if (_ruleCount == 0) return 0.0;

            int m = _filterSize;
            int k = _hashFunctionCount;
            int n = _ruleCount;

            double p = Math.Pow(1 - Math.Exp(-k * n / (double)m), k);
            return p * 100.0;
        }
    }

    /// <summary>
    /// Thread-safe bit array wrapper for Bloom Filter implementation
    /// Uses integer arrays for efficient bit storage and operations
    /// </summary>
    internal class BitArrayWrapper
    {
        private readonly int _size;
        private readonly int[] _data;

        public BitArrayWrapper(int size)
        {
            _size = size;
            int blocks = (size + 31) / 32;
            _data = new int[blocks];
        }

        public void Set(int idx)
        {
            int block = idx / 32;
            int bit = idx % 32;
            Interlocked.Or(ref _data[block], 1 << bit);
        }

        public bool Get(int idx)
        {
            int block = idx / 32;
            int bit = idx % 32;
            return ((_data[block] >> bit) & 1) == 1;
        }
    }

    /// <summary>
    /// Represents a group of security rules with common characteristics
    /// Used for organized rule management and optimization
    /// </summary>
    public class RuleGroup
    {
        public string Protocol { get; set; }
        public List<Entity.Signatures> Rules { get; set; } = new List<Entity.Signatures>();
    }

    /// <summary>
    /// Statistics container for rule optimization performance metrics
    /// Tracks filter count, rule count, memory usage, and accuracy estimates
    /// </summary>
    public class RuleOptimizationStats
    {
        public int TotalFilters { get; set; }
        public int TotalRules { get; set; }
        public long MemoryUsage { get; set; }
        public double FalsePositiveEstimate { get; set; }
    }
}