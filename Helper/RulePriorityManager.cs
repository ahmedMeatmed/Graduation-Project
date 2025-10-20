using System.Collections.Concurrent;

namespace IDSApp.Helper
{
    /// <summary>
    /// Manages rule priorities and detects conflicts among IDS rules.
    /// Ensures that when multiple rules match the same packet, the most specific rule is applied first.
    /// </summary>
    public class RulePriorityManager
    {
        private readonly ConcurrentDictionary<int, int> _rulePriorities = new();
        private readonly ConcurrentDictionary<string, List<int>> _conflictingRules = new();
        private readonly ConcurrentDictionary<int, RuleSpecificity> _ruleSpecificity = new();

        /// <summary>
        /// Analyzes a list of IDS rules to calculate their specificity and detect conflicts.
        /// Conflicting rules are grouped by similar characteristics (protocol, port, content pattern).
        /// </summary>
        /// <param name="rules">List of IDS rules (signatures) to analyze.</param>
        public void AnalyzeRuleConflicts(List<Entity.Signatures> rules)
        {
            _rulePriorities.Clear();
            _conflictingRules.Clear();
            _ruleSpecificity.Clear();

            foreach (var rule in rules)
            {
                var specificity = CalculateRuleSpecificity(rule);
                _ruleSpecificity[rule.SignatureId] = specificity;
                _rulePriorities[rule.SignatureId] = specificity.Score;
            }

            var contentRules = rules
                .Where(r => !string.IsNullOrEmpty(r.ContentPattern))
                .GroupBy(r => GetRuleFingerprint(r))
                .Where(g => g.Count() > 1);

            foreach (var group in contentRules)
            {
                var ruleIds = group.Select(r => r.SignatureId).ToList();
                _conflictingRules[group.Key] = ruleIds;

                foreach (var rule in group.OrderByDescending(r => _ruleSpecificity[r.SignatureId].Score))
                {
                    _rulePriorities[rule.SignatureId] = _ruleSpecificity[rule.SignatureId].Score;
                }
            }

            Console.WriteLine($"Analyzed {rules.Count} rules, found {_conflictingRules.Count} conflict groups");
        }

        /// <summary>
        /// Filters and prioritizes matching rules based on calculated priorities and conflicts.
        /// Only the highest priority rule in each conflict group is kept.
        /// </summary>
        /// <param name="matches">List of matching rules for a packet.</param>
        /// <returns>Prioritized and distinct list of rules.</returns>
        public List<Entity.Signatures> ApplyPriorities(List<Entity.Signatures> matches)
        {
            if (matches.Count <= 1)
                return matches;

            var conflictGroups = new Dictionary<string, List<Entity.Signatures>>();
            var nonConflicting = new List<Entity.Signatures>();

            foreach (var match in matches)
            {
                var fingerprint = GetRuleFingerprint(match);
                if (_conflictingRules.ContainsKey(fingerprint))
                {
                    if (!conflictGroups.ContainsKey(fingerprint))
                        conflictGroups[fingerprint] = new List<Entity.Signatures>();

                    conflictGroups[fingerprint].Add(match);
                }
                else
                {
                    nonConflicting.Add(match);
                }
            }

            var prioritizedMatches = new List<Entity.Signatures>();
            prioritizedMatches.AddRange(nonConflicting);

            foreach (var group in conflictGroups.Values)
            {
                var highestPriorityRule = group.OrderByDescending(r => _rulePriorities[r.SignatureId]).First();
                prioritizedMatches.Add(highestPriorityRule);
            }

            return prioritizedMatches.Distinct().ToList();
        }

        /// <summary>
        /// Calculates the specificity score for a rule based on protocol, ports, IPs, content pattern, and other conditions.
        /// </summary>
        /// <param name="rule">The rule to calculate specificity for.</param>
        /// <returns>A <see cref="RuleSpecificity"/> object with score and contributing fields.</returns>
        private RuleSpecificity CalculateRuleSpecificity(Entity.Signatures rule)
        {
            int score = 0;
            var specificFields = new List<string>();

            if (!string.IsNullOrEmpty(rule.Protocol) && rule.Protocol != "any") { score += 10; specificFields.Add($"Protocol:{rule.Protocol}"); }
            if (!string.IsNullOrEmpty(rule.DestPort) && rule.DestPort != "any") { score += 10; specificFields.Add($"DestPort:{rule.DestPort}"); }
            if (!string.IsNullOrEmpty(rule.SrcIp) && rule.SrcIp != "any") { score += 5; specificFields.Add($"SrcIp:{rule.SrcIp}"); }
            if (!string.IsNullOrEmpty(rule.DestIp) && rule.DestIp != "any") { score += 5; specificFields.Add($"DestIp:{rule.DestIp}"); }
            if (!string.IsNullOrEmpty(rule.ContentPattern)) { score += 20; specificFields.Add($"ContentLength:{rule.ContentPattern.Length}"); }
            if (!string.IsNullOrEmpty(rule.Http)) { score += 15; specificFields.Add("HttpConditions"); }
            if (!string.IsNullOrEmpty(rule.Tls)) { score += 15; specificFields.Add("TlsConditions"); }
            if (!string.IsNullOrEmpty(rule.Flow)) { score += 10; specificFields.Add("FlowConditions"); }

            return new RuleSpecificity { Score = score, SpecificFields = specificFields };
        }

        /// <summary>
        /// Generates a fingerprint for a rule based on protocol, destination port, and content pattern length.
        /// Used to identify potential conflicting rules.
        /// </summary>
        private string GetRuleFingerprint(Entity.Signatures rule)
        {
            var components = new List<string>
            {
                rule.Protocol ?? "any",
                rule.DestPort ?? "any",
                rule.ContentPattern?.Length.ToString() ?? "0"
            };
            return string.Join("|", components);
        }

        /// <summary>
        /// Prints the calculated specificity scores and fields for all rules.
        /// </summary>
        public void PrintRuleAnalysis()
        {
            Console.WriteLine("Rule Priority Analysis:");
            foreach (var rule in _ruleSpecificity.OrderByDescending(r => r.Value.Score))
            {
                Console.WriteLine($"Rule {rule.Key}: Score={rule.Value.Score}, Fields=[{string.Join(", ", rule.Value.SpecificFields)}]");
            }
        }
    }

    /// <summary>
    /// Represents the specificity of a rule with a score and contributing fields.
    /// </summary>
    public class RuleSpecificity
    {
        public int Score { get; set; }
        public List<string> SpecificFields { get; set; } = new List<string>();
    }
}
