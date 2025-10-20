using System.Text;
using System.Text.RegularExpressions;

namespace IDSApp.Helper
{
    /// <summary>
    /// Defines an interface for pattern matchers that operate on raw packet payloads.
    /// Used for detecting signatures or malicious content across various protocols.
    /// </summary>
    public interface IContentMatcher
    {
        /// <summary>
        /// Determines whether the specified payload matches a predefined pattern.
        /// </summary>
        /// <param name="payload">The byte array representing packet data.</param>
        /// <param name="protocol">The name of the protocol being analyzed (e.g., HTTP, DNS).</param>
        /// <returns><c>true</c> if the pattern is found within the payload; otherwise, <c>false</c>.</returns>
        bool Match(byte[] payload, string protocol);
    }

    /// <summary>
    /// Performs pattern matching on raw byte payloads using a simple byte comparison algorithm.
    /// Used for non-text protocols or binary signatures.
    /// </summary>
    public class BytePatternMatcher : IContentMatcher
    {
        private readonly byte[] _pattern;

        /// <summary>
        /// Initializes a new instance of the <see cref="BytePatternMatcher"/> class.
        /// </summary>
        /// <param name="pattern">The byte pattern to search for within payloads.</param>
        public BytePatternMatcher(byte[] pattern)
        {
            _pattern = pattern;
        }

        /// <summary>
        /// Checks whether the payload contains the specified byte pattern.
        /// </summary>
        /// <param name="payload">The packet payload as a byte array.</param>
        /// <param name="protocol">The name of the protocol being analyzed.</param>
        /// <returns><c>true</c> if the pattern is found; otherwise, <c>false</c>.</returns>
        public bool Match(byte[] payload, string protocol)
        {
            if (payload == null || _pattern == null || _pattern.Length == 0)
                return false;

            return BoyerMooreSearch.Contains(payload, _pattern);
        }
    }

    /// <summary>
    /// Performs pattern matching using PCRE (Perl-Compatible Regular Expressions).
    /// Useful for detecting text-based signatures in HTTP, SMTP, or DNS payloads.
    /// </summary>
    public class PcreContentMatcher : IContentMatcher
    {
        private readonly Regex _regex;

        /// <summary>
        /// Initializes a new instance of the <see cref="PcreContentMatcher"/> class.
        /// </summary>
        /// <param name="regex">The regular expression pattern used for matching text payloads.</param>
        public PcreContentMatcher(Regex regex)
        {
            _regex = regex;
        }

        /// <summary>
        /// Checks whether the text content of the payload matches the configured regular expression.
        /// </summary>
        /// <param name="payload">The raw packet payload.</param>
        /// <param name="protocol">The protocol being analyzed (for contextual matching).</param>
        /// <returns><c>true</c> if the regex matches the text content; otherwise, <c>false</c>.</returns>
        public bool Match(byte[] payload, string protocol)
        {
            if (payload == null || payload.Length == 0)
                return false;

            try
            {
                var text = Encoding.UTF8.GetString(payload);
                return _regex.IsMatch(text);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Provides efficient search methods for locating byte or character sequences
    /// within larger datasets, based on the Boyer-Moore algorithm.
    /// </summary>
    public static class BoyerMooreSearch
    {
        /// <summary>
        /// Searches for a byte sequence within another byte sequence.
        /// </summary>
        /// <param name="haystack">The main data buffer to search in.</param>
        /// <param name="needle">The byte pattern to look for.</param>
        /// <returns><c>true</c> if the pattern exists in the buffer; otherwise, <c>false</c>.</returns>
        public static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
        {
            if (needle.Length == 0) return true;
            if (haystack.Length < needle.Length) return false;

            // Simple implementation for now - consider proper Boyer-Moore for production
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

        /// <summary>
        /// Searches for a character sequence within another string (case-insensitive).
        /// </summary>
        /// <param name="haystack">The text content to search in.</param>
        /// <param name="needle">The substring to look for.</param>
        /// <returns><c>true</c> if the substring exists within the text; otherwise, <c>false</c>.</returns>
        public static bool Contains(ReadOnlySpan<char> haystack, ReadOnlySpan<char> needle)
        {
            if (needle.Length == 0) return true;
            if (haystack.Length < needle.Length) return false;

            // Case-insensitive search
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (char.ToLowerInvariant(haystack[i + j]) != char.ToLowerInvariant(needle[j]))
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
