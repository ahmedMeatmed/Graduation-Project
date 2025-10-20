using PacketDotNet;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Timers;

namespace IDSApp.Helper
{
    /// <summary>
    /// Robust TCP Stream Reassembler for higher-layer protocols (e.g., SMB, HTTP, TLS)
    /// Handles bidirectional reassembly, out-of-order segments, retransmissions,
    /// and multi-packet message extraction (especially for NetBIOS/SMB).
    /// </summary>
    public class TcpStreamReassembler : IDisposable
    {
        private class TcpConnection : IDisposable
        {
            public SortedList<uint, byte[]> Fragments { get; } = new();
            public uint NextExpectedSequence { get; set; }
            public DateTime LastActivity { get; set; } = DateTime.Now;
            public const int MaxBufferSize = 10 * 1024 * 1024; // 10MB
            public void Dispose() => Fragments.Clear();
        }

        private readonly ConcurrentDictionary<string, TcpConnection> _connections = new();
        private readonly System.Timers.Timer _cleanupTimer;
        private bool _disposed = false;

        public TcpStreamReassembler()
        {
            _cleanupTimer = new System.Timers.Timer(30000); // cleanup every 30s
            _cleanupTimer.Elapsed += (s, e) => CleanupOldConnections(TimeSpan.FromMinutes(10));
            _cleanupTimer.Start();
        }

        private static string GetConnectionKey(IPv4Packet ip, TcpPacket tcp, bool reverse = false)
        {
            return !reverse
                ? $"{ip.SourceAddress}:{tcp.SourcePort}-{ip.DestinationAddress}:{tcp.DestinationPort}"
                : $"{ip.DestinationAddress}:{tcp.DestinationPort}-{ip.SourceAddress}:{tcp.SourcePort}";
        }

        /// <summary>
        /// Processes an incoming TCP segment and returns all complete higher-layer messages.
        /// </summary>
        public List<byte[]> ProcessTcpSegment(IPv4Packet ip, TcpPacket tcp)
        {
            var messages = new List<byte[]>();
            if (tcp.PayloadData == null || tcp.PayloadData.Length == 0)
                return messages;

            string key = GetConnectionKey(ip, tcp);
            string reverseKey = GetConnectionKey(ip, tcp, true);

            var conn = _connections.GetOrAdd(key, _ => new TcpConnection());
            conn.LastActivity = DateTime.Now;

            lock (conn)
            {
                // Handle retransmission or duplicates
                if (!conn.Fragments.ContainsKey(tcp.SequenceNumber))
                    conn.Fragments[tcp.SequenceNumber] = tcp.PayloadData;

                MergeFragments(conn);

                messages.AddRange(ExtractMessages(conn, key));

                if (tcp.Finished || tcp.Reset)
                {
                    OptimizedLogger.LogDebug($"[TCP-REASSEMBLY] Connection closed ({(tcp.Finished ? "FIN" : "RST")}) {key}");
                    _connections.TryRemove(key, out _);
                    _connections.TryRemove(reverseKey, out _);
                    conn.Dispose();
                }
            }

            return messages;
        }

        /// <summary>
        /// Merges contiguous TCP fragments based on sequence numbers.
        /// </summary>
        private void MergeFragments(TcpConnection conn)
        {
            if (conn.Fragments.Count == 0) return;

            var ordered = conn.Fragments.OrderBy(f => f.Key).ToList();
            var merged = new List<byte>();
            uint expected = ordered.First().Key;
            var toRemove = new List<uint>();

            foreach (var (seq, data) in ordered)
            {
                if (seq == expected)
                {
                    merged.AddRange(data);
                    expected += (uint)data.Length;
                    toRemove.Add(seq);
                }
                else if (seq < expected)
                {
                    // overlapping segment (retransmit)
                    toRemove.Add(seq);
                }
                else break; // gap
            }

            foreach (var seq in toRemove)
                conn.Fragments.Remove(seq);

            conn.Fragments[expected - (uint)merged.Count] = merged.ToArray();
            conn.NextExpectedSequence = expected;
        }

        /// <summary>
        /// Extracts complete SMB/NetBIOS messages or any other TCP-based protocol messages.
        /// </summary>
        private List<byte[]> ExtractMessages(TcpConnection conn, string key)
        {
            var messages = new List<byte[]>();
            if (conn.Fragments.Count == 0)
                return messages;

            var buffer = conn.Fragments.Values.SelectMany(f => f).ToList();
            int offset = 0;

            while (buffer.Count - offset >= 4)
            {
                // Check for NetBIOS Session header (0x00 or 0x81)
                if (buffer[offset] == 0x00 || buffer[offset] == 0x81)
                {
                    int msgLength = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
                    int totalLength = msgLength + 4;

                    if (buffer.Count - offset >= totalLength)
                    {
                        byte[] message = buffer.Skip(offset).Take(totalLength).ToArray();
                        messages.Add(message);
                        offset += totalLength;
                        OptimizedLogger.LogDebug($"[TCP-REASSEMBLY] Extracted complete {totalLength}B message from {key}");
                    }
                    else break; // incomplete message, wait for next packet
                }
                else
                {
                    offset++; // skip invalid header byte
                }
            }

            // Keep remaining incomplete bytes
            var leftover = buffer.Skip(offset).ToArray();
            conn.Fragments.Clear();
            if (leftover.Length > 0)
                conn.Fragments[conn.NextExpectedSequence - (uint)leftover.Length] = leftover;

            return messages;
        }

        public void CleanupOldConnections(TimeSpan maxAge)
        {
            try
            {
                var cutoff = DateTime.Now - maxAge;
                var expired = _connections.Where(kv => kv.Value.LastActivity < cutoff).ToList();

                foreach (var item in expired)
                {
                    if (_connections.TryRemove(item.Key, out var conn))
                        conn.Dispose();
                }

                if (expired.Count > 0)
                    OptimizedLogger.LogDebug($"[TCP-REASSEMBLY] Cleaned up {expired.Count} idle connections");
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[TCP-REASSEMBLY] Cleanup error: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _cleanupTimer?.Stop();
            _cleanupTimer?.Dispose();

            foreach (var conn in _connections.Values)
                conn.Dispose();

            _connections.Clear();
            _disposed = true;
        }
    }

}
