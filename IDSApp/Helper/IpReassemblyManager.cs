using PacketDotNet;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IDSApp.Helper
{
    /// <summary>
    /// Enhanced IP fragment reassembly manager with proper memory management
    /// </summary>
    public class IpReassemblyManager : IDisposable
    {
        private readonly ConcurrentDictionary<string, IpFragmentBuffer> _fragmentBuffers;
        private readonly ConcurrentDictionary<string, DateTime> _fragmentTimestamps;
        private readonly TimeSpan _fragmentTimeout;
        private readonly System.Timers.Timer _cleanupTimer;
        private bool _disposed = false;

        public IpReassemblyManager()
        {
            _fragmentBuffers = new ConcurrentDictionary<string, IpFragmentBuffer>();
            _fragmentTimestamps = new ConcurrentDictionary<string, DateTime>();
            _fragmentTimeout = TimeSpan.FromSeconds(30);

            _cleanupTimer = new System.Timers.Timer(15000);
            _cleanupTimer.Elapsed += (s, e) => CleanupExpiredFragments();
            _cleanupTimer.Start();
        }

        /// <summary>
        /// Process an IPv4 fragment and return a reassembled IP packet if complete
        /// </summary>
        public IPPacket ProcessFragment(IPPacket ipPacket)
        {
            if (!(ipPacket is IPv4Packet ipv4)) return ipPacket;

            bool moreFragments = (ipv4.FragmentFlags & 0x1) != 0;
            bool hasOffset = ipv4.FragmentOffset > 0;
            bool isFragmented = moreFragments || hasOffset;

            if (!isFragmented) return ipPacket;

            string key = $"{ipv4.SourceAddress}-{ipv4.DestinationAddress}-{ipv4.Protocol}-{ipv4.Id}";

            var buffer = _fragmentBuffers.GetOrAdd(key, k => new IpFragmentBuffer(ipv4.Protocol));
            _fragmentTimestamps[key] = DateTime.Now;

            var reassembledPacket = buffer.AddFragment(ipv4, ipv4.FragmentOffset * 8, !moreFragments);

            if (reassembledPacket != null)
            {
                _fragmentBuffers.TryRemove(key, out _);
                _fragmentTimestamps.TryRemove(key, out _);
            }

            return reassembledPacket;
        }

        public ReassemblyStats GetStats()
        {
            return new ReassemblyStats
            {
                ActiveBuffers = _fragmentBuffers.Count,
                TotalMemoryUsage = _fragmentBuffers.Values.Sum(b => b.BufferSize)
            };
        }

        private void CleanupExpiredFragments()
        {
            try
            {
                var now = DateTime.Now;
                var expired = _fragmentTimestamps
                    .Where(kv => now - kv.Value > _fragmentTimeout)
                    .Select(kv => kv.Key)
                    .ToList();

                foreach (var key in expired)
                {
                    if (_fragmentBuffers.TryRemove(key, out var buffer))
                    {
                        buffer.Dispose();
                    }
                    _fragmentTimestamps.TryRemove(key, out _);
                }

                if (expired.Count > 0)
                {
                    OptimizedLogger.LogDebug($"[REASSEMBLY] Cleaned up {expired.Count} expired fragment buffers");
                }
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogError($"[REASSEMBLY] Cleanup error: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (_disposed) return;

            _cleanupTimer?.Stop();
            _cleanupTimer?.Dispose();

            foreach (var buffer in _fragmentBuffers.Values)
            {
                buffer.Dispose();
            }
            _fragmentBuffers.Clear();
            _fragmentTimestamps.Clear();

            _disposed = true;
        }
    }

    public class ReassemblyStats
    {
        public int ActiveBuffers { get; set; }
        public long TotalMemoryUsage { get; set; }
    }

    /// <summary>
    /// Enhanced fragment buffer with proper resource disposal
    /// </summary>
    public class IpFragmentBuffer : IDisposable
    {
        private readonly ProtocolType _protocol;
        private readonly SortedDictionary<int, byte[]> _fragments = new();
        private readonly List<byte[]> _rentedArrays = new();
        private bool _hasLastFragment;
        private bool _disposed;

        public IpFragmentBuffer(ProtocolType protocol) => _protocol = protocol;

        public int BufferSize => _fragments.Values.Sum(f => f?.Length ?? 0);

        public IPPacket AddFragment(IPv4Packet fragment, int offset, bool isLastFragment)
        {
            if (_disposed) return null;

            lock (_fragments)
            {
                byte[] storedData;
                var payload = fragment.PayloadData;

                if (payload != null && payload.Length > 0)
                {
                    storedData = ArrayPool<byte>.Shared.Rent(payload.Length);
                    Buffer.BlockCopy(payload, 0, storedData, 0, payload.Length);
                    _rentedArrays.Add(storedData);
                }
                else
                {
                    storedData = Array.Empty<byte>();
                }

                _fragments[offset] = storedData;
                _hasLastFragment |= isLastFragment;

                if (_hasLastFragment && IsComplete())
                    return ReassemblePacket(fragment);
            }

            return null;
        }

        private bool IsComplete()
        {
            int expectedOffset = 0;

            foreach (var kvp in _fragments)
            {
                if (kvp.Key != expectedOffset) return false;
                expectedOffset += kvp.Value.Length;
                if (expectedOffset > 65535) return false; // safety
            }

            return _hasLastFragment;
        }

        private IPPacket ReassemblePacket(IPv4Packet lastFragment)
        {
            int totalLength = _fragments.Values.Sum(f => f.Length);
            if (totalLength == 0) return null;

            byte[] reassembledData = new byte[totalLength];
            int pos = 0;

            foreach (var fragment in _fragments.Values)
            {
                if (fragment.Length > 0)
                {
                    Buffer.BlockCopy(fragment, 0, reassembledData, pos, fragment.Length);
                    pos += fragment.Length;
                }
            }

            // Clean up rented arrays immediately
            foreach (var arr in _rentedArrays)
            {
                if (arr != Array.Empty<byte>())
                    ArrayPool<byte>.Shared.Return(arr);
            }
            _rentedArrays.Clear();
            _fragments.Clear();

            var reassembledPacket = new IPv4Packet(lastFragment.SourceAddress, lastFragment.DestinationAddress)
            {
                Protocol = _protocol,
                FragmentFlags = 0,
                FragmentOffset = 0
            };

            try
            {
                if (_protocol == ProtocolType.Tcp && reassembledData.Length >= 20)
                    reassembledPacket.PayloadPacket = new TcpPacket(new PacketDotNet.Utils.ByteArraySegment(reassembledData));
                else if (_protocol == ProtocolType.Udp && reassembledData.Length >= 8)
                    reassembledPacket.PayloadPacket = new UdpPacket(new PacketDotNet.Utils.ByteArraySegment(reassembledData));
            }
            catch (Exception ex)
            {
                OptimizedLogger.LogDebug($"[REASSEMBLY] Protocol parsing failed: {ex.Message}");
            }

            return reassembledPacket;
        }

        public void Dispose()
        {
            if (_disposed) return;

            lock (_fragments)
            {
                foreach (var arr in _rentedArrays)
                    if (arr != Array.Empty<byte>()) ArrayPool<byte>.Shared.Return(arr);

                _fragments.Clear();
                _rentedArrays.Clear();
            }

            _disposed = true;
        }
    }
}
