using IDSApp.BLL;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IDSApp.Helper
{

    // ====== AiEngine (One class handles ALL AI logic) ======
    public class AiEngine : IDisposable
    {
        private readonly HttpClient _http;
        private readonly BlockingCollection<PacketInfo> _queue;
        private readonly List<Task> _workers;
        private CancellationTokenSource _cts;

        private readonly string _apiUrl = "http://127.0.0.1:5000/predict"; // عدله حسب API بتاع AI
        private readonly int _workerCount = 2;
        private readonly int _timeout = 2000;

        public bool Enabled { get; private set; } = true;

        // ====== Constructor ======
        public AiEngine()
        {
            _http = new HttpClient
            {
                Timeout = TimeSpan.FromMilliseconds(_timeout)
            };

            _queue = new BlockingCollection<PacketInfo>(20000);
            _workers = new List<Task>();
            _cts = new CancellationTokenSource();
        }

        // ====== Start AI Dispatcher ======
        public void Start()
        {
            if (!Enabled) return;

            for (int i = 0; i < _workerCount; i++)
                _workers.Add(Task.Run(() => WorkerLoop(_cts.Token)));

            Console.WriteLine($"[AI] Started with {_workerCount} workers");
        }

        // ====== Stop AI Engine ======
        public void Stop()
        {
            try
            {
                _queue.CompleteAdding();
                _cts.Cancel();
                Task.WaitAll(_workers.ToArray(), 1500);
            }
            catch { }
        }

        // ====== Add packet to AI Queue ======
        public void Enqueue(PacketInfo packet)
        {
            if (!Enabled) return;

            if (!_queue.TryAdd(packet))
                Console.WriteLine("[AI] Queue full – dropping packet");
        }

        // ====== Worker Loop ======
        private async Task WorkerLoop(CancellationToken token)
        {
            foreach (var packet in _queue.GetConsumingEnumerable(token))
            {
                try
                {
                    var features = BuildFeatures(packet);
                    var response = await SendToModel(features);

                    if (response == null)
                    {
                        Console.WriteLine("[AI] Null response");
                        continue;
                    }

                    HandlePrediction(packet, response);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[AI Worker] " + ex.Message);
                }
            }
        }

        // ====== Build AI Features ======
        private Dictionary<string, object> BuildFeatures(PacketInfo p)
        {
            return new Dictionary<string, object>
            {
                ["srcIp"] = p.SrcIp,
                ["destIp"] = p.DestIp,
                ["packetSize"] = p.PacketSize,
                ["protocolName"] = p.ProtocolName,
                ["protocol"] = p.Protocol,
                ["srcPort"] = p.SrcPort,
                ["destPort"] = p.DestPort,
                ["payloadSize"] = p.PayloadSize,
                ["tcpFlag"] = p.TcpFlag,
                ["flowDirection"] = p.FlowDirection,
                ["packetCount"] = p.PacketCount,
                ["duration"] = p.Duration
            };
        }

        // ====== Send Request to AI Model ======
        private async Task<AiResponse?> SendToModel(Dictionary<string, object> data)
        {
            try
            {
                var res = await _http.PostAsJsonAsync(_apiUrl, data);
                if (!res.IsSuccessStatusCode)
                    return null;

                return await res.Content.ReadFromJsonAsync<AiResponse>();
            }
            catch
            {
                return null;
            }
        }

        // ====== Handle AI Result (Log + Alert) ======
        private void HandlePrediction(PacketInfo p, AiResponse res)
        {
            // log
            int logId = LogBLL.Insert(DateTime.Now, p.SrcIp, p.DestIp, (int)p.PacketSize, res.prediction == 1, p.ProtocolName, p.Protocol, p.SrcPort, p.DestPort, p.PayloadSize, p.TcpFlag, p.FlowDirection, p.PacketCount, p.Duration, null, $"AI Prediction: {res.prediction}, confidence={res.confidence}");
         
              

            // alert
            if (res.prediction == 1)
            {
                AlertBLL.Insert(logId, $"AI detected malicious traffic (conf={res.confidence})", "AI_Malicious", "High", p.SrcIp, p.DestIp, "", DateTime.Now,"New");
              
            }
        }

        public void Dispose()
        {
            Stop();
            _http.Dispose();
            _cts.Dispose();
        }
    }

    // ====== AI Model Response DTO ======
    public class AiResponse
    {
        public int prediction { get; set; }
        public double confidence { get; set; }
    }

    // ====== PacketInfo DTO (adjust to your structure) ======
    public class PacketInfo
    {
        public string SrcIp { get; set; }
        public string DestIp { get; set; }
        public double PacketSize { get; set; }
        public string ProtocolName { get; set; }
        public string Protocol { get; set; }
        public int SrcPort { get; set; }
        public int DestPort { get; set; }
        public double PayloadSize { get; set; }
        public string TcpFlag { get; set; }
        public string FlowDirection { get; set; }
        public int PacketCount { get; set; }
        public double Duration { get; set; }
    }
}