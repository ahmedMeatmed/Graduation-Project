using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace IDSApp.Helper
{
    public class AiEngine : IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _apiUrl = "http://127.0.0.1:5000/predict";

        public AiEngine()
        {
            _http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(2)
            };
        }

        // ====== MAIN METHOD ======
        public async Task<AiResult?> PredictAsync(AiFeatures features)
        {
            try
            {
                var response = await _http.PostAsJsonAsync(_apiUrl, features);

                if (!response.IsSuccessStatusCode)
                    return null;

                return await response.Content.ReadFromJsonAsync<AiResult>();
            }
            catch
            {
                return null;
            }
        }

        public void Dispose()
        {
            _http.Dispose();
        }
    }

    // ====== INPUT FEATURES ======
    public class AiFeatures
{
    public int DstPort { get; set; }
    public int Protocol { get; set; }
    public double PacketSize { get; set; }
    public int PacketCount { get; set; }
    public double PayloadSize { get; set; }
    public int FlowDirection { get; set; }
    public int TcpFlags { get; set; }
}

public class AiResult
{
    public int prediction { get; set; }
    public double mse { get; set; }
    public double threshold { get; set; }
}
}
