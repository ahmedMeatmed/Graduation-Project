using IDSApp; // ضيف namespace بتاع مشروع الـ IDS Core
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace IDSWindowsService
{
    public class Worker : BackgroundService
    {
        IDSCore idsCore = new IDSCore();
        private readonly ILogger<Worker> _logger;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        // لما الخدمة تبدأ
        public override Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Service starting at: {time}", DateTimeOffset.Now);
            idsCore.Start(); // هنا بنبدأ IDS
            return base.StartAsync(cancellationToken);
        }

        // لما الخدمة تتوقف
        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Service stopping at: {time}", DateTimeOffset.Now);
            idsCore.Stop(); // هنا بنوقف IDS
            return base.StopAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // loop خفيف يراقب الـ cancellationToken فقط
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }
        }
    }
}