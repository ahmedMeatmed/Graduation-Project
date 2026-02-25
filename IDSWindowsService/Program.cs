using IDSWindowsService;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService() // <-- مهم جدًا
    .ConfigureServices((hostContext, services) =>
    {
        services.AddHostedService<Worker>();
    })
    .Build();

await builder.RunAsync();