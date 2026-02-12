using System;
using System.Threading;

namespace IDSApp
{
    internal class Program
    {
        private static bool _running = true;

        public static void Main()
        {
            Console.WriteLine("Starting IDS Core...");

            // Start IDS Core (your existing logic)
            var idsCore = new IDSCore();
            idsCore.Start();

            // Configure Redis routing for test
            IDSApp.DBL.DBL.RedisHost = "127.0.0.1";
            IDSApp.DBL.DBL.RedisPort = 6379;
            IDSApp.DBL.DBL.RedisDb = 0; // set to Laravel's DB index if needed
            IDSApp.DBL.DBL.RedisPassword = null; // set if your Redis requires password
            // IDSApp.DBL.DBL.RedisListKey = "aegis_database_ids_logs"; // match Laravel key

            Console.WriteLine("IDS Core started . Press any key to stop...");

            // Background thread to push sample logs to Redis
            // var logThread = new Thread(() =>
            // {
            //     int counter = 1;
            //     while (_running)
            //     {
            //         string logJson = $"{{\"timestamp\":\"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\",\"level\":\"INFO\",\"message\":\"Sample log {counter}\"}}";
            //         int result = IDSApp.DBL.DBL.PushLog(logJson);

            //         Console.WriteLine(result == 1
            //             ? $"Log {counter} pushed to Redis successfully."
            //             : $"Failed to push log {counter}.");

            //         counter++;
            //         Thread.Sleep(2000); // Push every 2 seconds
            //     }
            // });

            // logThread.IsBackground = true;
            // logThread.Start();

            // Wait for user input to stop
            Console.ReadKey();

            // Signal background thread to stop
            _running = false;

            // Stop IDS Core
            idsCore.Stop();

            Console.WriteLine("IDS Core stopped.");
        }
    }
}
