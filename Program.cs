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

            Console.WriteLine("IDS Core started . Press any key to stop...");

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
