using IDSApp.Helper;
using System;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace IDSApp
{
    internal class Program
    {
        public static void Main()
        {
            Console.WriteLine("Starting IDS Core...");

            var idsCore = new IDSCore();
            idsCore.Start();
            Console.WriteLine("IDS Core started. Press any key to stop...");
            Console.ReadKey();

            // Stop IDS Core (this will stop the packet capture)
            idsCore.Stop();

            Console.WriteLine("IDS Core stopped.");
        }
    }
   
}
