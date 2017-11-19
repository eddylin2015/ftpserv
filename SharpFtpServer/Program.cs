using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

namespace SharpFtpServer
{
    class Program
    {
        static void Main(string[] args)
        {
           Console.OutputEncoding = Encoding.UTF8;
           
            
            //IPAddress ip = IPAddress.Parse("192.168.102.135");
            //using (FtpServer server = new FtpServer(IPAddress.IPv6Any, 21))
            using (FtpServer server = new FtpServer())
            {
                server.Start();

                Console.WriteLine("Press any key to stop...");
                while (!Console.ReadLine().Equals("Q")) { }
            }
        }
    }
}
