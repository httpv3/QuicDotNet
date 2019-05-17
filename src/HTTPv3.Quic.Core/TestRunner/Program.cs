using HTTPv3.Quic;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TestRunner
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await Run();
        }
        async static Task Run()
        {
            QuicClient client = new QuicClient("quic.ogre.com", 4433);
            await client.Connect();

            //var res = await client.Request("index.html");
        }
    }
}
