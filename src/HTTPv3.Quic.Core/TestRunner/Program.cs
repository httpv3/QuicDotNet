using HTTPv3.Quic;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TestRunner
{
    class Program
    {
        static void Main(string[] args)
        {
            Run().Wait();
        }
        async static Task Run()
        {
            QuicClient client = new QuicClient("quic.ogre.com", 4433);
            await client.Connect();

            //var res = await client.Request("index.html");
        }
    }
}
