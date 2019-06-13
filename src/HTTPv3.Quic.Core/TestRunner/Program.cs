using HTTPv3.Quic;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TestRunner
{
    class Program
    {
        static AwaitableQueue<char> q = new AwaitableQueue<char>();

        static async Task Main(string[] args)
        {
            await Run();
        }

        private static async Task EchoTest()
        {
            await foreach (var c in q)
            {
                Console.Write(c);
            }
        }

        async static Task Run()
        {
            QuicClient client = new QuicClient("http3-test.litespeedtech.com", 4433);
            await client.Connect();

            await Task.Delay(100000000);

            //var res = await client.Request("index.html");
        }
    }
}
