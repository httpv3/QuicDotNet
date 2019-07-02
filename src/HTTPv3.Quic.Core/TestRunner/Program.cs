using HTTPv3.Quic;
using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace TestRunner
{
    class Program
    {
        static KeystrokeStream stream1;
        static KeystrokeStream stream2;

        static async Task Main(string[] args)
        {
            //await KeyStrokeTest();
            await Run();
        }

        private static async Task KeyStrokeTest()
        {
            int a = 1, b = 1, c = 1, d = 1;
            stream1 = new KeystrokeStream();
            stream2 = new KeystrokeStream();
            var writer = KeyStrokeWriter();

            await Task.Yield();

            while (true)
            {
                var key = Console.ReadKey(true);
                switch (key.KeyChar)
                {
                    case 'a':
                        stream1.NewPacketProcessed("a", a++);
                        break;
                    case 'b':
                        stream1.NewPacketProcessed("b", b++);
                        break;
                    case 'c':
                        stream2.NewPacketProcessed("c", c++);
                        break;
                    case 'd':
                        stream2.NewPacketProcessed("d", d++);
                        break;
                    case 'q':
                        return;
                    default:
                        break;
                }
            }
        }

        private static KeystrokeStream[] streams;
        private static IAsyncEnumerable<KeystrokeStream> Streams => streams.Select(s => s.WaitBytesAvailable()).Combine();

        private static async Task KeyStrokeWriter()
        {
            streams = new[] { stream1, stream2 };
            await foreach(var stream in Streams)
            {
                var data = await stream.GetFrame();
                Console.WriteLine($"{data.Letter}: {data.Number}");
                await Task.Delay(1000);
            }
            Console.WriteLine("Done Writing!");
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
