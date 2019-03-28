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
            UdpClient client = new UdpClient("quic.ogre.com", 4433);

            byte[] hello = new byte[] { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o' };
            await client.SendAsync(hello, 5);
            var res = await client.ReceiveAsync();
        }
    }
}
