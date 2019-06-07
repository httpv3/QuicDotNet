using HTTPv3.Quic.TLS;
using System.Linq;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class Sender
    {
        UdpClient udpClient;
        Connection conn;

        public Sender(UdpClient udpClient, Connection conn)
        {
            this.udpClient = udpClient;
            this.conn = conn;
        }

        public async Task Run()
        {
            await foreach (var stream in CryptoStreams)
            {

            }
        }

        private IAsyncEnumerable<(CryptoStream, long)> CryptoStreams => conn.InitialStream.GetNumBytesAvailable().Union(
                                                                            conn.HandshakeStream.GetNumBytesAvailable(),
                                                                            conn.ApplicationStream.GetNumBytesAvailable()
                                                                        );
    }
}
