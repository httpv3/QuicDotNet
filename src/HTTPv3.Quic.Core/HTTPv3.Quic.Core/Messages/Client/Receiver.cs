using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class Receiver
    {
        UdpClient udpClient;
        Connection conn;

        InitialProcessor initial;
        HandshakeProcessor handshake;
        ApplicationProcessor application;

        public Receiver(UdpClient udpClient, Connection conn)
        {
            this.udpClient = udpClient;
            this.conn = conn;

            initial = new InitialProcessor(conn);
            handshake = new HandshakeProcessor(conn);
            application = new ApplicationProcessor(conn);
        }

        public async Task Run()
        {
            await foreach (var packet in GetPackets())
            {
                switch (packet.KeySpace)
                {
                    case EncryptionState.Initial:
                        await initial.Process(packet);
                        break;
                    case EncryptionState.Handshake:
                        await handshake.Process(packet);
                        break;
                    case EncryptionState.Application:
                        //await application.Process(packet);
                        break;
                }

                packet.EncryptedPacket.Processed = DateTime.UtcNow;

                //Add packet to ACKHandler
            }
        }

        internal async IAsyncEnumerable<InboundDatagram> GetDatagrams()
        {
            while (!conn.Cancel.IsCancellationRequested)
            {
                UdpReceiveResult res;

                try
                {
                    res = await udpClient.ReceiveAsync(conn.Cancel);
                }
                catch
                {
                    yield break;
                }

                if (res.Buffer != null )
                    yield return new InboundDatagram(res.Buffer);
            }
        }

        public IAsyncEnumerable<InboundPacket> GetPackets()
        {
            return GetDatagrams().AsPackets().AsDecrypted(conn.KeyManager);
        }
    }
}
