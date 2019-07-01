using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Messages.Frames;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class ApplicationProcessor
    {
        Connection conn;

        public ApplicationProcessor(Connection conn)
        {
            this.conn = conn;
        }

        public async Task Process(InboundPacket packet)
        {
            foreach (var frame in packet.AsFrames())
                await Process(frame);

            conn.ApplicationAckStream.NewPacketProcessed(packet.EncryptedPacket.PacketNum, packet.EncryptedPacket.InboundDatagram.Recieved);
        }

        public async Task Process(IFrame frame)
        {
            if (frame is CryptoFrame)
            {
                await conn.ApplicationCryptoStream.AddFrame(frame as CryptoFrame);
                return;
            }
        }
    }
}
