﻿using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Messages.Frames;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class InitialProcessor
    {
        Connection conn;
        bool receivedFirstPacket = false;

        public InitialProcessor(Connection conn)
        {
            this.conn = conn;
        }

        public async Task Process(InboundPacket packet)
        {
            if (!receivedFirstPacket)
            {
                receivedFirstPacket = true;
                conn.ServerConnectionId = new ServerConnectionId(((InboundEncryptedLongPacket)packet.EncryptedPacket).SrcId.ToArray());
            }

            foreach (var frame in packet.AsFrames())
                await Process(frame);

            conn.InitialAckStream.NewPacketProcessed(packet.EncryptedPacket.PacketNum, packet.EncryptedPacket.InboundDatagram.Recieved);
        }

        public async Task Process(IFrame frame)
        {
            if (frame is CryptoFrame)
            {
                await conn.InitialCryptoStream.AddFrame(frame as CryptoFrame);
                return;
            }
        }
    }
}
