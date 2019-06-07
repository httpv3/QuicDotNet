using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    abstract class OutboundPacket
    {
        public const ulong BYTE_MAX_1 = 0xFF;
        public const ulong BYTE_MAX_2 = 0xFFFF;
        public const ulong BYTE_MAX_3 = 0xFFFFFF;

        protected Connection conn;
        protected uint packetNumber;

        public OutboundPacket(Connection conn, uint packetNumber)
        {
            this.conn = conn;
            this.packetNumber = packetNumber;
        }

        protected int GetPacketNumberLength()
        {
            if (packetNumber <= BYTE_MAX_1) return 1;
            if (packetNumber <= BYTE_MAX_2) return 2;
            if (packetNumber <= BYTE_MAX_3) return 3;
            return 4;
        }
    }
}
