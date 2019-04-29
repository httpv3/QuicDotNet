using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 17.2.  Long Header Packets
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.2
    internal class Header
    {
        public const int HeaderForm_Offset = 0;
        public const byte HeaderForm_Mask = 0x80;
        public const int FixedBit_Offset = 0;
        public const byte FixedBit_Mask = 0x40;
        public const int PacketNumberLength_Offset = 0;
        public const int PacketNumberLength_Mask = 0x3;

        public const int LongPacketType_Offset = 0;
        public const byte LongPacketType_Mask = 0x30;
        public const short LongPacketType_Shift = 4;
        public const int TypeSpecificBits_Offset = 0;
        public const byte TypeSpecificBits_Mask = 0x0F;

        public const int KeyPhase_Offset = 0;
        public const byte KeyPhase_Mask = 0x04;

        public const int Version_Offset = 1;
        public const byte Version_Length = 4;

        public const int DCIL_Offset = 5;
        public const byte DCIL_Mask = 0xF0;
        public const short DCIL_Shift = 4;
        public const int SCIL_Offset = 5;
        public const byte SCIL_Mask = 0x0F;

        public const int StartOfConnIDs_Offset = 6;

        public static bool IsLongHeader(ref Packet packet)
        {
            return (packet.Bytes[HeaderForm_Offset] & HeaderForm_Mask) > 0;
        }
    }
}
