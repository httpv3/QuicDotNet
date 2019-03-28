using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 17.2.  Long Header Packets
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.2
    internal ref struct Header
    {
        public const int HeaderFormOffset = 0;
        public const byte HeaderFormMask = 0x80;
        public const int FixedBitOffset = 0;
        public const byte FixedBitMask = 0x40;
        public const int PacketNumberLengthOffset = 0;
        public const int PacketNumberLengthMask = 0x3;

        public const int LongPacketTypeOffset = 0;
        public const byte LongPacketTypeMask = 0x30;
        public const short LongPacketTypeShift = 4;
        public const int TypeSpecificBitsOffset = 0;
        public const byte TypeSpecificBitsMask = 0x0F;

        public const int VersionOffset = 1;
        public const byte VersionLength = 4;

        public const int DCILOffset = 5;
        public const byte DCILMask = 0xF0;
        public const short DCILShift = 4;
        public const int SCILOffset = 5;
        public const byte SCILMask = 0x0F;

        public const int StartOfConnIDsOffset = 6;
    }
}
