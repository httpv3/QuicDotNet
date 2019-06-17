using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 17.2.  Long Header Packets - Table 5: Long Header Packet Types
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.2
    internal enum LongHeaderPacketTypes : byte
    {
        Initial = 0x0,
        ZeroRTT = 0x1,
        Handshake = 0x2,
        Retry = 0x3,
    }
}
