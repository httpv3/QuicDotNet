using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal interface IFrame
    {
        Span<byte> Write(Span<byte> buffer, bool isLastInPacket);
    }
}
