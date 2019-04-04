using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class CryptoFrame
    {
        public CryptoFrame(ref Packet p)
        {
            int offset;
            int length;
            Span<byte> data;

            p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out offset)
                                             .ReadNextVariableInt(out length)
                                             .ReadNextBytes(length, out data);

            var handshake = Handshake.Parse(data);
        }
    }
}
