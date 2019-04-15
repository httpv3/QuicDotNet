using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class CryptoFrame
    {
        List<Handshake> HandshakeMessages = new List<Handshake>();

        public CryptoFrame(ref Packet p)
        {
            p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out int offset)
                                             .ReadNextVariableInt(out int length)
                                             .ReadNextBytes(length, out ReadOnlySpan<byte> data);

            while (!data.IsEmpty)
            {
                HandshakeMessages.Add(Handshake.Parse(ref data));
            }
        }
    }
}
