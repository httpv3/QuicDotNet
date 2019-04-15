using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class NewConnectionIdFrame
    {
        public const int ResetToken_NumBytes = 16;

        public ConnectionId Id;
        public ulong Sequence;
        public byte[] ResetToken;

        public NewConnectionIdFrame(ref Packet p)
        {
            p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out Sequence)
                                             .ReadNextByte(out byte length)
                                             .ReadNextBytes(length, out byte[] idBytes)
                                             .ReadNextBytes(ResetToken_NumBytes, out ResetToken);

            Id = new ConnectionId(idBytes);
        }
    }
}
