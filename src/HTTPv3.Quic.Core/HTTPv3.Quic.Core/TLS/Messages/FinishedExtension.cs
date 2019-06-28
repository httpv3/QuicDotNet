using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    internal class FinishedExtension : Handshake
    {
        public byte[] VerifyData;

        public FinishedExtension() : base(HandshakeType.Finished)
        {
        }

        public static FinishedExtension Parse(ReadOnlySpan<byte> data)
        {
            FinishedExtension ret = new FinishedExtension();

            ret.VerifyData = data.ToArray();

            return ret;
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            return buffer.Write((byte)HandshakeType.Finished)
                         .WriteVector(Handshake.Length_NumBytes, (buf, state) =>
                         {
                             buf = buf.Write(VerifyData);
                             state.EndLength = buf.Length;
                         });
        }
    }
}
