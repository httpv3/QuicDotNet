using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class CryptoFrame : IFrame
    {
        public List<Handshake> HandshakeMessages = new List<Handshake>();

        public ulong Offset;
        public byte[] Data;

        private CryptoFrame()
        {
        }

        public CryptoFrame(in ulong offset, in byte[] data)
        {
            Offset = offset;
            Data = data;
        }

        public static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> bytes, out IFrame frameOut)
        {
            CryptoFrame f = new CryptoFrame();
            frameOut = f;

            var cur = bytes.ReadNextVariableInt(out f.Offset)
                           .ReadNextVariableInt(out int len)
                           .Read(len, out f.Data);

            return cur;
        }

        public Span<byte> Write(Span<byte> buffer, bool isLastInPacket)
        {
            return buffer.Write(FrameType.Crypto)
                         .WriteVarLengthInt(Offset)
                         .WriteVarLengthInt(Data.Length)
                         .Write(Data);
        }
    }
}
