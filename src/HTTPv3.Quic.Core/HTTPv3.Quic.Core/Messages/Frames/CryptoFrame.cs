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

        public static CryptoFrame Parse(ref ReadOnlySpan<byte> bytes)
        {
            CryptoFrame ret = new CryptoFrame();

            bytes = bytes.ReadNextVariableInt(out ret.Offset)
                         .ReadNextVariableInt(out int length)
                         .Read(length, out ret.Data);

            return ret;
        }

        public Span<byte> Write(Span<byte> buffer)
        {
            return buffer.Write(FrameType.Crypto)
                         .WriteVarLengthInt(Offset)
                         .WriteVarLengthInt(Data.Length)
                         .Write(Data);
        }
    }
}
