using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.Messages.Frames
{
    public class CryptoFrame : IFrame
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

        public static (ushort min, ushort max) GetSize(ulong offset, ulong dataLen)
        {
            ushort min = 4; //type + 1 length + 1 data
            min += (ushort)VariableLengthInt.GetNumberOfBytesNeeded(offset);

            if (dataLen > IFrame.MAX_SIZE)
                return (min, IFrame.MAX_SIZE);

            ushort max = 2;
            max += (ushort)VariableLengthInt.GetNumberOfBytesNeeded(offset);
            max += (ushort)VariableLengthInt.GetNumberOfBytesNeeded(dataLen);
            max += (ushort)dataLen;

            if (max > IFrame.MAX_SIZE)
                return (min, IFrame.MAX_SIZE);

            return (min, max);
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

        public Memory<byte> Write(Memory<byte> buffer, bool isLastInPacket)
        {
            var ret = Write(buffer, isLastInPacket);
            return buffer.Slice(buffer.Length - ret.Length);
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
