using System;

namespace HTTPv3.Quic.Messages.Frames
{
    public interface IFrame
    {
        public const ushort MAX_SIZE = 1200;

        Span<byte> Write(Span<byte> buffer, bool isLastInPacket);

        public Memory<byte> Write(Memory<byte> buffer, bool isLastInPacket)
        {
            var ret = Write(buffer.Span, isLastInPacket);
            return buffer.Slice(buffer.Length - ret.Length);
        }
    }
}
