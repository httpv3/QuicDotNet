using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;
using System;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class StreamFrame : IFrame
    {
        public const ushort TYPE_DEFAULT = 0x08;
        public const byte OFF_BIT = 0x4;
        public const byte LEN_BIT = 0x2;
        public const byte FIN_BIT = 0x1;

        public ulong StreamId;
        public ulong Offset = 0;
        public ReadOnlyMemory<byte> Data;
        public bool LastFrame = false;

        private StreamFrame()
        {
        }

        public StreamFrame(in ulong streamId, in ulong offset, in ReadOnlyMemory<byte> data, bool lastFrame = false)
        {
            StreamId = streamId;
            Offset = offset;
            Data = data;
            LastFrame = lastFrame;
        }

        public static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> bytes, in byte type, out IFrame frameOut)
        {
            StreamFrame f = new StreamFrame()
            {
                LastFrame = (type & FIN_BIT) > 0
            };
            frameOut = f;

            var cur = bytes.ReadNextVariableInt(out f.StreamId);

            if ((type & OFF_BIT) > 0)
                cur = cur.ReadNextVariableInt(out f.Offset);

            if ((type & LEN_BIT) == 0)
            {
                f.Data = cur;
                return default;
            }

            return cur.ReadNextVariableInt(out int len)
                      .Read(len, out f.Data);
        }

        public Span<byte> Write(Span<byte> buffer, bool isLastInPacket)
        {
            var type = TYPE_DEFAULT | (Offset == 0 ? 0 : OFF_BIT) | (isLastInPacket ? 0 : LEN_BIT) | (LastFrame ? FIN_BIT : 0);

            var cur = buffer.Write((ushort)type).WriteVarLengthInt(StreamId);

            if (Offset > 0)
                cur = cur.WriteVarLengthInt(Offset);

            if (!isLastInPacket)
                cur = cur.WriteVarLengthInt(Data.Length);

            return cur.Write(Data.Span);
        }
    }
}
