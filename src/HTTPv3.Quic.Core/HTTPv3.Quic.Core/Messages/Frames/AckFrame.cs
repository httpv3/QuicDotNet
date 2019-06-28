using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;
using System;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class AckFrame : IFrame
    {
        public ulong LargestAcknowledged;
        public ulong Delay;
        public int RangeCount;
        public ulong FirstRange;

        public AckFrame()
        {
        }

        public ushort GetSize()
        {
            ushort min = 3; //type + 1 range count + 1 ack range
            min += (ushort)VariableLengthInt.GetNumberOfBytesNeeded(LargestAcknowledged);
            min += (ushort)VariableLengthInt.GetNumberOfBytesNeeded(Delay);

            return min;
        }


        public static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> bytes, out IFrame frameOut)
        {
            AckFrame f = new AckFrame();
            frameOut = f;

            var cur = bytes.ReadNextVariableInt(out f.LargestAcknowledged)
                           .ReadNextVariableInt(out f.Delay)
                           .ReadNextVariableInt(out f.RangeCount)
                           .ReadNextVariableInt(out f.FirstRange);

            for (int i = 0; i < f.RangeCount; i++)
            {
                cur = cur.ReadNextVariableInt(out int gap)
                         .ReadNextVariableInt(out int range);
            }

            return cur;
        }

        public Span<byte> Write(Span<byte> buffer, bool isLastInPacket)
        {
            return buffer.Write(FrameType.Ack)
                         .WriteVarLengthInt(LargestAcknowledged)
                         .WriteVarLengthInt(Delay)
                         .WriteVarLengthInt(RangeCount)
                         .WriteVarLengthInt(FirstRange);
        }

        //public AckFrame(ref Packet p)
        //{
        //    p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out LargestAcknowledged)
        //                                     .ReadNextVariableInt(out Delay)
        //                                     .ReadNextVariableInt(out RangeCount)
        //                                     .ReadNextVariableInt(out FirstRange);

        //    for (ulong i = 0; i < RangeCount; i++)
        //    {
        //        p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out ulong nextNum);
        //    }
        //}
    }
}
