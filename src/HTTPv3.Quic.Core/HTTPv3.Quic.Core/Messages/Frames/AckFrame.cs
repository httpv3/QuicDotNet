using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class AckFrame
    {
        public ulong LargestAcknowledged;
        public ulong Delay;
        public ulong RangeCount;
        public ulong FirstRange;

        public AckFrame(ref Packet p)
        {
            p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out LargestAcknowledged)
                                             .ReadNextVariableInt(out Delay)
                                             .ReadNextVariableInt(out RangeCount)
                                             .ReadNextVariableInt(out FirstRange);

            for (ulong i = 0; i < RangeCount; i++)
            {
                p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out ulong nextNum);
            }
        }
    }
}
