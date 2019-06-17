using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class NewConnectionIdFrame
    {
        public const int ResetToken_NumBytes = 16;

        public ConnectionId Id;
        public ulong Sequence;
        public byte[] ResetToken;

        //public NewConnectionIdFrame(ref Packet p)
        //{
        //    p.PayloadCursor = p.PayloadCursor.ReadNextVariableInt(out Sequence)
        //                                     .Read(out byte length)
        //                                     .Read(length, out byte[] idBytes)
        //                                     .Read(ResetToken_NumBytes, out ResetToken);

        //    Id = new ConnectionId(idBytes);
        //}
    }
}
