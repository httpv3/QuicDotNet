using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Common;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class ConnectionCloseQuicFrame
    {
        public const int ErrorCode_NumBytes = 2;

        public TransportErrorCodes ErrorCode;
        public FrameType FrameType;
        public string Reason;

        //public ConnectionCloseQuicFrame(ref Packet p)
        //{
        //    p.PayloadCursor = p.PayloadCursor.Read(ErrorCode_NumBytes, out ushort errorCodeNum)
        //                                     .Read(out FrameType)
        //                                     .ReadNextVariableInt(out int reasonLength)
        //                                     .Read(reasonLength, out byte[] reasonBytes);

        //    ErrorCode = ConnectionCloseAppFrame.ParseErrorCode(errorCodeNum);
        //    Reason = Encoding.UTF8.GetString(reasonBytes);
        //}
    }
}
