using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class ConnectionCloseQuicFrame
    {
        public const int ErrorCode_NumBytes = 2;

        public TransportErrorCodes ErrorCode;
        public FrameType FrameType;
        public string Reason;

        public ConnectionCloseQuicFrame(ref Packet p)
        {
            p.PayloadCursor = p.PayloadCursor.ReadNextNumber(ErrorCode_NumBytes, out uint errorCodeNum)
                                             .ReadNextVariableInt(out ulong frameType)
                                             .ReadNextVariableInt(out int reasonLength)
                                             .ReadNextBytes(reasonLength, out byte[] reasonBytes);

            ErrorCode = ConnectionCloseAppFrame.ParseErrorCode((ushort)errorCodeNum);
            FrameType = FrameTypes.Parse((byte)frameType);
            Reason = Encoding.UTF8.GetString(reasonBytes);
        }
    }
}
