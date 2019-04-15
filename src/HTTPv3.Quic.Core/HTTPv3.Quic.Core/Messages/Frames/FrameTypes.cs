using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    public class FrameTypes
    {
        public static FrameType Parse(byte value)
        {
            if (Enum.IsDefined(typeof(FrameType), value))
                return (FrameType)Enum.ToObject(typeof(FrameType), value);

            return FrameType.Unknown;

        }
    }

    public enum FrameType : byte
    {
        Padding = 0x00,
        Ping = 0x01,
        Ack = 0x02,
        AckECN = 0x03,
        ResetStream = 0x04,
        StopSending = 0x05,
        Crypto = 0x06,
        NewToken = 0x07,
        MaxData = 0x10,
        MaxStreamData = 0x11,
        MaxStreamsBiDi = 0x12,
        MaxStreamsUniDi = 0x13,
        DataBlocked = 0x14,
        StreamDataBlocked = 0x15,
        StreamsBlockedBiDi = 0x16,
        StreamsBlockedUniDi = 0x17,
        NewConnectionId = 0x18,
        RetireConnectionId = 0x19,
        PathChallenge = 0x1a,
        PathResponse = 0x1b,
        ConnectionCloseQuic = 0x1c,
        ConnectionCloseApplication = 0x1d,

        Unknown = 0xFF,
    }
}
