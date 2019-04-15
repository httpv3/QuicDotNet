﻿using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Frames
{
    internal class ConnectionCloseAppFrame
    {
        public const int ErrorCode_NumBytes = 2;

        public TransportErrorCodes ErrorCode;
        public string Reason;

        public ConnectionCloseAppFrame(ref Packet p)
        {
            p.PayloadCursor = p.PayloadCursor.ReadNextNumber(ErrorCode_NumBytes, out uint errorCodeNum)
                                             .ReadNextVariableInt(out int reasonLength)
                                             .ReadNextBytes(reasonLength, out byte[] reasonBytes);

            ErrorCode = ParseErrorCode((ushort)errorCodeNum);
            Reason = Encoding.UTF8.GetString(reasonBytes);
        }

        public static TransportErrorCodes ParseErrorCode(ushort errorCodeNum)
        {
            if (Enum.IsDefined(typeof(TransportErrorCodes), errorCodeNum))
                return (TransportErrorCodes)Enum.ToObject(typeof(TransportErrorCodes), errorCodeNum);

            if ((errorCodeNum & (ushort)TransportErrorCodes.CryptoError) == (ushort)TransportErrorCodes.CryptoError)
                return TransportErrorCodes.CryptoError;

            return TransportErrorCodes.Unknown;
        }
    }
}