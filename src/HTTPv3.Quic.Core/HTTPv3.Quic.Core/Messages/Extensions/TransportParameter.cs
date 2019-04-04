using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Extensions
{
    internal abstract class TransportParameter
    {
        public const int TypeNumBytes = 2;
        public const int LengthNumBytes = 2;

        public TransportParameterId TransportParameterType;

        public TransportParameter(TransportParameterId transportParameterType)
        {
            TransportParameterType = transportParameterType;
        }

        public static TransportParameter Parse(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(TypeNumBytes, out uint typeInt)
                       .ReadNextTLSVariableLength(LengthNumBytes, out var extBytes);

            TransportParameterId type = (TransportParameterId)typeInt;

            switch (type)
            {
                case TransportParameterId.IdleTimeout:
                case TransportParameterId.InitialMaxData:
                case TransportParameterId.MaxPacketSize:
                    return new TransportParameterNumber(type, extBytes);
                default:
                    return null;
            }
        }
    }

    internal enum TransportParameterId : ushort
    {
        OriginalConnectionId = 0,
        IdleTimeout = 1,
        StatelessResetToken = 2,
        MaxPacketSize = 3,
        InitialMaxData = 4,
        InitialMaxStreamDataBidiLocal = 5,
        InitialMaxStreamDataBidiRemote = 6,
        InitialMaxStreamDataUni = 7,
        InitialMaxStreamsBidi = 8,
        InitialMaxStreamsUni = 9,
        AckDelayExponent = 10,
        MaxAckDelay = 11,
        DisableMigration = 12,
        PreferredAddress = 13,
    }
}
