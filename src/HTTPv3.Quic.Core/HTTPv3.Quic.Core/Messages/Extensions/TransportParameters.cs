using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.Messages.Extensions
{
    // IETF quic-transport draft-19
    // 18.1.  Transport Parameter Definitions
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-18.1
    internal class TransportParameters : Extension
    {
        public const int ArrayLength_NumBytes = 2;
        public const int SupportedVersionsArrayLength_NumBytes = 1;
        public const int NamedGroupLength_NumBytes = 2;
        public const int StatelessResetToken_NumBytes = 16;

        public VersionTypes InitialVersion;
        public VersionTypes NegotiatedVersion;
        public List<VersionTypes> SupportedVersions = new List<VersionTypes>();

        public ConnectionId OriginalConnectionId;

        public ulong IdleTimeoutMilliseconds;

        private byte[] statelessResetToken;
        public byte[] StatelessResetToken
        {
            get => statelessResetToken;
            set => statelessResetToken = (value == null || value.Length == StatelessResetToken_NumBytes) ? value : throw new ParsingException($"TransportParameters.StatelessResetToken: Must be {StatelessResetToken_NumBytes} bytes, but given {value.Length} bytes.");
        }

        private ulong maxPacketSize;
        public ulong MaxPacketSize
        {
            get => maxPacketSize;
            set => maxPacketSize = value < 1200 ? throw new ParsingException($"TransportParameters.MaxPacketSize: Must be atleast 1200, but given {value}.") :
                                   value > 65527 ? throw new ParsingException($"TransportParameters.MaxPacketSize: Max is 65527, but given {value}.") :
                                   value;
        }

        public ulong InitialMaxData;
        public ulong InitialMaxStreamDataBidiLocal;
        public ulong InitialMaxStreamDataBidiRemote;
        public ulong InitialMaxStreamDataUni;
        public ulong InitialMaxStreamsBidi;
        public ulong InitialMaxStreamsUni;

        private ulong ackDelayExponent = 3;
        public ulong AckDelayExponent
        {
            get => ackDelayExponent;
            set => ackDelayExponent = value > 20 ? throw new ParsingException($"TransportParameters.AckDelayExponent: Max is 20, but given {value}.") :
                                      value;
        }

        private ulong maxAckDelayMilliseconds = 25;
        public ulong MaxAckDelayMilliseconds
        {
            get => maxAckDelayMilliseconds;
            set => maxAckDelayMilliseconds = value > 0x3FFF ? throw new ParsingException($"TransportParameters.MaxAckDelayMilliseconds: Max is 2^14, but given {value}.") :
                                             value;
        }

        public bool DisableMigration = false;
        public PreferredAddress PreferredAddress;

        public TransportParameters(ReadOnlySpan<byte> data, HandshakeType handshakeType) : base(ExtensionType.QuicTransportParameters)
        {
            // Backwards compatibility for Version 18
            if (handshakeType == HandshakeType.ClientHello)
            {
                data = data.ReadNextBytes(4, out ReadOnlySpan<byte> versionBytes);
                InitialVersion = LongHeader.ParseVersionType(versionBytes);

            }
            else if (handshakeType == HandshakeType.EncryptedExtensions)
            {
                data = data.ReadNextBytes(4, out ReadOnlySpan<byte> negotiatedVersion)
                           .ReadNextTLSVariableLength(SupportedVersionsArrayLength_NumBytes, out var versionArrData);
                NegotiatedVersion = LongHeader.ParseVersionType(negotiatedVersion);

                while (!versionArrData.IsEmpty)
                {
                    versionArrData = versionArrData.ReadNextBytes(4, out ReadOnlySpan<byte> versionBytes);
                    SupportedVersions.Add(LongHeader.ParseVersionType(versionBytes));
                }
            }

            data = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);


            while (!arrData.IsEmpty)
            {
                ParseParameter(ref arrData);
            }
        }

        private void ParseParameter(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(Type_NumBytes, out uint typeInt)
                       .ReadNextTLSVariableLength(Length_NumBytes, out var extBytes);

            TransportParameterId type = (TransportParameterId)typeInt;

            switch (type)
            {
                case TransportParameterId.OriginalConnectionId:
                    OriginalConnectionId = !extBytes.IsEmpty ? new ConnectionId(extBytes.ToArray()) : throw new ParsingException("TransportParameters.OriginalConnectionId: Extension present, but no data inside.");
                    break;
                case TransportParameterId.IdleTimeout:
                    extBytes.ReadNextVariableInt(out IdleTimeoutMilliseconds);
                    break;
                case TransportParameterId.StatelessResetToken:
                    StatelessResetToken = !extBytes.IsEmpty ? extBytes.ToArray() : throw new ParsingException("TransportParameters.StatelessResetToken: Extension present, but no data inside.");
                    break;
                case TransportParameterId.MaxPacketSize:
                    extBytes.ReadNextVariableInt(out maxPacketSize);
                    break;
                case TransportParameterId.InitialMaxData:
                    extBytes.ReadNextVariableInt(out InitialMaxData);
                    break;
                case TransportParameterId.InitialMaxStreamDataBidiLocal:
                    extBytes.ReadNextVariableInt(out InitialMaxStreamDataBidiLocal);
                    break;
                case TransportParameterId.InitialMaxStreamDataBidiRemote:
                    extBytes.ReadNextVariableInt(out InitialMaxStreamDataBidiRemote);
                    break;
                case TransportParameterId.InitialMaxStreamDataUni:
                    extBytes.ReadNextVariableInt(out InitialMaxStreamDataUni);
                    break;
                case TransportParameterId.InitialMaxStreamsBidi:
                    extBytes.ReadNextVariableInt(out InitialMaxStreamsBidi);
                    break;
                case TransportParameterId.InitialMaxStreamsUni:
                    extBytes.ReadNextVariableInt(out InitialMaxStreamsUni);
                    break;
                case TransportParameterId.AckDelayExponent:
                    extBytes.ReadNextVariableInt(out ackDelayExponent);
                    break;
                case TransportParameterId.MaxAckDelay:
                    extBytes.ReadNextVariableInt(out maxAckDelayMilliseconds);
                    break;
                case TransportParameterId.DisableMigration:
                    DisableMigration = true;
                    break;
                case TransportParameterId.PreferredAddress:
                    PreferredAddress = new PreferredAddress(extBytes);
                    break;
                default:
                    break;
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
