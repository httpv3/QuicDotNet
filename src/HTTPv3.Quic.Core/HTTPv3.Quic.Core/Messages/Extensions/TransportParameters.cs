using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace HTTPv3.Quic.Messages.Extensions
{
    // IETF quic-transport draft-19
    // 18.1.  Transport Parameter Definitions
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-18.1
    internal class TransportParameters
    {
        public const int Type_NumBytes = 2;
        public const int ArrayLength_NumBytes = 2;
        public const int SupportedVersionsArrayLength_NumBytes = 1;
        public const int NamedGroupLength_NumBytes = 2;
        public const int StatelessResetToken_NumBytes = 16;

        public static readonly TransportParameters Default = new TransportParameters();

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

        public TransportParameters()
        {

        }

        public static TransportParameters Parse(ReadOnlySpan<byte> data, HandshakeType handshakeType)
        {
            TransportParameters ret = new TransportParameters();

            data = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);


            while (!arrData.IsEmpty)
            {
                ret.ParseParameter(ref arrData);
            }

            return ret;
        }

        private void ParseParameter(ref ReadOnlySpan<byte> data)
        {
            data = data.Read(Extension.Type_NumBytes, out ushort typeInt)
                       .ReadNextTLSVariableLength(Extension.Length_NumBytes, out var extBytes);

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

        public Span<byte> Write(Span<byte> buffer)
        {
            return buffer.WriteVector(ArrayLength_NumBytes, (buf, state) =>
            {
                if (OriginalConnectionId != null)
                    buf = buf.WriteParameterValue(TransportParameterId.OriginalConnectionId, OriginalConnectionId.ConnectionIdBytes);

                buf = buf.WriteParameterValue(TransportParameterId.IdleTimeout, IdleTimeoutMilliseconds);

                if (StatelessResetToken != null)
                    buf = buf.WriteParameterValue(TransportParameterId.StatelessResetToken, StatelessResetToken);

                if (MaxPacketSize != 0)
                    buf = buf.WriteParameterValue(TransportParameterId.MaxPacketSize, MaxPacketSize);

                buf = buf.WriteParameterValue(TransportParameterId.InitialMaxData, InitialMaxData);
                buf = buf.WriteParameterValue(TransportParameterId.InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiLocal);
                buf = buf.WriteParameterValue(TransportParameterId.InitialMaxStreamDataBidiRemote, InitialMaxStreamDataBidiRemote);
                buf = buf.WriteParameterValue(TransportParameterId.InitialMaxStreamDataUni, InitialMaxStreamDataUni);
                buf = buf.WriteParameterValue(TransportParameterId.InitialMaxStreamsBidi, InitialMaxStreamsBidi);
                buf = buf.WriteParameterValue(TransportParameterId.InitialMaxStreamsUni, InitialMaxStreamsUni);
                buf = buf.WriteParameterValue(TransportParameterId.AckDelayExponent, AckDelayExponent);
                buf = buf.WriteParameterValue(TransportParameterId.MaxAckDelay, MaxAckDelayMilliseconds);

                if (DisableMigration)
                    buf = buf.WriteParameterValue(TransportParameterId.DisableMigration, (x,y) => { });

                buf = buf.WriteParameterValue(TransportParameterId.PreferredAddress, (buf, state) =>
                            {
                                buf = PreferredAddress.Write(buf);
                                state.EndLength = buf.Length;
                            });

                state.EndLength = buf.Length;
            });
        }
    }
}
