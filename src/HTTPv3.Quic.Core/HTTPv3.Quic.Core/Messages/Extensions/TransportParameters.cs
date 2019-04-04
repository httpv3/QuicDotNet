using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Extensions
{
    // IETF quic-transport draft-19
    // 18.1.  Transport Parameter Definitions
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-18.1
    internal class TransportParameters : Extension
    {
        public const int ArrayLengthNumBytes = 2;
        public const int NamedGroupLengthNumBytes = 2;

        public VersionTypes InitialVersion;
        public List<TransportParameter> Parameters = new List<TransportParameter>();

        public ConnectionId OriginalConnectionId;
        public ulong IdleTimeoutMilliseconds;
        public byte[] StatelessResetToken { get; set; }

        public TransportParameters(ReadOnlySpan<byte> data) : base(ExtensionType.QuicTransportParameters)
        {
            data = data.ReadNextBytes(4, out ReadOnlySpan<byte> versionBytes)
                       .ReadNextTLSVariableLength(ArrayLengthNumBytes, out var arrData);

            InitialVersion = LongHeader.ParseVersionType(versionBytes);

            while (!arrData.IsEmpty)
            {
                Parameters.Add(TransportParameter.Parse(ref arrData));
            }
        }
    }
}
