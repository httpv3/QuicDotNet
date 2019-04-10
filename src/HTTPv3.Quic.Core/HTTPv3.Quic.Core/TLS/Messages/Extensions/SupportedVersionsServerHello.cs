
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedVersionsServerHello : Extension
    {
        public const int SupportedVersionLength_NumBytes = 2;

        public ProtocolVersion Version = ProtocolVersion.NA;

        public SupportedVersionsServerHello(ReadOnlySpan<byte> data) : base(ExtensionType.SupportedVersions)
        {
            data = data.ReadNextNumber(SupportedVersionLength_NumBytes, out var val);

            if (Enum.IsDefined(typeof(ProtocolVersion), (ushort)val))
                Version = (ProtocolVersion)Enum.ToObject(typeof(ProtocolVersion), (ushort)val);
        }
    }
}
