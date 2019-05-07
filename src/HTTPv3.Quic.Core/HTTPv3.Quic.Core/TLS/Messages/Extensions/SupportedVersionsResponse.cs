
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedVersionsResponse
    {
        public ProtocolVersion Version = ProtocolVersion.NA;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            return data.Read(out Version);
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            return buffer.Write(ExtensionType.SupportedVersions)
                         .Write(ProtocolVersionExtensions.Length_NumBytes, Extension.Length_NumBytes)
                         .Write(Version);
        }
    }
}
