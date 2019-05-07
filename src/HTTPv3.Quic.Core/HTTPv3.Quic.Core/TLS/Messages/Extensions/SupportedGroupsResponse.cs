using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedGroupsResponse
    {
        public NamedGroup Group;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            return data.Read(out Group);
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            return buffer.Write(ExtensionType.SupportedGroups)
                         .Write(NamedGroupExtensions.Length_NumBytes, Extension.Length_NumBytes)
                         .Write(Group);
        }
    }
}
