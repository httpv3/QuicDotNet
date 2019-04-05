using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedGroups : Extension
    {
        public const int ArrayLength_NumBytes = 2;
        public const int NamedGroupLength_NumBytes = 2;

        public List<NamedGroup> Groups = new List<NamedGroup>();

        public SupportedGroups(ReadOnlySpan<byte> data) : base(ExtensionType.SupportedGroups)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(NamedGroupLength_NumBytes, out var val);

                if (Enum.IsDefined(typeof(NamedGroup), (ushort)val))
                    Groups.Add((NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)val));
            }
        }
    }
}
