using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedGroups : Extension
    {
        public const int ArrayLengthNumBytes = 2;
        public const int NamedGroupLengthNumBytes = 2;

        public List<NamedGroup> Groups = new List<NamedGroup>();

        public SupportedGroups(ReadOnlySpan<byte> data) : base(ExtensionType.SupportedGroups)
        {
            data.ReadNextTLSVariableLength(ArrayLengthNumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(NamedGroupLengthNumBytes, out var val);

                if (Enum.IsDefined(typeof(NamedGroup), (ushort)val))
                    Groups.Add((NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)val));
            }
        }
    }
}
