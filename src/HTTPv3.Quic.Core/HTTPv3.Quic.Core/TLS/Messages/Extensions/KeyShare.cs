using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShare
    {
        public const int KeyShareLengthNumBytes = 2;

        public NamedGroup Group;
        public byte[] KeyExchange;

        public KeyShare(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(SupportedGroups.NamedGroupLengthNumBytes, out var groupVal)
                       .ReadNextTLSVariableLength(KeyShareLengthNumBytes, out var keyData);

            if (Enum.IsDefined(typeof(NamedGroup), (ushort)groupVal))
                Group = (NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)groupVal);

            KeyExchange = keyData.ToArray();
        }
    }
}
