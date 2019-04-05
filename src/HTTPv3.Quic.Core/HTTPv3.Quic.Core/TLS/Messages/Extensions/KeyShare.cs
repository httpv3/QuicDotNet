using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShare
    {
        public const int KeyShareLength_NumBytes = 2;

        public NamedGroup Group;
        public byte[] KeyExchange;

        public KeyShare(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(SupportedGroups.NamedGroupLength_NumBytes, out var groupVal)
                       .ReadNextTLSVariableLength(KeyShareLength_NumBytes, out var keyData);

            if (Enum.IsDefined(typeof(NamedGroup), (ushort)groupVal))
                Group = (NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)groupVal);

            KeyExchange = keyData.ToArray();
        }
    }
}
