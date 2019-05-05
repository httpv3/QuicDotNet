using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShare
    {
        public const int ArrayLength_NumBytes = 2;
        public const int KeyShareLength_NumBytes = 2;

        public NamedGroup Group;
        public byte[] KeyExchange;

        public static List<KeyShare> ParseArray(ReadOnlySpan<byte> data)
        {
            List<KeyShare> ret = new List<KeyShare>();

            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                ret.Add(ParseOne(ref arrData));
            }

            return ret;
        }

        public static KeyShare ParseOne(ref ReadOnlySpan<byte> data)
        {
            KeyShare ret = new KeyShare();

            data = data.ReadNextNumber(SupportedGroups.NamedGroupLength_NumBytes, out var groupVal)
                       .ReadNextTLSVariableLength(KeyShareLength_NumBytes, out var keyData);

            if (Enum.IsDefined(typeof(NamedGroup), (ushort)groupVal))
                ret.Group = (NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)groupVal);

            ret.KeyExchange = keyData.ToArray();

            return ret;
        }
    }
}
