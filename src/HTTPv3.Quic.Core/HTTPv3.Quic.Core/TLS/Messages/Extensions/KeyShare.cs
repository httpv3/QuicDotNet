using System;
using System.Collections.Generic;
using System.Linq;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShare
    {
        public NamedGroup Group;
        public byte[] KeyExchange;

        public override bool Equals(object obj)
        {
            var k = obj as KeyShare;
            if (k == null) return false;

            return Group.Equals(k.Group) && KeyExchange.SequenceEqual(k.KeyExchange);
        }

        public override int GetHashCode()
        {
            return Group.GetHashCode() + KeyExchange.GetHashCode();
        }
    }

    internal static class KeyShareExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, out KeyShare namedGroup)
        {
            namedGroup = new KeyShare();

            var ret = bytesIn.Read(out namedGroup.Group)
                          .ReadNextTLSVariableLength(Length_NumBytes, out var keyData);

            namedGroup.KeyExchange = keyData.ToArray();

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<KeyShare> list)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out KeyShare ks);
                list.Add(ks);
            }

            return ret;
        }

        public static Span<byte> Write(this in Span<byte> buffer, KeyShare ks)
        {
            var ret = buffer.Write(ks.Group)
                            .WriteTLSVariableLength(Length_NumBytes, ks.KeyExchange);

            return ret;
        }

        public static Span<byte> Write(this in Span<byte> buffer, List<KeyShare> list)
        {
            return buffer.WriteVector(ArrayLength_NumBytes, (buf, state) =>
            {
                foreach (var item in list)
                {
                    buf = buf.Write(item);
                }
                state.EndLength = buf.Length;
            });
        }
    }
}
