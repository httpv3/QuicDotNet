using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal static class ALPNExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int ALPNLength_NumBytes = 1;

        public static ReadOnlySpan<byte> ReadALPN(this in ReadOnlySpan<byte> bytesIn, out string alpn)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ALPNLength_NumBytes, out ReadOnlySpan<byte> bytes);

            alpn = Encoding.ASCII.GetString(bytes.ToArray());

            return ret;
        }

        public static ReadOnlySpan<byte> ReadALPN(this in ReadOnlySpan<byte> bytesIn, in List<string> list)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out ReadOnlySpan<byte> arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.ReadALPN(out string item);
                list.Add(item);
            }

            return ret;
        }

        public static Span<byte> WriteALPNSingle(this in Span<byte> buffer, string alpn)
        {
            return buffer.WriteTLSVariableLength(ALPNLength_NumBytes, Encoding.ASCII.GetBytes(alpn));
        }

        public static Span<byte> WriteALPNVector(this in Span<byte> buffer, List<string> list)
        {
            return buffer.WriteVector(ArrayLength_NumBytes, (buf, state) =>
            {
                foreach (var item in list)
                    buf = buf.WriteALPNSingle(item);

                state.EndLength = buf.Length;
            });
        }
    }
}
