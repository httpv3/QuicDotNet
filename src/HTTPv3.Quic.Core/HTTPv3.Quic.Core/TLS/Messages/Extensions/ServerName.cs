using System;
using System.Collections.Generic;
using System.Text;
using HTTPv3.Quic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal static class ServerNameExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int NameLength_NumBytes = 2;
        public const byte HostNameType = 0;

        public static ReadOnlySpan<byte> ReadServerNameSingle(this in ReadOnlySpan<byte> bytesIn, out string hostName)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(NameLength_NumBytes, out ReadOnlySpan<byte> bytes);

            hostName = Encoding.ASCII.GetString(bytes.ToArray());

            return ret;
        }

        public static ReadOnlySpan<byte> ReadServerNameVector(this in ReadOnlySpan<byte> bytesIn, out string hostName)
        {
            hostName = "";

            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out ReadOnlySpan<byte> arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out byte type)
                                 .ReadNextTLSVariableLength(NameLength_NumBytes, out ReadOnlySpan<byte> name);

                if (type == HostNameType)
                    hostName = Encoding.ASCII.GetString(name.ToArray());
            }

            return ret;
        }

        public static Span<byte> WriteServerNameSingle(this in Span<byte> buffer, string hostName)
        {
            return buffer.WriteTLSVariableLength(NameLength_NumBytes, Encoding.ASCII.GetBytes(hostName));
        }

        public static Span<byte> WriteServerNameVector(this in Span<byte> buffer, string hostName)
        {
            var bytes = Encoding.ASCII.GetBytes(hostName);
            var len = bytes.Length;

            return buffer.Write(len + 1 + NameLength_NumBytes, ArrayLength_NumBytes)
                         .Write(HostNameType, 1)
                         .WriteTLSVariableLength(NameLength_NumBytes, bytes);
        }
    }
}
