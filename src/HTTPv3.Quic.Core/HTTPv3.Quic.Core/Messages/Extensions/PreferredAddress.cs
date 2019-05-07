using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Extensions
{
    // IETF quic-transport draft-19
    // 18.1.  Transport Parameter Definitions
    // Figure 16: Preferred Address format
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-18.1

    public struct PreferredAddress
    {
        public const int IPv4Address_NumBytes = 4;
        public const int IPv6Address_NumBytes = 16;
        public const int Port_NumBytes = 2;
        public const int ConnectionIdLength_NumBytes = 2;
        public const int StatelessResetToken_NumBytes = 16;

        byte[] IPv4Address;
        ushort IPv4Port;
        byte[] IPv6Address;
        ushort IPv6Port;
        ConnectionId ConnectionId;
        byte[] StatelessResetToken;

        public PreferredAddress(ReadOnlySpan<byte> bytes)
        {
            bytes.Read(IPv4Address_NumBytes, out IPv4Address)
                 .Read(Port_NumBytes, out ushort ipv4Port)
                 .Read(IPv6Address_NumBytes, out IPv6Address)
                 .Read(Port_NumBytes, out ushort ipv6Port)
                 .ReadNextTLSVariableLength(ConnectionIdLength_NumBytes, out var connBytes)
                 .Read(StatelessResetToken_NumBytes, out StatelessResetToken);

            IPv4Port = ipv4Port;
            IPv6Port = ipv6Port;
            ConnectionId = connBytes.Length == 0 ? null : new ConnectionId(connBytes.ToArray());
        }
    }
}
