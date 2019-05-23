using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Extensions
{
    // IETF quic-transport draft-19
    // 18.1.  Transport Parameter Definitions
    // Figure 16: Preferred Address format
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-18.1

    public class PreferredAddress
    {
        public readonly static PreferredAddress Default = new PreferredAddress()
        {
            IPv4Address = new byte[] { 0, 0, 0, 0 },
            IPv6Address = new byte[] { 0, 0, 0, 0, 0, 0 },
            IPv4Port = 0,
            IPv6Port = 0,
            ConnectionId = ConnectionId.Empty,
            StatelessResetToken = new byte[0],
        };

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

        public PreferredAddress()
        {
        }

        public static PreferredAddress Parse(ReadOnlySpan<byte> bytes)
        {
            PreferredAddress ret = new PreferredAddress();

            bytes.Read(IPv4Address_NumBytes, out ret.IPv4Address)
                 .Read(Port_NumBytes, out ret.IPv4Port)
                 .Read(IPv6Address_NumBytes, out ret.IPv6Address)
                 .Read(Port_NumBytes, out ret.IPv6Port)
                 .ReadNextTLSVariableLength(ConnectionIdLength_NumBytes, out var connBytes)
                 .Read(StatelessResetToken_NumBytes, out ret.StatelessResetToken);

            ret.ConnectionId = connBytes.Length == 0 ? ConnectionId.Empty : new ConnectionId(connBytes.ToArray());
                
            return ret;
        }

        public Span<byte> Write(Span<byte> buffer)
        {
            return buffer.Write(IPv4Address)
                         .Write(IPv4Port)
                         .Write(IPv6Address)
                         .Write(IPv6Port)
                         .WriteTLSVariableLength(ConnectionIdLength_NumBytes, ConnectionId.ConnectionIdBytes)
                         .Write(StatelessResetToken);

        }
    }
}
