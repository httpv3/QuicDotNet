using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    abstract class OutboundInitialPacket : OutboundLongPacket
    {
        public ReadOnlyMemory<byte> Payload;
        public byte[] Token;

        public OutboundInitialPacket(Connection conn, ulong packetNumber, ReadOnlyMemory<byte> payload, byte[] token = null) : base(conn)
        {
            Payload = payload;
            Token = token;
        }

        public override Span<byte> Write(in Span<byte> buffer)
        {
            var cur = buffer;
            cur = base.Write(cur);

            cur = cur.WriteVarLengthInt(Token.Length)
                     .Write(Token);

            return cur;
        }
    }
}
