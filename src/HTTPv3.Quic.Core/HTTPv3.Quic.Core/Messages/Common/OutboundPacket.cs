using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    abstract class OutboundPacket
    {
        protected Connection conn;
        protected ulong packetNumber;

        public OutboundPacket(Connection conn, ulong packetNumber)
        {
            this.conn = conn;
            this.packetNumber = packetNumber;
        }

        public abstract Span<byte> Write(in Span<byte> buffer);

        protected Span<byte> WritePNandPayload(in Span<byte> buffer, in ReadOnlySpan<byte> payload)
        {
            var pnLen = VariableLengthInt.GetNumberOfBytesNeeded(packetNumber);
            var len = pnLen + payload.Length;
            return buffer.WriteVarLengthInt(len)
                         .Write;
        }
    }
}
