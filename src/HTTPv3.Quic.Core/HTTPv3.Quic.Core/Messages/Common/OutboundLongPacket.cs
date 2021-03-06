﻿using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    abstract class OutboundLongPacket : OutboundPacket
    {
        public const VersionType CURRENT_VERSION = VersionType.Draft_20;

        public OutboundLongPacket(Connection conn, uint packetNumber) : base(conn, packetNumber) { }

        protected Span<byte> Write(in Span<byte> buffer)
        {
            var cur = buffer.Write(CURRENT_VERSION)
                            .Write((byte)((conn.OtherConnectionId.LengthByte << Header.DCIL_Shift) | conn.MyConnectionId.LengthByte));
            cur = conn.OtherConnectionId.Write(cur);
            cur = conn.MyConnectionId.Write(cur);

            return cur;
        }
    }
}
