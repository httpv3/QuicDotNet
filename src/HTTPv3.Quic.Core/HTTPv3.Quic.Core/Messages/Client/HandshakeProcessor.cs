﻿using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Messages.Frames;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class HandshakeProcessor
    {
        Connection conn;

        public HandshakeProcessor(Connection conn)
        {
            this.conn = conn;
        }

        public async Task Process(InboundPacket packet)
        {
            foreach (var frame in packet.AsFrames())
                await Process(frame);
        }

        public async Task Process(IFrame frame)
        {
            if (frame is CryptoFrame)
            {
                await conn.HandshakeStream.AddFrame(frame as CryptoFrame);
                return;
            }
        }
    }
}
