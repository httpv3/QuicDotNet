using HTTPv3.Quic.Messages.Frames;
using HTTPv3.Quic.Security;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundPacket
    {
        public readonly EncryptionState KeySpace;

        public InboundEncryptedPacket EncryptedPacket;

        public ReadOnlyMemory<byte> Payload;
        public bool AckEliciting = false;
        public DateTime Processed;

        public InboundPacket(InboundEncryptedPacket packet, EncryptionKeys keys)
        {
            KeySpace = keys.KeySpace;

            EncryptedPacket = packet;

            Payload = keys.DecryptPayload(packet.UnprotectedHeader, packet.EncryptedPayload.Span, packet.PacketNum);
        }

        public IEnumerable<IFrame> AsFrames()
        {
            var cur = Payload;
            while (cur.Length > 0)
            {
                IFrame f = null;

                cur = cur.Read(out FrameType type);

                try
                {
                    switch (type)
                    {
                        case FrameType.Padding:
                            continue;
                        case FrameType.Ack:
                            cur = AckFrame.Parse(cur, out f);
                            break;
                        case FrameType.Crypto:
                            AckEliciting = true;
                            cur = CryptoFrame.Parse(cur, out f);
                            break;
                        default:
                            cur = default;
                            break;
                    }
                }
                catch
                {

                }

                if (f != null)
                    yield return f;
            }
        }
    }

    internal static class InboundPacketExtension
    {
        public static async IAsyncEnumerable<IFrame> AsFrames(this IAsyncEnumerable<InboundPacket> packets)
        {
            await foreach (var p in packets)
            {
                foreach (var f in p.AsFrames())
                    yield return f;
            }
        }
    }
}
