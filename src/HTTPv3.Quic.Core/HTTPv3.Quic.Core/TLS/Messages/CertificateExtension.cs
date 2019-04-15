using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    // The Transport Layer Security (TLS) Protocol Version 1.3
    // 4.1.3.  Server Hello
    // https://tools.ietf.org/html/rfc8446#section-4.1.3
    internal class CertificateExtension : Handshake
    {
        public CertificateExtension(ReadOnlySpan<byte> data) : base(HandshakeType.Certificate)
        {
        }
    }
}
