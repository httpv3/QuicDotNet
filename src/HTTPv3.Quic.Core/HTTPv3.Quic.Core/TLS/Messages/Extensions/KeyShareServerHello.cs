using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShareServerHello : Extension
    {
        public const int SignatureAlgorithmLength_NumBytes = 2;

        public KeyShare SharedKey;

        public KeyShareServerHello(ReadOnlySpan<byte> data) : base(ExtensionType.KeyShare)
        {
            SharedKey = new KeyShare(ref data);
        }
    }
}
