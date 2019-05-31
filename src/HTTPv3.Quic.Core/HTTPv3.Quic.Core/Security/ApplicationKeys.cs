using HTTPv3.Quic.TLS.Messages.Extensions;
using System;

namespace HTTPv3.Quic.Security
{
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal class ApplicationKeys : EncryptionKeys
    {
        public ApplicationKeys(in byte[] encSecret, in byte[] decSecret, CipherSuite cipherSuite) : base(encSecret, decSecret, cipherSuite)
        {
        }
    }
}
