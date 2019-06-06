using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;

namespace HTTPv3.Quic.Security
{
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal class HandshakeKeys : EncryptionKeys
    {
        public HandshakeKeys(in byte[] encSecret, in byte[] decSecret, CipherSuite cipherSuite) : base(EncryptionState.Handshake, encSecret, decSecret, cipherSuite)
        {
        }
    }
}
