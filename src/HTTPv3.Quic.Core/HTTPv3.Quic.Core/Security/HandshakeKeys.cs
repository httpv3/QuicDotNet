using HTTPv3.Quic.TLS.Messages.Extensions;
using System;

namespace HTTPv3.Quic.Security
{
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal class HandshakeKeys
    {
        public readonly byte[] ClientInitialSecret;
        public readonly byte[] ServerInitialSecret;

        public readonly EncryptionKeys EncryptionKeys;

        public HandshakeKeys(byte[] clientHandshakeSecret, byte[] serverHandshakeSecret, CipherSuite cipherSuite, bool isServer)
        {
            ClientInitialSecret = clientHandshakeSecret;
            ServerInitialSecret = serverHandshakeSecret;

            if (isServer)
                EncryptionKeys = new EncryptionKeys(ServerInitialSecret, ClientInitialSecret, cipherSuite);
            else
                EncryptionKeys = new EncryptionKeys(ClientInitialSecret, ServerInitialSecret, cipherSuite);
        }
    }
}
