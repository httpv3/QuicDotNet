using HTTPv3.Quic.TLS.Messages.Extensions;

namespace HTTPv3.Quic.Security
{
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal class InitialKeys : EncryptionKeys
    {
        private InitialKeys(in byte[] encSecret, in byte[] decSecret, CipherSuite cipherSuite) : base(encSecret, decSecret, cipherSuite)
        {
        }

        public static InitialKeys Create(byte[] clientChosenDestinationId, bool isServer)
        {
            var initialSecret = Hkdf256.Extract(clientChosenDestinationId, InitialSalt);

            var clientSecret = Hkdf256.Expand(initialSecret, 32, ClientIn);
            var serverSecret = Hkdf256.Expand(initialSecret, 32, ServerIn);

            if (isServer)
                return new InitialKeys(serverSecret, clientSecret, CipherSuite.TLS_AES_128_GCM_SHA256);
            else
                return new InitialKeys(clientSecret, serverSecret, CipherSuite.TLS_AES_128_GCM_SHA256);
        }
    }
}
