using HTTPv3.Quic.TLS.Messages.Extensions;

namespace HTTPv3.Quic.Security
{
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal class InitialKeys
    {
        public readonly byte[] ClientChosenDestinationId;

        public readonly byte[] InitialSecret;
        public readonly byte[] ClientInitialSecret;
        public readonly byte[] ServerInitialSecret;

        public readonly EncryptionKeys EncryptionKeys;

        public InitialKeys(byte[] clientChosenDestinationId, bool isServer)
        {
            ClientChosenDestinationId = clientChosenDestinationId;
            InitialSecret = EncryptionKeys.Hkdf256.Extract(ClientChosenDestinationId, EncryptionKeys.InitialSalt);

            ClientInitialSecret = EncryptionKeys.Hkdf256.Expand(InitialSecret, 32, EncryptionKeys.ClientIn);
            ServerInitialSecret = EncryptionKeys.Hkdf256.Expand(InitialSecret, 32, EncryptionKeys.ServerIn);

            if (isServer)
                EncryptionKeys = new EncryptionKeys(ServerInitialSecret, ClientInitialSecret, CipherSuite.TLS_AES_128_GCM_SHA256);
            else
                EncryptionKeys = new EncryptionKeys(ClientInitialSecret, ServerInitialSecret, CipherSuite.TLS_AES_128_GCM_SHA256);
        }
    }
}
