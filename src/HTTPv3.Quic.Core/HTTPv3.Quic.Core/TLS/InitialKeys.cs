namespace HTTPv3.Quic.TLS
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
            InitialSecret = EncryptionKeys.Hkdf.Extract(ClientChosenDestinationId, EncryptionKeys.InitialSalt);

            ClientInitialSecret = EncryptionKeys.Hkdf.Expand(InitialSecret, 32, EncryptionKeys.ServerIn);
            ServerInitialSecret = EncryptionKeys.Hkdf.Expand(InitialSecret, 32, EncryptionKeys.ServerIn);

            if (isServer)
                EncryptionKeys = new EncryptionKeys(ServerInitialSecret, ClientInitialSecret);
            else
                EncryptionKeys = new EncryptionKeys(ClientInitialSecret, ServerInitialSecret);
        }
    }
}
