namespace HTTPv3.Quic.TLS
{
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal class HandshakeKeys
    {
        public readonly byte[] ClientInitialSecret;
        public readonly byte[] ServerInitialSecret;

        public readonly EncryptionKeys EncryptionKeys;

        public HandshakeKeys(byte[] clientHandshakeSecret, byte[] serverHandshakeSecret, bool isServer)
        {
            ClientInitialSecret = clientHandshakeSecret;
            ServerInitialSecret = serverHandshakeSecret;

            if (isServer)
                EncryptionKeys = new EncryptionKeys(ServerInitialSecret, ClientInitialSecret, 384);
            else
                EncryptionKeys = new EncryptionKeys(ClientInitialSecret, ServerInitialSecret, 384);
        }
    }
}
