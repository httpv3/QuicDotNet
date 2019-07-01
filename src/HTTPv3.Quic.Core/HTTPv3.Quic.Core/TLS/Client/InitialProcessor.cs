using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Messages;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace HTTPv3.Quic.TLS.Client
{
    internal class InitialProcessor
    {
        public static readonly byte[] MASTER_SECRET_LABEL = "6D 61 73 74 65 72 20 73 65 63 72 65 74".ToByteArrayFromHex();

        ClientConnection conn;
        CryptoStream stream;

        public InitialProcessor(ClientConnection conn, CryptoStream stream)
        {
            this.conn = conn;
            this.stream = stream;
        }

        public async Task Run()
        {
            await foreach(var record in RawRecord.ReadRecords(conn, stream.Input, conn.cancel))
            {
                await Process(record);
            }
        }

        private async Task Process(RawRecord r)
        {
            var h = Handshake.Parse(r);

            switch (r.HandshakeType)
            {
                case HandshakeType.ServerHello:
                    await Process(h as ServerHello);
                    break;
            }
        }

        private async Task Process(ServerHello m)
        {
            conn.SelectedCipherSuite = m.CipherSuite;

            if (m.KeyShare == null || m.KeyShare.Group != conn.MyKeyShare.Group)
                return;

            if (m.KeyShare.Group == Messages.Extensions.NamedGroup.secp256r1)
            {
                var sharedPub = CryptoHelper.PublicKeyFromBytes(m.KeyShare.KeyExchange);
                var shared_secret = CryptoHelper.CalculateSharedKey(conn.MyKey, sharedPub);

                var hello_hash = conn.GetHashOfProcessedHelloMessages();
                var zero_key = "0000000000000000000000000000000000000000000000000000000000000000".ToByteArrayFromHex();

                AronParker.Hkdf.Hkdf hkdf = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);

                var early_secret = hkdf.Extract(zero_key, new byte[] { 0 });
                var empty_hash = CryptoHelper.ComputeSha256Hash(new byte[] { });
                var derived_secret = CryptoHelper.ExpandTLSLabel(hkdf, early_secret, CryptoHelper.DERIVED_LABEL, empty_hash, 32);
                conn.handshake_secret = hkdf.Extract(shared_secret, derived_secret);
                conn.client_handshake_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, conn.handshake_secret, CryptoHelper.CLIENT_HANDSHAKE_LABEL, hello_hash, 32);
                conn.server_handshake_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, conn.handshake_secret, CryptoHelper.SERVER_HANDSHAKE_LABEL, hello_hash, 32);

                Console.WriteLine("QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET " + BitConverter.ToString(conn.Random).Replace("-", "") + " " + BitConverter.ToString(conn.server_handshake_traffic_secret).Replace("-", ""));
                Console.WriteLine("QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET " + BitConverter.ToString(conn.Random).Replace("-", "") + " " + BitConverter.ToString(conn.client_handshake_traffic_secret).Replace("-", ""));


                //var masterKey = ecdhe.DeriveKeyTls(theirKey, MASTER_SECRET_LABEL, seed);
                //master_secret = PRF(premasterKey, "master secret", ClientHello.random + ServerHello.random)
                //var keyData = EncryptionKeys.Hkdf256.Expand(premasterKey, 96, seed);

                conn.CipherUpdated(new CipherUpdateDetail()
                {
                    State = EncryptionState.Handshake,
                    ClientSecret = conn.client_handshake_traffic_secret,
                    ServerSecret = conn.server_handshake_traffic_secret,
                    CipherSuite = conn.SelectedCipherSuite,
                });
            }

            await Task.Yield();
        }
    }
}
