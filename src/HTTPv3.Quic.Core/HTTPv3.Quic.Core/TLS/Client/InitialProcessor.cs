using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Security;
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

        static public readonly byte[] TLS_LABEL = "74 6C 73 31 33 20".ToByteArrayFromHex();
        static public readonly byte[] DERIVED_LABEL = "64 65 72 69 76 65 64".ToByteArrayFromHex();
        static public readonly byte[] CLIENT_HANDSHAKE_LABEL = "63 20 68 73 20 74 72 61 66 66 69 63".ToByteArrayFromHex();
        static public readonly byte[] SERVER_HANDSHAKE_LABEL = "73 20 68 73 20 74 72 61 66 66 69 63".ToByteArrayFromHex();

        private async Task Process(ServerHello m)
        {
            conn.SelectedCipherSuite = m.CipherSuite;

            if (m.KeyShare == null || m.KeyShare.Group != conn.MyKeyShare.Group)
                return;

            if (m.KeyShare.Group == Messages.Extensions.NamedGroup.secp256r1)
            {
                var seed = new byte[MASTER_SECRET_LABEL.Length + 64];
                seed.AsSpan().Write(MASTER_SECRET_LABEL).Write(conn.Random).Write(m.Random);

                using(var theirKey = CngKeyExtensions.FromTLSPublicKey(CngAlgorithm.ECDiffieHellmanP256, m.KeyShare.KeyExchange))
                using (var ecdhe = new ECDiffieHellmanCng(conn.MyKey))
                {
                    var shared_secret = ecdhe.DeriveKeyMaterial(theirKey);
                    var hello_hash = conn.GetHashOfProcessedMessage();
                    var zero_key = "0000000000000000000000000000000000000000000000000000000000000000".ToByteArrayFromHex();

                    AronParker.Hkdf.Hkdf hkdf = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);

                    var early_secret = hkdf.Extract(zero_key, new byte[] { 0 });
                    var empty_hash = ComputeSha256Hash(new byte[] { });
                    var derived_secret = ExpandTLSLabel(hkdf, early_secret, DERIVED_LABEL, empty_hash, 32);
                    var handshake_secret = hkdf.Extract(shared_secret, derived_secret);
                    var client_handshake_traffic_secret = ExpandTLSLabel(hkdf, handshake_secret, CLIENT_HANDSHAKE_LABEL, hello_hash, 32);
                    var server_handshake_traffic_secret = ExpandTLSLabel(hkdf, handshake_secret, SERVER_HANDSHAKE_LABEL, hello_hash, 32);

                    //var masterKey = ecdhe.DeriveKeyTls(theirKey, MASTER_SECRET_LABEL, seed);
                    //master_secret = PRF(premasterKey, "master secret", ClientHello.random + ServerHello.random)
                    //var keyData = EncryptionKeys.Hkdf256.Expand(premasterKey, 96, seed);

                    conn.CipherUpdated(new CipherUpdateDetail()
                    {
                        State = EncryptionState.Handshake,
                        ClientSecret = client_handshake_traffic_secret,
                        ServerSecret = server_handshake_traffic_secret,
                        CipherSuite = conn.SelectedCipherSuite,
                    });
                }
            }

            await Task.Yield();
        }

        static private byte[] ExpandTLSLabel(AronParker.Hkdf.Hkdf hkdf, byte[] secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, ushort length)
        {
            var info = new byte[4 + TLS_LABEL.Length + label.Length + context.Length];
            info.AsSpan().Write(length)
                         .Write((byte)(TLS_LABEL.Length + label.Length))
                         .Write(TLS_LABEL)
                         .Write(label)
                         .Write((byte)(context.Length))
                         .Write(context);

            //Console.WriteLine($"info: {BitConverter.ToString(info).Replace("-", "")}");
            return hkdf.Expand(secret, length, info);
        }

        static byte[] ComputeSha256Hash(byte[] bytesIn)
        {
            using (SHA256 hash = SHA256.Create())
            {
                return hash.ComputeHash(bytesIn);
            }
        }

        static byte[] ComputeSha384Hash(byte[] bytesIn)
        {
            using (SHA384 hash = SHA384.Create())
            {
                return hash.ComputeHash(bytesIn);

            }
        }
    }
}
