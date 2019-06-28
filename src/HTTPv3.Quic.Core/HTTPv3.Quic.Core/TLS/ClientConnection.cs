using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Client;
using HTTPv3.Quic.TLS.Messages;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic.TLS
{
    internal class ClientConnection
    {
        public const int Random_NumBytes = 32;
        public const int LegacySessionId_NumBytes = 32;

        public CancellationToken cancel;

        private InitialProcessor InitialStream;
        private HandshakeProcessor HandshakeStream;

        public byte[] Random = new byte[Random_NumBytes];
        public byte[] LegacySessionId = new byte[LegacySessionId_NumBytes];
        public CipherSuite SelectedCipherSuite;
        public ECPrivateKeyParameters MyKey;
        public KeyShare MyKeyShare;

        public byte[] ClientHelloBytes = new byte[0];
        public byte[] ServerHelloBytes = new byte[0];
        public byte[] EncryptedExtensionsBytes = new byte[0];
        public byte[] CertificateBytes = new byte[0];
        public byte[] CertificateVerifyBytes = new byte[0];
        public byte[] ServerFinishedBytes = new byte[0];

        public byte[] client_handshake_traffic_secret = new byte[0];
        public byte[] server_handshake_traffic_secret = new byte[0];

        Task readerTask;

        public Action<CipherUpdateDetail> CipherUpdated { get; }

        public ClientConnection(CryptoStream initial, CryptoStream handshake, CryptoStream application, Action<CipherUpdateDetail> cipherUpdated, CancellationToken cancel)
        {
            CipherUpdated = cipherUpdated;
            this.cancel = cancel;

            InitialStream = new InitialProcessor(this, initial);
            HandshakeStream = new HandshakeProcessor(this, handshake);

            readerTask = StartReading();
        }

        private Task StartReading()
        {
            return Task.WhenAll(InitialStream.Run(), HandshakeStream.Run());
        }

        internal Span<byte> WriteClientHello(in Span<byte> buffer, string serverName, params UnknownExtension[] unknownExtensions)
        {
            RandomNumberGenerator.Fill(Random);
            RandomNumberGenerator.Fill(LegacySessionId);

            var hello = new ClientHello()
            {
                ServerName = serverName,
                Random = Random,
                LegacySessionId = LegacySessionId
            };

            hello.CipherSuites.AddRange(new[] { CipherSuite.TLS_AES_128_GCM_SHA256 });
            hello.ALPN.Add("h3-20");
            hello.SupportedVersions.Add(ProtocolVersion.TLSv1_3);
            hello.SupportedGroups.Add(NamedGroup.secp256r1);
            hello.SignatureAlgorithms.AddRange(new[] { SignatureScheme.rsa_pss_rsae_sha256, SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.rsa_pkcs1_sha256, SignatureScheme.rsa_pkcs1_sha1 });
            hello.PskKeyExchangeModes.AddRange(new[] { PskKeyExchangeMode.PSKwithDheKeyEstablishment });
            hello.UnknownExtensions.AddRange(unknownExtensions);

            MyKeyShare = CreateKeyShare();
            hello.KeyShares.Add(MyKeyShare);

            var ret = hello.Write(buffer);

            ClientHelloBytes = buffer.Subtract(ret).ToArray();

            return ret;
        }

        private KeyShare CreateKeyShare()
        {
            var pair = CryptoHelper.GenerateKeyPair();

            MyKey = (ECPrivateKeyParameters)pair.Private;

            return new KeyShare()
            {
                Group = NamedGroup.secp256r1,
                KeyExchange = CryptoHelper.EncodePublicKey((ECPublicKeyParameters)pair.Public)
            };
        }

        public byte[] GetHashOfProcessedHelloMessages()
        {
            var bytes = new byte[ClientHelloBytes.Length + ServerHelloBytes.Length];
            bytes.AsSpan().Write(ClientHelloBytes).Write(ServerHelloBytes);
            return CryptoHelper.ComputeSha256Hash(bytes);
        }

        public byte[] GetHashOfProcessedHandshakeMessages()
        {
            var bytes = new byte[ClientHelloBytes.Length + ServerHelloBytes.Length + EncryptedExtensionsBytes.Length + CertificateBytes.Length + CertificateVerifyBytes.Length + ServerFinishedBytes.Length];
            bytes.AsSpan().Write(ClientHelloBytes).Write(ServerHelloBytes).Write(EncryptedExtensionsBytes).Write(CertificateBytes).Write(CertificateVerifyBytes).Write(ServerFinishedBytes);
            return CryptoHelper.ComputeSha256Hash(bytes);
        }
    }
}
