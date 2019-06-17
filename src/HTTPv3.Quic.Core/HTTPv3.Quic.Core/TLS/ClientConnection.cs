using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Client;
using HTTPv3.Quic.TLS.Messages;
using HTTPv3.Quic.TLS.Messages.Extensions;
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

        public byte[] Random = new byte[Random_NumBytes];
        public byte[] LegacySessionId = new byte[LegacySessionId_NumBytes];
        public CipherSuite SelectedCipherSuite;
        public CngKey MyKey;
        public KeyShare MyKeyShare;

        private byte[] Messages = new byte[0];

        Task readerTask;

        public Action<CipherUpdateDetail> CipherUpdated { get; }

        public ClientConnection(CryptoStream initial, CryptoStream handshake, CryptoStream application, Action<CipherUpdateDetail> cipherUpdated, CancellationToken cancel)
        {
            CipherUpdated = cipherUpdated;
            this.cancel = cancel;

            InitialStream = new InitialProcessor(this, initial);

            readerTask = StartReading();
        }

        private Task StartReading()
        {
            return Task.WhenAll(InitialStream.Run());
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

            var ret =  hello.Write(buffer);

            AddProcessedMessage(buffer.Subtract(ret));

            return ret;
        }

        private KeyShare CreateKeyShare()
        {
            MyKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            var tlsKey = MyKey.ToTLSPublicKey();

            return new KeyShare()
            {
                Group = NamedGroup.secp256r1,
                KeyExchange = tlsKey
            };
        }

        public void AddProcessedMessage(in ReadOnlySpan<byte> message)
        {
            var buffer = new byte[Messages.Length + message.Length];
            buffer.AsSpan().Write(Messages).Write(message);
            Messages = buffer;
        }

        public byte[] GetHashOfProcessedMessage()
        {
            using (SHA256 hash = SHA256.Create())
            {
                return hash.ComputeHash(Messages);
            }
        }
    }
}
