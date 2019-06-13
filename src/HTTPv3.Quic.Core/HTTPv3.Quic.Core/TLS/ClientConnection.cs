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
        public CancellationToken cancel;

        private InitialProcessor InitialStream;

        public CipherSuite SelectedCipherSuite;
        public CngKey MyKey;
        public KeyShare MyKeyShare;

        Task readerTask;

        public ClientConnection(CryptoStream initial, CryptoStream handshake, CryptoStream application, CancellationToken cancel)
        {
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
            var hello = new ClientHello()
            {
                ServerName = serverName,
            };

            hello.CipherSuites.AddRange(new[] { CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256 });
            hello.ALPN.Add("h3-20");
            hello.SupportedVersions.Add(ProtocolVersion.TLSv1_3);
            hello.SupportedGroups.Add(NamedGroup.secp256r1);
            hello.SignatureAlgorithms.AddRange(new[] { SignatureScheme.rsa_pss_rsae_sha256, SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.rsa_pkcs1_sha256, SignatureScheme.rsa_pkcs1_sha1 });
            hello.PskKeyExchangeModes.AddRange(new[] { PskKeyExchangeMode.PSKwithDheKeyEstablishment });
            hello.UnknownExtensions.AddRange(unknownExtensions);

            MyKeyShare = CreateKeyShare();
            hello.KeyShares.Add(MyKeyShare);

            return hello.Write(buffer);
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
    }
}
