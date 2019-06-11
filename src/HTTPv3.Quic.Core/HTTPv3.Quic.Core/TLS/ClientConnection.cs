using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HTTPv3.Quic.Messages.Extensions;
using HTTPv3.Quic.TLS.Messages;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace HTTPv3.Quic.TLS
{
    internal class ClientConnection
    {
        private static SecureRandom prng = new SecureRandom();

        private CancellationToken cancel;

        private CryptoStream InitialStream;
        private CryptoStream HandshakeStream;
        private CryptoStream ApplicationStream;

        Task readerTask;

        public ClientConnection(CryptoStream initial, CryptoStream handshake, CryptoStream application, CancellationToken cancel)
        {
            InitialStream = initial;
            HandshakeStream = handshake;
            ApplicationStream = application;
            this.cancel = cancel;

            readerTask = StartReading();
        }

        private async Task StartReading()
        {
            //await foreach (var r in RawRecord.ReadRecords(reader, cancel))
            //{
            //    var msg = Handshake.Parse(r);
            //    //if (msg != null)
            //    //    msg.Process(this);
            //}
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

            hello.KeyShares.Add(CreateKeyShare());

            return hello.Write(buffer);
        }

        private KeyShare CreateKeyShare()
        {
            var key = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            var tlsKey = key.ToTLSPublicKey();

            return new KeyShare()
            {
                Group = NamedGroup.secp256r1,
                KeyExchange = tlsKey
            };
        }
    }
}
