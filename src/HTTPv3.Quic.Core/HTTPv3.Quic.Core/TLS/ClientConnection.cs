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
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace HTTPv3.Quic.TLS
{
    internal class ClientConnection
    {
        private static SecureRandom prng = new SecureRandom();

        CancellationToken cancel;
        PipeReader reader;
        PipeWriter writer;

        Task readerTask;

        public ClientConnection(PipeReader reader, PipeWriter writer, CancellationToken cancel)
        {
            this.reader = reader;
            this.writer = writer;
            this.cancel = cancel;

            readerTask = StartReading();
        }

        private async Task StartReading()
        {
            await foreach (var r in RawRecord.ReadRecords(reader, cancel))
            {
                var msg = Handshake.Parse(r);
                //if (msg != null)
                //    msg.Process(this);
            }
        }

        internal void WriteClientHello(Span<byte> buffer, string serverName)
        {
            var hello = new ClientHello()
            {
                ServerName = serverName,
                TransportParameters = TransportParameters.Default
            };

            hello.CipherSuites.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            hello.ALPN.Add("h3-20");
            hello.SupportedVersions.Add(ProtocolVersion.TLSv1_3);
            hello.SupportedGroups.Add(NamedGroup.secp256r1);
            hello.SignatureAlgorithms.Add(SignatureScheme.ecdsa_secp256r1_sha256);
            hello.PskKeyExchangeModes.Add(PskKeyExchangeMode.PSKwithDheKeyEstablishment);

            hello.KeyShares.Add(CreateKeyShare());

            hello.Write(buffer);
        }

        private KeyShare CreateKeyShare()
        {
            var key = new byte[65];

            IAsymmetricCipherKeyPairGenerator bcKpGen = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            bcKpGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, prng));
            AsymmetricCipherKeyPair pair = bcKpGen.GenerateKeyPair();

            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public);

            return new KeyShare()
            {
                Group = NamedGroup.secp256r1,
                KeyExchange = info.PublicKeyData.GetBytes(),
            };
        }
    }
}
