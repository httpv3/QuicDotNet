using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Messages;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace HTTPv3.Quic.TLS.Client
{
    internal class InitialProcessor
    {
        ClientConnection conn;
        CryptoStream stream;

        public InitialProcessor(ClientConnection conn, CryptoStream stream)
        {
            this.conn = conn;
            this.stream = stream;
        }

        public async Task Run()
        {
            await foreach(var record in RawRecord.ReadRecords(stream.Input, conn.cancel))
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
                using(var theirKey = CngKeyExtensions.FromTLSPublicKey(CngAlgorithm.ECDiffieHellmanP256, m.KeyShare.KeyExchange))
                using (var ecdhe = new ECDiffieHellmanCng(conn.MyKey))
                {
                    var premasterKey = ecdhe.DeriveKeyMaterial(theirKey);
                }
            }

            await Task.Yield();
        }
    }
}
