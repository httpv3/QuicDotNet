using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Messages;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace HTTPv3.Quic.TLS.Client
{
    internal class HandshakeProcessor
    {
        ClientConnection conn;
        CryptoStream stream;

        public HandshakeProcessor(ClientConnection conn, CryptoStream stream)
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
                case HandshakeType.EncryptedExtensions:
                    await Process(h as EncryptedExtensions);
                    break;
                case HandshakeType.Certificate:
                    await Process(h as CertificateExtension);
                    break;
                case HandshakeType.CertificateVerify:
                    await Process(h as CertificateVerify);
                    break;
                case HandshakeType.Finished:
                    await Process(h as FinishedExtension);
                    break;
            }
        }

        private async Task Process(EncryptedExtensions m)
        {
            await Task.Yield();
        }

        private async Task Process(CertificateExtension m)
        {
            await Task.Yield();
        }

        private async Task Process(CertificateVerify m)
        {
            await Task.Yield();
        }

        private async Task Process(FinishedExtension m)
        {
            var finished_hash = conn.GetHashOfProcessedHandshakeMessages();

            AronParker.Hkdf.Hkdf hkdf = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);
            var finished_key = CryptoHelper.ExpandTLSLabel(hkdf, conn.client_handshake_traffic_secret, CryptoHelper.FINISHED_LABEL, new byte[0], 32);

            var verify_data = hkdf.Extract(finished_hash, finished_key);

            FinishedExtension finished = new FinishedExtension()
            {
                VerifyData = verify_data
            };

            int bufferSize = 100;
            var buffer = stream.Output.GetMemory(bufferSize);
            var bytesLeft = finished.Write(buffer.Span).Length;

            stream.Output.Advance(bufferSize - bytesLeft);
            await stream.Output.FlushAsync(conn.cancel);
        }
    }
}
