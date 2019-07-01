using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Messages;
using System;
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

            var empty_hash = CryptoHelper.ComputeSha256Hash(new byte[] { });
            var zero_key = "0000000000000000000000000000000000000000000000000000000000000000".ToByteArrayFromHex();
            var derived_secret = CryptoHelper.ExpandTLSLabel(hkdf, conn.handshake_secret, CryptoHelper.DERIVED_LABEL, empty_hash, 32);
            conn.master_secret = hkdf.Extract(zero_key, derived_secret);
            conn.client_application_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, conn.master_secret, CryptoHelper.CLIENT_APP_LABEL, finished_hash, 32);
            conn.server_application_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, conn.master_secret, CryptoHelper.SERVER_APP_LABEL, finished_hash, 32);

            Console.WriteLine("QUIC_SERVER_TRAFFIC_SECRET_0 " + BitConverter.ToString(conn.Random).Replace("-", "") + " " + BitConverter.ToString(conn.server_application_traffic_secret).Replace("-", ""));
            Console.WriteLine("QUIC_CLIENT_TRAFFIC_SECRET_0 " + BitConverter.ToString(conn.Random).Replace("-", "") + " " + BitConverter.ToString(conn.client_application_traffic_secret).Replace("-", ""));


            conn.CipherUpdated(new CipherUpdateDetail()
            {
                State = EncryptionState.Application,
                ClientSecret = conn.client_application_traffic_secret,
                ServerSecret = conn.server_application_traffic_secret,
                CipherSuite = conn.SelectedCipherSuite,
            });



            var finished_key = CryptoHelper.ExpandTLSLabel(hkdf, conn.client_handshake_traffic_secret, CryptoHelper.FINISHED_LABEL, new byte[0], 32);

            var verify_data = hkdf.Extract(finished_hash, finished_key);

            FinishedExtension finished = new FinishedExtension()
            {
                VerifyData = verify_data
            };

            int bufferSize = 100;
            var buffer = stream.Output.GetMemory(bufferSize);
            var bytesLeft = finished.Write(buffer.Span).Length;

            stream.Output.Advance(buffer.Length - bytesLeft);
            await stream.Output.FlushAsync(conn.cancel);
        }
    }
}
