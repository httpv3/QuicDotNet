using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Messages;
using System.Threading.Tasks;

namespace HTTPv3.Quic.TLS.Client
{
    internal class ApplicationProcessor
    {
        ClientConnection conn;
        CryptoStream stream;

        public ApplicationProcessor(ClientConnection conn, CryptoStream stream)
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
            }
        }
    }
}
