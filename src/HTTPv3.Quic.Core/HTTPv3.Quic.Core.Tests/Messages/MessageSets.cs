using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Security;
using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PcapngFile;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.Messages
{
    class MessageSets : IEnumerable<DataFile>
    {
        public static MessageSets Set1 = new MessageSets(1);
        //public static MessageSets Set2 = new MessageSets(2);

        private readonly Dictionary<int, DataFile> files = new Dictionary<int, DataFile>();
        public DataFile this[int i] { get { return files[i].Clone(); } }

        public ClientConnectionId ClientId;
        public ServerConnectionId ServerId;

        public ApplicationKeys[] ClientApplicationKeys;
        public ApplicationKeys[] ServerApplicationKeys;

        public Connection ClientConnection;
        public Connection ServerConnection;

        private MessageSets(int setNum)
        {
            var index = JsonConvert.DeserializeObject<Index>(File.ReadAllText(ConstructFileName(setNum, "index.json")));

            ClientId = new ClientConnectionId(index.ClientId.ToByteArrayFromHex());
            ServerId = new ServerConnectionId(index.ServerId.ToByteArrayFromHex());

            var clientIp = index.ClientIp.ToByteArrayFromHex();

            using (var rdr = new Reader(ConstructFileName(setNum, "wireshark.pcapng")))
            {
                int i = 1;
                foreach (var packet in rdr.AllBlocks.Select(x => x as EnhancedPacketBlock).Where(x=>x != null))
                {
                    var data = packet.Data.AsSpan()
                                          .ReadBytes(14, out _)
                                          .ReadByte(out var ipHeader)
                                          .ReadBytes((ipHeader & 0xf) * 4 - 9, out _)
                                          .ReadBytes(4, out var source)
                                          .ReadBytes(4, out _)
                                          .ReadBytes(8, out _);

                    files[i] = new DataFile()
                    {
                        Sequence = i++,
                        Data = data.ToArray(),
                        Source = source.SequenceEqual(clientIp) ? DataFileSources.Client : DataFileSources.Server,
                    };
                }
            }

            if (index.Secrets != null)
                LoadSecrets(index.Secrets);
        }

        private void LoadSecrets(Secrets secrets)
        {
            ClientConnection = new Connection(secrets.Initial.ToByteArrayFromHex().ToArray(), "", false)
            {
                ClientConnectionId = ClientId,
                ServerConnectionId = ServerId,
            };

            ServerConnection = new Connection(secrets.Initial.ToByteArrayFromHex().ToArray(), "", true)
            {
                ClientConnectionId = ClientId,
                ServerConnectionId = ServerId,
            };

            if (secrets.Handshake != null)
            {
                ClientConnection.HandshakeKeys = new HandshakeKeys(secrets.Handshake.Client.ToByteArrayFromHex().ToArray(), secrets.Handshake.Server.ToByteArrayFromHex().ToArray(), secrets.Handshake.CipherSuite, false);
                ServerConnection.HandshakeKeys = new HandshakeKeys(secrets.Handshake.Client.ToByteArrayFromHex().ToArray(), secrets.Handshake.Server.ToByteArrayFromHex().ToArray(), secrets.Handshake.CipherSuite, true);
            }

            if (secrets.Application != null)
            {
                List<ApplicationKeys> cKeys = new List<ApplicationKeys>();
                List<ApplicationKeys> sKeys = new List<ApplicationKeys>();

                foreach (var app in secrets.Application)
                {
                    cKeys.Add(new ApplicationKeys(app.Client.ToByteArrayFromHex().ToArray(), app.Server.ToByteArrayFromHex().ToArray(), app.CipherSuite, false));
                    sKeys.Add(new ApplicationKeys(app.Client.ToByteArrayFromHex().ToArray(), app.Server.ToByteArrayFromHex().ToArray(), app.CipherSuite, true));
                }

                ClientApplicationKeys = cKeys.ToArray();
                ServerApplicationKeys = sKeys.ToArray();

                ClientConnection.ApplicationKeys = ClientApplicationKeys[0];
                ServerConnection.ApplicationKeys = ServerApplicationKeys[0];
            }
        }

        private string ConstructFileName(int setNum, string filename)
        {
            return $"../../../Messages/Data/{setNum}/{filename}";
        }

        IEnumerator<DataFile> IEnumerable<DataFile>.GetEnumerator()
        {
            foreach(var file in files.Values.OrderBy(x=>x.Sequence))
                yield return file.Clone();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
        }
    }

    public class Index
    {
        public string ClientId;
        public string ClientIp;
        public string ServerId;

        public DataFile[] Files;
        public Secrets Secrets;
    }

    public class DataFile
    {
        public int Sequence;
        public DataFileSources Source;
        public byte[] Data;

        public bool FromClient => Source == DataFileSources.Client;

        public DataFile Clone()
        {
            return new DataFile()
            {
                Sequence = Sequence,
                Source = Source,
                Data = Data.ToArray()
            };
        }
    }

    public class Secrets
    {
        public string Initial;
        public KeyPair Handshake;
        public KeyPair[] Application;
    }

    public class KeyPair
    {
        public string Client;
        public string Server;
        public CipherSuite CipherSuite;
    }

    public enum DataFileSources
    {
        Client,
        Server
    }
}
