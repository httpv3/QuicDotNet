﻿using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
        public static MessageSets Set2 = new MessageSets(2);

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

            foreach (var file in index.Files)
            {
                file.Data = LoadBinFile(setNum, file.Name);
                files[file.Sequence] = file;
            }

            if (index.Secrets != null)
                LoadSecrets(index.Secrets);
        }

        private void LoadSecrets(Secrets secrets)
        {
            ClientConnection = new Connection(secrets.Initial.ToByteArrayFromHex().ToArray(), false)
            {
                ClientConnectionId = ClientId,
                ServerConnectionId = ServerId,
            };

            ServerConnection = new Connection(secrets.Initial.ToByteArrayFromHex().ToArray(), true)
            {
                ClientConnectionId = ClientId,
                ServerConnectionId = ServerId,
            };

            if (secrets.Handshake != null)
            {
                ClientConnection.TLSConn.HandshakeKeys = new HandshakeKeys(secrets.Handshake.Client.ToByteArrayFromHex().ToArray(), secrets.Handshake.Server.ToByteArrayFromHex().ToArray(), secrets.Handshake.CipherSuite, false);
                ServerConnection.TLSConn.HandshakeKeys = new HandshakeKeys(secrets.Handshake.Client.ToByteArrayFromHex().ToArray(), secrets.Handshake.Server.ToByteArrayFromHex().ToArray(), secrets.Handshake.CipherSuite, true);
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

                ClientConnection.TLSConn.ApplicationKeys = ClientApplicationKeys[0];
                ServerConnection.TLSConn.ApplicationKeys = ServerApplicationKeys[0];
            }
        }

        private byte[] LoadBinFile(int setNum, string filename)
        {
            string fullFileName = ConstructFileName(setNum, filename);
            FileInfo fi = new FileInfo(fullFileName);
            if (!fi.Exists)
                return null;

            return File.ReadAllBytes(fullFileName);
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
        public string ServerId;

        public DataFile[] Files;
        public Secrets Secrets;
    }

    public class DataFile
    {
        public int Sequence;
        public string Name;
        public DataFileSources Source;
        public byte[] Data;

        public bool FromClient => Source == DataFileSources.Client;

        public DataFile Clone()
        {
            return new DataFile()
            {
                Sequence = Sequence,
                Name = Name,
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
