using HTTPv3.Quic.Messages.Common;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.Messages
{
    class MessageSets
    {
        public static MessageSets Set1 = new MessageSets(1);

        private readonly Dictionary<int, DataFile> files = new Dictionary<int, DataFile>();
        public DataFile this[int i] { get { return files[i].Clone(); } }

        private MessageSets(int setNum)
        {
            var index = JsonConvert.DeserializeObject<Index>(File.ReadAllText(ConstructFileName(setNum, "index.json")));

            foreach (var file in index.Files)
            {
                file.Data = LoadBinFile(setNum, file.Name);
                files[file.Sequence] = file;
            }

            var firstPacket = this[1];
            var p = new Packet(firstPacket.Data, false);
            p.LongHeader = new LongHeader(ref p);
            var serverId = new ConnectionId(p.LongHeader.DestinationConnID.ToArray());
            var clientId = new ConnectionId(p.LongHeader.SourceConnID.ToArray());
            p.Connection = ConnectionManager.GetOrCreate(serverId, clientId, p.IsServer);
        }

        private byte[] LoadBinFile(int setNum, string filename)
        {
            string fullFileName = ConstructFileName(setNum, filename);
            FileInfo fi = new FileInfo(fullFileName);
            if (!fi.Exists)
                return null;

            return File.ReadAllBytes(fullFileName);
        }

        public string ConstructFileName(int setNum, string filename)
        {
            return $"../../../Messages/Data/{setNum}/{filename}";
        }
    }

    public class Index
    {
        public DataFile[] Files;
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

    public enum DataFileSources
    {
        Client,
        Server
    }
}
