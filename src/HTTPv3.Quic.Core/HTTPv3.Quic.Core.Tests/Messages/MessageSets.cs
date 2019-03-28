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

        private readonly byte[] _Client_Initial;
        public byte[] Client_Initial { get { return _Client_Initial.ToArray(); } }

        private MessageSets(int setNum)
        {
            _Client_Initial = LoadBinFile(setNum, "c.initial.bin");
        }

        private byte[] LoadBinFile(int setNum, string filename)
        {
            string fullFileName = $"../../../Messages/Data/{setNum}/{filename}";
            FileInfo fi = new FileInfo(fullFileName);
            if (!fi.Exists)
                throw new FileNotFoundException($"Cannot find {fi.FullName}");

            return File.ReadAllBytes(fullFileName);
        }
    }
}
