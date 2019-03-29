using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    class MessageSets
    {
        public static MessageSets Set1 = new MessageSets(1);

        private int SetNum;

        private Dictionary<string, byte[]> data = new Dictionary<string, byte[]>();

        private MessageSets(int setNum)
        {
            SetNum = setNum;
        }

        public byte[] GetData(string filename)
        {
            byte[] ret;
            if (data.TryGetValue(filename, out ret))
                return ret.ToArray();

            ret = LoadBinFile(filename);
            data[filename] = ret;

            return ret.ToArray();
        }

        private byte[] LoadBinFile(string filename)
        {
            string fullFileName = $"../../../TLS/Data/{SetNum}/{filename}";
            FileInfo fi = new FileInfo(fullFileName);
            if (!fi.Exists)
                return null;

            return File.ReadAllBytes(fullFileName);
        }
    }
}
