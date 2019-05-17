using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    internal static class OrderedStream
    {
        public static async IAsyncEnumerable<byte[]> ToOrderedStream(this IAsyncEnumerable<NumberedData> streamIn)
        {
            long curNumber = 0;
            Dictionary<long, NumberedData> items = new Dictionary<long, NumberedData>();

            await foreach (var item in streamIn)
            {
                if (item.Number == curNumber)
                {
                    curNumber++;
                    yield return item.Data;
                }
                else
                {
                    items[item.Number] = item;
                }

                if (items.Count > 0)
                {
                    while (items.ContainsKey(curNumber))
                    {
                        items.Remove(curNumber, out var inner);
                        curNumber++;
                        yield return inner.Data;
                    }
                }
            }
        }

        public static async IAsyncEnumerable<byte[]> ToOrderedStream(this IAsyncEnumerable<OffsetData> streamIn)
        {
            long currentOffset = 0;
            Dictionary<long, OffsetData> items = new Dictionary<long, OffsetData>();

            await foreach (var item in streamIn)
            {
                if (item.Offset == currentOffset)
                {
                    currentOffset += item.Data.Length;
                    yield return item.Data;
                }
                else
                {
                    items[item.Offset] = item;
                }

                if (items.Count > 0)
                {
                    while (items.ContainsKey(currentOffset))
                    {
                        items.Remove(currentOffset, out var inner);
                        currentOffset += inner.Data.Length;
                        yield return inner.Data;
                    }
                }
            }
        }

        public class NumberedData
        {
            public byte[] Data;
            public long Number;
        }

        public class OffsetData
        {
            public byte[] Data;
            public long Offset;
        }
    }
}
