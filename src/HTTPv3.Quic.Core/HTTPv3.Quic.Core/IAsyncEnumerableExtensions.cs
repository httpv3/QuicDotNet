using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace HTTPv3.Quic
{
    internal static class IAsyncEnumerableExtensions
    {
        public static IAsyncEnumerable<T> Union<T>(this IAsyncEnumerable<T> first, params IAsyncEnumerable<T>[] others)
        {
            var list = new List<IAsyncEnumerable<T>>();
            list.Add(first);
            list.AddRange(others);

            return new AsyncUnionEnumerable<T>(list.ToArray());
        }
    }

    internal class AsyncUnionEnumerable<T> : IAsyncEnumerable<T>
    {
        private IAsyncEnumerable<T>[] streams;

        public AsyncUnionEnumerable(params IAsyncEnumerable<T>[] streams)
        {
            this.streams = streams;
        }

        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        {
            return new AsyncUnionEnumerator<T>(cancellationToken, streams);
        }
    }

    internal class AsyncUnionEnumerator<T> : IAsyncEnumerator<T>
    {
        private IAsyncEnumerator<T>[] streams;
        private List<(IAsyncEnumerator<T> stream, ValueTask<bool> value, Task<bool> task)> tasks;

        private T current = default;
        public T Current => current;

        public AsyncUnionEnumerator(CancellationToken cancellationToken, params IAsyncEnumerable<T>[] streams)
        {
            this.streams = streams.Select(s => s.GetAsyncEnumerator(cancellationToken)).ToArray();
        }

        public ValueTask DisposeAsync()
        {
            return default;
        }

        public async ValueTask<bool> MoveNextAsync()
        {
            if (tasks == null)
                tasks = streams.Select(s => GetTask(s)).ToList();

            if (tasks.Count > 0)
            {
                var t = await Task.WhenAny(tasks.Select(p => p.task));

                var next = tasks.First(p => p.task == t);

                current = next.stream.Current;

                if (t.Result) // There is more
                    tasks.Add(GetTask(next.stream));
            }

            return tasks.Count > 0;
        }

        private (IAsyncEnumerator<T> stream, ValueTask<bool> value, Task<bool> task) GetTask(IAsyncEnumerator<T> stream)
        {
            var val = stream.MoveNextAsync();
            return (stream, val, val.AsTask());
        }
    }
}
