using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace HTTPv3.Quic.Extensions
{
    public static class IAsyncEnumerableExtensions
    {
        public static IAsyncEnumerable<T> Combine<T>(this IEnumerable<IAsyncEnumerable<T>> streams)
        {
            return new AsyncCombinedEnumerable<T>(streams.ToArray());
        }

        public static IAsyncEnumerable<T> Combine<T>(this IAsyncEnumerable<T> first, IAsyncEnumerable<T> second)
        {
            var list = new List<IAsyncEnumerable<T>>();
            list.Add(first);
            list.Add(second);

            return new AsyncCombinedEnumerable<T>(list.ToArray());
        }
    }

    internal class AsyncCombinedEnumerable<T> : IAsyncEnumerable<T>
    {
        private IAsyncEnumerable<T>[] streams;

        public AsyncCombinedEnumerable(params IAsyncEnumerable<T>[] streams)
        {
            this.streams = streams;
        }

        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        {
            return new AsyncCombinedEnumerator<T>(cancellationToken, streams);
        }
    }

    internal class AsyncCombinedEnumerator<T> : IAsyncEnumerator<T>
    {
        private List<AsyncCombinedEnumeratorState<T>> states;

        public T Current { get; private set; } = default;

        public AsyncCombinedEnumerator(CancellationToken cancellationToken, params IAsyncEnumerable<T>[] streams)
        {
            states = streams.Select(s => new AsyncCombinedEnumeratorState<T>(s.GetAsyncEnumerator(cancellationToken))).ToList();
        }

        public ValueTask DisposeAsync()
        {
            return default;
        }

        public async ValueTask<bool> MoveNextAsync()
        {
            while (true)
            {
                if (states.Count == 0)
                    return false;

                foreach (var state in states)
                    state.MoveNextIfNeeded();

                var completedTask = await Task.WhenAny(states.Select(s => s.Task));

                var completedState = states.First(s => s.Task == completedTask);
                if (completedTask.Result == false) // There is no more
                {
                    states.Remove(completedState);
                    continue;
                }

                Current = completedState.Stream.Current;

                return true;
            }
        }
    }

    internal class AsyncCombinedEnumeratorState<T>
    {
        public IAsyncEnumerator<T> Stream;
        public ValueTask<bool> Value = default;
        public Task<bool> Task = null;

        public AsyncCombinedEnumeratorState(IAsyncEnumerator<T> stream)
        {
            Stream = stream;
        }

        internal void MoveNextIfNeeded()
        {
            if (Task != null)
                if (!Task.IsCompleted)
                    return;

            Value = Stream.MoveNextAsync();
            Task = Value.AsTask();
        }
    }
}
