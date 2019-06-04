using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TestRunner
{
    class AwaitableQueue<T> : IAsyncEnumerable<T>, IAsyncEnumerator<T>
    {
        Queue<T> q = new Queue<T>();
        TaskCompletionSource<bool> tsc = null;

        public T Current { get; private set; } = default(T);

        public void Add(T item)
        {
            lock (q)
            {
                q.Enqueue(item);

                if (tsc != null && !tsc.Task.IsCompleted)
                {
                    tsc.SetResult(true);
                    tsc = null;
                }
            }
        }

        async ValueTask IAsyncDisposable.DisposeAsync()
        {
            await Task.Delay(0);
            tsc.SetResult(false);
        }

        IAsyncEnumerator<T> IAsyncEnumerable<T>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return this;
        }

        ValueTask<bool> IAsyncEnumerator<T>.MoveNextAsync()
        {
            lock (q)
            {
                if (q.Count == 0)
                {
                    tsc = new TaskCompletionSource<bool>();
                    return new ValueTask<bool>(tsc.Task);
                }

                Current = q.Dequeue();

                return new ValueTask<bool>(true);
            }
        }
    }
}
