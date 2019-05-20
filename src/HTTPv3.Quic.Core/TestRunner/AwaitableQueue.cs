using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TestRunner
{
    class AwaitableQueue<T> : IAsyncEnumerable<T>, IAsyncEnumerator<T>
    {
        Queue<T> q = new Queue<T>(new [] { default(T) });
        TaskCompletionSource<bool> tsc = null;

        public T Current
        {
            get
            {
                if (q.Count > 0)
                    return q.Peek();
                return default(T);
            }
        }

        public void Add(T item)
        {
            q.Enqueue(item);

            if (tsc != null)
                tsc.SetResult(true);
            else
                tsc = null;
        }

        async ValueTask IAsyncDisposable.DisposeAsync()
        {
            tsc.SetResult(false);
        }

        IAsyncEnumerator<T> IAsyncEnumerable<T>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return this;
        }

        ValueTask<bool> IAsyncEnumerator<T>.MoveNextAsync()
        {
            if (q.Count > 0)
                q.Dequeue();

            if (q.Count > 0)
                return new ValueTask<bool>(true);

            tsc = new TaskCompletionSource<bool>();
            return new ValueTask<bool>(tsc.Task);
        }
    }
}
