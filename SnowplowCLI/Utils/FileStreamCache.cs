using System;
using System.Collections.Generic;
using System.IO;

namespace SnowplowCLI.Utils
{
    public sealed class FileStreamCache : IDisposable
    {
        internal sealed class Entry
        {
            public FileStream Stream = null!;
            public LinkedListNode<string> Node = null!;
            public int Active;
        }

        public sealed class StreamLease : IDisposable
        {
            private FileStreamCache? m_owner;
            private Entry? m_entry;

            internal StreamLease(FileStreamCache owner, Entry entry)
            {
                m_owner = owner;
                m_entry = entry;
                Stream = entry.Stream;
            }

            public FileStream Stream { get; }

            public void Dispose()
            {
                if (m_owner != null && m_entry != null)
                {
                    m_owner.Release(m_entry);
                    m_owner = null;
                    m_entry = null;
                }
            }
        }

        private readonly int m_capacity;
        private readonly Dictionary<string, Entry> m_entries;
        private readonly LinkedList<string> m_lru;
        private readonly object m_lock = new object();
        private bool m_disposed;

        public FileStreamCache(int capacity)
        {
            m_capacity = Math.Max(1, capacity);
            m_entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
            m_lru = new LinkedList<string>();
        }

        public StreamLease Acquire(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Path is empty.", nameof(path));

            lock (m_lock)
            {
                if (m_disposed)
                    throw new ObjectDisposedException(nameof(FileStreamCache));

                if (!m_entries.TryGetValue(path, out Entry? entry))
                {
                    entry = new Entry
                    {
                        Stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.RandomAccess)
                    };
                    entry.Node = m_lru.AddFirst(path);
                    m_entries[path] = entry;
                }
                else
                {
                    MoveToFront(entry);
                }

                entry.Active++;
                TryEvict();
                return new StreamLease(this, entry);
            }
        }

        private void Release(Entry entry)
        {
            lock (m_lock)
            {
                entry.Active = Math.Max(0, entry.Active - 1);
                MoveToFront(entry);
                TryEvict();
            }
        }

        private void MoveToFront(Entry entry)
        {
            if (entry.Node.List != null)
            {
                m_lru.Remove(entry.Node);
                entry.Node = m_lru.AddFirst(entry.Node.Value);
            }
        }

        private void TryEvict()
        {
            if (m_entries.Count <= m_capacity)
                return;

            LinkedListNode<string>? node = m_lru.Last;
            while (node != null && m_entries.Count > m_capacity)
            {
                string path = node.Value;
                LinkedListNode<string>? prev = node.Previous;
                Entry entry = m_entries[path];
                if (entry.Active == 0)
                {
                    m_entries.Remove(path);
                    m_lru.Remove(node);
                    entry.Stream.Dispose();
                }
                node = prev;
            }
        }

        public void Dispose()
        {
            lock (m_lock)
            {
                if (m_disposed)
                    return;

                foreach (var entry in m_entries.Values)
                {
                    entry.Stream.Dispose();
                }

                m_entries.Clear();
                m_lru.Clear();
                m_disposed = true;
            }
        }
    }
}
