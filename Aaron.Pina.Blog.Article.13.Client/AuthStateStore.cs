using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Buffers.Text;

namespace Aaron.Pina.Blog.Article._13.Client;

public class AuthStateStore
{
    private readonly ConcurrentDictionary<string, PendingAuth> _pending = new();

    public string Add(PendingAuth pending)
    {
        var state = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        _pending[state] = pending;
        return state;
    }

    public PendingAuth? Consume(string state)
    {
        _pending.TryRemove(state, out var pending);
        return pending;
    }
}
