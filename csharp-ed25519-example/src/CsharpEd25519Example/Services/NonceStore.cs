namespace CsharpEd25519Example.Services;

public sealed class NonceStore
{
    public static readonly TimeSpan Retention = TimeSpan.FromMinutes(6);

    private readonly Lock _lock = new();
    private readonly Dictionary<string, long> _usedNonces = new();
    private readonly Queue<(string Nonce, long ExpiresAt)> _expiry = new();

    public bool TryMarkUsed(string nonce, long now)
    {
        lock (_lock)
        {
            while (_expiry.Count > 0 && _expiry.Peek().ExpiresAt < now)
            {
                _usedNonces.Remove(_expiry.Dequeue().Nonce);
            }

            var expiresAt = now + (long)Retention.TotalSeconds;
            if (!_usedNonces.TryAdd(nonce, expiresAt))
            {
                return false;
            }

            _expiry.Enqueue((nonce, expiresAt));
            return true;
        }
    }
}
