namespace CsharpEd25519Example.Tests;

public class NonceStoreTests
{
    private const long Now = 1_700_000_000;

    private readonly NonceStore _store = new();

    [Fact]
    public void FirstUseSucceeds() => Assert.True(_store.TryMarkUsed("a", Now));

    [Fact]
    public void ReuseWithinRetentionFails()
    {
        _store.TryMarkUsed("a", Now);

        Assert.False(_store.TryMarkUsed("a", Now + 360));
    }

    [Fact]
    public void ReuseAfterRetentionSucceeds()
    {
        _store.TryMarkUsed("a", Now);

        Assert.True(_store.TryMarkUsed("a", Now + 361));
    }

    [Fact]
    public void DifferentNoncesAreIndependent()
    {
        _store.TryMarkUsed("a", Now);

        Assert.True(_store.TryMarkUsed("b", Now));
    }
}
