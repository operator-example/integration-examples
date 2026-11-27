using System.Text;

namespace CsharpEd25519Example.Tests;

public class SignedPayloadTests
{
    private static bool TryParse(string payload, out SignedPayload? result) =>
        SignedPayload.TryParse(Encoding.Latin1.GetBytes(payload), out result);

    [Fact]
    public void ReadsStringFields()
    {
        Assert.True(TryParse("""{"data":"d","domain":"five-gaming","nonce":"n"}""", out var payload));
        Assert.Equal(new SignedPayload("five-gaming", "n", "d"), payload);
    }

    [Fact]
    public void NonStringFieldsAreNull()
    {
        Assert.True(TryParse("""{"data":1,"domain":null,"nonce":["n"]}""", out var payload));
        Assert.Equal(new SignedPayload(null, null, null), payload);
    }

    [Fact]
    public void LastDuplicateKeyWins()
    {
        Assert.True(TryParse("""{"data":"first","data":"last"}""", out var payload));
        Assert.Equal("last", payload!.Data);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1,2]")]
    [InlineData("""{"data":"\udcff"}""")]
    [InlineData("""{"x":"\udcff"}""")]
    [InlineData("\u00EF\u00BB\u00BF{}")]
    [InlineData("{\"data\":\"\u00FF\"}")]
    public void RejectsMalformedPayloads(string payload) => Assert.False(TryParse(payload, out _));

    [Fact]
    public void AcceptsSixtyFourLevelsAndRejectsSixtyFive()
    {
        Assert.True(TryParse("{\"x\":" + new string('[', 63) + new string(']', 63) + "}", out _));
        Assert.False(TryParse("{\"x\":" + new string('[', 64) + new string(']', 64) + "}", out _));
    }
}
