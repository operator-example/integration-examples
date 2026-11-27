using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Time.Testing;

namespace CsharpEd25519Example.Tests;

public sealed class AuthServiceSignTests
{
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeMilliseconds(1_767_225_600_123));
    private readonly AuthService _authService;

    public AuthServiceSignTests()
    {
        _authService = TestKeys.NewAuthService(_time);
    }

    public static TheoryData<string, string, string> PayloadCases()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var c in LoadCases(rejected: false))
        {
            data.Add(c.GetProperty("name").GetString()!, c.GetProperty("bodyHex").GetString()!, c.GetProperty("expectedData").GetString()!);
        }

        return data;
    }

    public static TheoryData<string, string> RejectedCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var c in LoadCases(rejected: true))
        {
            data.Add(c.GetProperty("name").GetString()!, c.GetProperty("bodyHex").GetString()!);
        }

        return data;
    }

    private static List<JsonElement> LoadCases(bool rejected)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "payload-escaping-cases.json")));
        return document.RootElement.GetProperty("cases").EnumerateArray()
            .Where(c => (c.TryGetProperty("rejected", out var value) && value.GetBoolean()) == rejected)
            .Select(c => c.Clone())
            .ToList();
    }

    [Fact]
    public void SharedFixtureHasMoreThan100PayloadCases()
    {
        Assert.True(PayloadCases().Count() > 100);
    }

    [Fact]
    public void SharedFixtureHasRejectedCases()
    {
        Assert.NotEmpty(RejectedCases());
    }

    [Theory]
    [MemberData(nameof(RejectedCases))]
    public void RejectsInvalidUtf8(string name, string bodyHex)
    {
        var exception = Record.Exception(() => _authService.Sign(Convert.FromHexString(bodyHex)));

        Assert.True(exception is InvalidBodyException, $"case '{name}' should be rejected as invalid UTF-8");
    }

    [Fact]
    public void KeepsLeadingByteOrderMark()
    {
        var signed = _authService.Sign([0xEF, 0xBB, 0xBF, (byte)'a']);

        Assert.StartsWith("{\"data\":\"\\uFEFFa\",", signed.Payload, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(PayloadCases))]
    public void PayloadMatchesBaseline(string name, string bodyHex, string expectedData)
    {
        var signed = _authService.Sign(Convert.FromHexString(bodyHex));

        var prefix = "{\"data\":\"" + expectedData + "\",\"nonce\":\"";
        Assert.True(signed.Payload.StartsWith(prefix, StringComparison.Ordinal), $"case '{name}': expected payload to start with {prefix} but was {signed.Payload}");
        Assert.EndsWith("\"}", signed.Payload, StringComparison.Ordinal);
        AssertSignedByOperator(signed);
    }

    [Fact]
    public void ReturnsConfiguredIds()
    {
        var signed = _authService.Sign("{}"u8.ToArray());

        Assert.Equal(TestKeys.KeyId, signed.KeyId);
        Assert.Equal(TestKeys.OperatorId, signed.OperatorId);
    }

    [Fact]
    public void NonceIsCurrentUuidV7()
    {
        _time.Advance(TimeSpan.FromMilliseconds(4_321));
        var signed = _authService.Sign([]);

        var nonce = Regex.Match(signed.Payload, "\"nonce\":\"([^\"]+)\"").Groups[1].Value;
        Assert.Matches("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", nonce);
        var unixMilli = Convert.ToInt64(nonce[..8] + nonce[9..13], 16);
        Assert.Equal(_time.GetUtcNow().ToUnixTimeMilliseconds(), unixMilli);
    }

    [Fact]
    public void EverySignatureUsesFreshNonce()
    {
        var body = "same"u8.ToArray();

        Assert.NotEqual(_authService.Sign(body).Payload, _authService.Sign(body).Payload);
    }

    private static void AssertSignedByOperator(SignedData signed)
    {
        var payload = Encoding.ASCII.GetBytes(signed.Payload);
        Assert.True(TestKeys.Verify(TestKeys.Operator.GeneratePublicKey(), payload, Convert.FromBase64String(signed.Signature)));
    }
}
