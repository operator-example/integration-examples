using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Crypto.Parameters;

namespace CsharpEd25519Example.Tests;

public sealed class AuthServiceVerifyTests
{
    private static readonly JsonSerializerOptions RawUtf8 = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_767_225_600_123);
    private static readonly long NowMillis = Now.ToUnixTimeMilliseconds();
    private static readonly long NowSeconds = Now.ToUnixTimeSeconds();

    private readonly FakeTimeProvider _time = new(Now);
    private readonly AuthService _authService;

    public AuthServiceVerifyTests()
    {
        _authService = TestKeys.NewAuthService(_time);
    }

    private sealed record Request
    {
        public string Body { get; init; } = "{\"amount\":100}";
        public object? Data { get; init; }
        public string PayloadDomain { get; init; } = "five-gaming";
        public string HeaderDomain { get; init; } = "five-gaming";
        public string Nonce { get; init; } = NonceAt(NowMillis);
        public long NotBefore { get; init; } = NowSeconds - 60;
        public long NotAfter { get; init; } = NowSeconds + 3600;
        public Ed25519PrivateKeyParameters Root { get; init; } = TestKeys.Root;
        public Ed25519PrivateKeyParameters? PayloadSigner { get; init; }
        public byte[]? PayloadOverride { get; init; }

        public Request WithRawPayload(string json) => this with { PayloadOverride = Encoding.Latin1.GetBytes(json.Replace("NONCE", Nonce)) };

        public Request WithNestedPayload(int depth) =>
            WithRawPayload("{\"data\":\"{\\\"amount\\\":100}\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\",\"x\":"
            + new string('[', depth - 1) + new string(']', depth - 1) + "}");

        public byte[] BodyBytes => Encoding.UTF8.GetBytes(Body);

        public HeaderDictionary Headers()
        {
            var intermediate = TestKeys.RandomKey();
            var intermediatePublicKey = Convert.ToBase64String(intermediate.GeneratePublicKey().GetEncoded());
            var certificate = string.Create(CultureInfo.InvariantCulture, $"{{\"not_after\":{NotAfter},\"not_before\":{NotBefore},\"public_key\":\"{intermediatePublicKey}\"}}");

            var payload = PayloadOverride ?? JsonSerializer.SerializeToUtf8Bytes(
                new Dictionary<string, object?> { ["data"] = Data ?? Body, ["domain"] = PayloadDomain, ["nonce"] = Nonce }, RawUtf8);

            return new HeaderDictionary
            {
                ["X-Sign-Version"] = "2",
                ["X-Sign-Domain"] = HeaderDomain,
                ["X-Sign-Nonce"] = Nonce,
                ["X-Sign-Payload"] = Encoding.Latin1.GetString(payload),
                ["X-Sign-Signature"] = Convert.ToBase64String(TestKeys.Sign(PayloadSigner ?? intermediate, payload)),
                ["X-Sign-Intermediate-Public-Key"] = intermediatePublicKey,
                ["X-Sign-Intermediate-Signature"] = Convert.ToBase64String(TestKeys.Sign(Root, Encoding.UTF8.GetBytes(certificate))),
                ["X-Sign-Intermediate-Not-Before"] = NotBefore.ToString(CultureInfo.InvariantCulture),
                ["X-Sign-Intermediate-Not-After"] = NotAfter.ToString(CultureInfo.InvariantCulture),
            };
        }
    }

    private static string NonceAt(long unixMilli)
    {
        var hex = unixMilli.ToString("x12");
        var random = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        return $"{hex[..8]}-{hex[8..12]}-7{random[..3]}-8{random[3..6]}-{random[4..16]}";
    }

    private bool Verify(Request? request = null, Action<HeaderDictionary>? tamper = null)
    {
        request ??= new Request();
        var headers = request.Headers();
        tamper?.Invoke(headers);
        return _authService.Verify(headers.ToVerifyRequest(), request.BodyBytes);
    }

    [Fact]
    public void ValidRequest() => Assert.True(Verify());

    [Fact]
    public void UnicodeBodyWithRawUtf8Payload() => Assert.True(Verify(new Request { Body = "{\"name\":\"Joë’s Café — €5\",\"emoji\":\"🎰\"}" }));

    [Fact]
    public void EmptyBody() => Assert.True(Verify(new Request { Body = "" }));

    [Fact]
    public void NonceSlightlyInFutureWithinClockSkew() => Assert.True(Verify(new Request { Nonce = NonceAt(NowMillis + 30_000) }));

    [Fact]
    public void ReplayedRequest()
    {
        var request = new Request();
        var headers = request.Headers();

        Assert.True(_authService.Verify(headers.ToVerifyRequest(), request.BodyBytes));
        Assert.False(_authService.Verify(headers.ToVerifyRequest(), request.BodyBytes));
    }

    [Fact]
    public void TamperedBody()
    {
        var request = new Request();
        Assert.False(_authService.Verify(request.Headers().ToVerifyRequest(), "{\"amount\":999}"u8.ToArray()));
    }

    [Fact]
    public void NoHeadersAtAll() => Assert.False(_authService.Verify(new HeaderDictionary().ToVerifyRequest(), []));

    [Fact]
    public void WrongVersion() => Assert.False(Verify(tamper: h => h["X-Sign-Version"] = "1"));

    [Fact]
    public void DuplicatedHeader() =>
        Assert.False(Verify(tamper: h => h["X-Sign-Signature"] = new StringValues([h["X-Sign-Signature"].ToString(), h["X-Sign-Signature"].ToString()])));

    [Fact]
    public void MissingSignature() => Assert.False(Verify(tamper: h => h.Remove("X-Sign-Signature")));

    [Fact]
    public void SignatureNotBase64() => Assert.False(Verify(tamper: h => h["X-Sign-Signature"] = "not-base64!!"));

    [Fact]
    public void SignatureWrongLength() => Assert.False(Verify(tamper: h => h["X-Sign-Signature"] = Convert.ToBase64String(new byte[63])));

    [Fact]
    public void PayloadSignedByOtherKey() => Assert.False(Verify(new Request { PayloadSigner = TestKeys.RandomKey() }));

    [Fact]
    public void CertificateSignedByOtherRoot() => Assert.False(Verify(new Request { Root = TestKeys.RandomKey() }));

    [Fact]
    public void CertificateValidityExtendedAfterSigning() => Assert.False(Verify(tamper: h => h["X-Sign-Intermediate-Not-After"] = "9999999999"));

    [Fact]
    public void CertificateNotAfterNotANumber() => Assert.False(Verify(tamper: h => h["X-Sign-Intermediate-Not-After"] = "soon"));

    [Fact]
    public void CertificateExpired() => Assert.False(Verify(new Request { NotAfter = NowSeconds - 1 }));

    [Fact]
    public void CertificateNotYetValid() => Assert.False(Verify(new Request { NotBefore = NowSeconds + 600 }));

    [Fact]
    public void CertificateExpiresAsClockAdvances()
    {
        var request = new Request { NotAfter = NowSeconds + 10 };
        _time.Advance(TimeSpan.FromSeconds(11));

        Assert.False(Verify(request));
    }

    [Fact]
    public void NonceGoesStaleAsClockAdvances()
    {
        var request = new Request();
        _time.Advance(TimeSpan.FromMinutes(6));

        Assert.False(Verify(request));
    }

    [Fact]
    public void MissingPayload() => Assert.False(Verify(tamper: h => h.Remove("X-Sign-Payload")));

    [Fact]
    public void PayloadNotJson() => Assert.False(Verify(new Request { PayloadOverride = "not json"u8.ToArray() }));

    [Fact]
    public void PayloadIsJsonArray() => Assert.False(Verify(new Request { PayloadOverride = "[1,2]"u8.ToArray() }));

    [Fact]
    public void DataIsNotString() => Assert.False(Verify(new Request { Data = 100 }));

    [Fact]
    public void PayloadDomainMismatch() => Assert.False(Verify(new Request { PayloadDomain = "evil" }));

    [Fact]
    public void HeaderDomainMismatch() => Assert.False(Verify(new Request { HeaderDomain = "evil" }));

    [Fact]
    public void NonceHeaderMismatch() => Assert.False(Verify(tamper: h => h["X-Sign-Nonce"] = NonceAt(NowMillis)));

    [Fact]
    public void NonceTooOld() => Assert.False(Verify(new Request { Nonce = NonceAt(NowMillis - 6 * 60_000) }));

    [Fact]
    public void NonceTooFarInFuture() => Assert.False(Verify(new Request { Nonce = NonceAt(NowMillis + 2 * 60_000) }));

    [Fact]
    public void NonceTooShort() => Assert.False(Verify(new Request { Nonce = "abc" }));

    [Fact]
    public void NonceNotHex() => Assert.False(Verify(new Request { Nonce = "zzzzzzzz-zzzz-7zzz-8zzz-zzzzzzzzzzzz" }));

    [Fact]
    public void PayloadKeysDifferInCase() =>
        Assert.False(Verify(new Request().WithRawPayload("""{"DATA":"{\"amount\":100}","Domain":"five-gaming","Nonce":"NONCE"}""")));

    [Fact]
    public void ValidSurrogatePairInData() =>
        Assert.True(Verify(new Request { Body = "\U0001F680" }.WithRawPayload("""{"data":"\ud83d\ude80","domain":"five-gaming","nonce":"NONCE"}""")));

    [Theory]
    [InlineData("data")]
    [InlineData("domain")]
    [InlineData("nonce")]
    [InlineData("x")]
    public void LoneSurrogateIsRejected(string key)
    {
        var fields = new Dictionary<string, string> { ["data"] = "\\ufffd", ["domain"] = "five-gaming", ["nonce"] = "NONCE" };
        fields[key] = "\\udcff";
        var json = "{" + string.Join(",", fields.Select(f => $"\"{f.Key}\":\"{f.Value}\"")) + "}";

        Assert.False(Verify(new Request { Body = "\uFFFD" }.WithRawPayload(json)));
    }

    [Fact]
    public void InvalidUtf8ByteInPayload() =>
        Assert.False(Verify(new Request { Body = "\uFFFD" }.WithRawPayload("{\"data\":\"\u00ff\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}")));

    [Fact]
    public void PayloadStartsWithByteOrderMark() =>
        Assert.False(Verify(new Request().WithRawPayload("\u00EF\u00BB\u00BF{\"data\":\"{\\\"amount\\\":100}\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}")));

    [Fact]
    public void NotBeforeWithPlusSign() =>
        Assert.False(Verify(tamper: h => h["X-Sign-Intermediate-Not-Before"] = "+" + h["X-Sign-Intermediate-Not-Before"]));

    [Fact]
    public void SignatureBase64WithSpaceInside() =>
        Assert.False(Verify(tamper: h => h["X-Sign-Signature"] = h["X-Sign-Signature"].ToString().Insert(4, " ")));

    [Fact]
    public void SignatureBase64WithoutPadding() =>
        Assert.False(Verify(tamper: h => h["X-Sign-Signature"] = h["X-Sign-Signature"].ToString().TrimEnd('=')));

    [Fact]
    public void NegativeNotBeforeVerifiesUnderCultureWithNonAsciiMinusSign()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("sv-SE");
            Assert.Equal("\u2212", CultureInfo.CurrentCulture.NumberFormat.NegativeSign);

            Assert.True(Verify(new Request { NotBefore = -1 }));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void PayloadNested64LevelsDeep() => Assert.True(Verify(new Request().WithNestedPayload(64)));

    [Fact]
    public void PayloadNested65LevelsDeep() => Assert.False(Verify(new Request().WithNestedPayload(65)));

    [Fact]
    public void BracketsInsideStringsDoNotCountAsNesting() =>
        Assert.True(Verify(new Request { Body = new string('[', 100) + "\\\"" + new string('{', 100) }));
}
