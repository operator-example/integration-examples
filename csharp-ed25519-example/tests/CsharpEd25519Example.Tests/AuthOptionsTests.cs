using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Options;

namespace CsharpEd25519Example.Tests;

public sealed class AuthOptionsTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private static readonly string ValidKey = Convert.ToBase64String(new byte[32]);

    private static IEnumerable<string> Errors(string keyId = "key", string operatorId = "operator", string? privateKey = null, string? rootPublicKey = null)
    {
        var options = new AuthOptions
        {
            KeyId = keyId,
            OperatorId = operatorId,
            PrivateKey = privateKey ?? ValidKey,
            RootPublicKey = rootPublicKey ?? ValidKey,
        };
        return new AuthOptionsValidator().Validate(null, options).Failures ?? [];
    }

    [Fact]
    public void ValidConfigHasNoErrors()
    {
        Assert.True(new AuthOptionsValidator().Validate(null, TestKeys.Options()).Succeeded);
        Assert.Empty(Errors());
    }

    [Fact]
    public void ReportsEveryMissingSettingAtOnce()
    {
        var errors = Errors(keyId: "", operatorId: " ", privateKey: "", rootPublicKey: "");

        Assert.Contains("KEY_ID is not set", errors);
        Assert.Contains("OPERATOR_ID is not set", errors);
        Assert.Contains("PRIVATE_KEY is not set", errors);
        Assert.Contains("ROOT_PUBLIC_KEY is not set", errors);
    }

    [Fact]
    public void RejectsInvalidBase64()
    {
        Assert.Contains("PRIVATE_KEY is not valid base64", Errors(privateKey: "not base64!!"));
    }

    [Theory]
    [InlineData("without padding")]
    [InlineData("with a space")]
    public void RejectsNonCanonicalBase64(string variant)
    {
        var key = variant == "without padding" ? ValidKey.TrimEnd('=') : ValidKey.Insert(4, " ");

        Assert.Contains("PRIVATE_KEY is not valid base64", Errors(privateKey: key));
    }

    [Fact]
    public void RejectsWrongKeyLength()
    {
        var error = Assert.Single(Errors(rootPublicKey: Convert.ToBase64String(new byte[31])));

        Assert.Contains("ROOT_PUBLIC_KEY must be a 32-byte", error);
        Assert.Contains("got 31 bytes", error);
    }

    [Fact]
    public void RejectsPkcs8InsteadOfRawKey()
    {
        var error = Assert.Single(Errors(privateKey: Convert.ToBase64String(new byte[48])));

        Assert.Equal("PRIVATE_KEY must be a 32-byte raw Ed25519 key, got 48 bytes", error);
    }

    [Fact]
    public void ErrorMessageNeverContainsTheSecret()
    {
        var secret = Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

        Assert.All(Errors(privateKey: secret), error => Assert.DoesNotContain(secret, error));
    }

    [Fact]
    public async Task AppStartsWithValidConfig()
    {
        var response = await factory.CreateClient().PostAsync("/Auth/sign", new StringContent("{}"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(["key_id", "operator_id", "payload", "signature"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(TestKeys.KeyId, json.RootElement.GetProperty("key_id").GetString());
        Assert.Equal(TestKeys.OperatorId, json.RootElement.GetProperty("operator_id").GetString());
    }

    [Fact]
    public async Task AppRefusesToStartWithBadConfig()
    {
        await using var badFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder
            .UseSetting("KEY_ID", "key")
            .UseSetting("OPERATOR_ID", "operator")
            .UseSetting("PRIVATE_KEY", Convert.ToBase64String(new byte[48]))
            .UseSetting("ROOT_PUBLIC_KEY", ""));

        var exception = Assert.Throws<OptionsValidationException>(() => badFactory.CreateClient());

        Assert.Contains("PRIVATE_KEY must be a 32-byte", exception.Message);
        Assert.Contains("ROOT_PUBLIC_KEY is not set", exception.Message);
    }
}
