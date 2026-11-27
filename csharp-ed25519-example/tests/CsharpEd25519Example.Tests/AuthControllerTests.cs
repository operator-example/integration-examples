using System.Net;

namespace CsharpEd25519Example.Tests;

public sealed class AuthControllerTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task SignReturnsBadRequestForInvalidUtf8()
    {
        var response = await _client.PostAsync("/Auth/sign", new ByteArrayContent([0xFF]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("{\"error\":\"body is not valid UTF-8\"}", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/Auth/sign")]
    [InlineData("/Auth/verify")]
    public async Task ReturnsPayloadTooLargeOverTheLimit(string path)
    {
        var response = await _client.PostAsync(path, new ByteArrayContent(Body(AuthController.MaxBodySize + 1)));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal("{\"error\":\"body is too large\"}", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SignAcceptsBodyAtTheLimit()
    {
        var response = await _client.PostAsync("/Auth/sign", new ByteArrayContent(Body(AuthController.MaxBodySize)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task VerifyReturnsUnauthorizedWithoutHeaders()
    {
        var response = await _client.PostAsync("/Auth/verify", new StringContent("{}"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("{\"verified\":false}", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SignTreatsFormBodyAsRawBytes()
    {
        var response = await _client.PostAsync("/Auth/sign", new StringContent("a=b", null, "application/x-www-form-urlencoded"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\\\"data\\\":\\\"a=b\\\"", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task OversizedFormBodyReturnsPayloadTooLarge()
    {
        var content = new ByteArrayContent(Body(AuthController.MaxBodySize + 1));
        content.Headers.ContentType = new("application/x-www-form-urlencoded");

        var response = await _client.PostAsync("/Auth/sign", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal("{\"error\":\"body is too large\"}", await response.Content.ReadAsStringAsync());
    }

    private static byte[] Body(int size) => Enumerable.Repeat((byte)'a', size).ToArray();
}
