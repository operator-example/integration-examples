using CsharpEd25519Example.Services;

namespace CsharpEd25519Example.Controllers;

public static class VerifyRequestHeaders
{
    public static VerifyRequest ToVerifyRequest(this IHeaderDictionary headers) => new(
        headers.Single("X-Sign-Version"),
        headers.Single("X-Sign-Domain"),
        headers.Single("X-Sign-Nonce"),
        headers.Single("X-Sign-Payload"),
        headers.Single("X-Sign-Signature"),
        headers.Single("X-Sign-Intermediate-Public-Key"),
        headers.Single("X-Sign-Intermediate-Signature"),
        headers.Single("X-Sign-Intermediate-Not-Before"),
        headers.Single("X-Sign-Intermediate-Not-After"));

    private static string? Single(this IHeaderDictionary headers, string name) =>
        headers.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;
}
