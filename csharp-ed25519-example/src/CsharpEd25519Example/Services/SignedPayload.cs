using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace CsharpEd25519Example.Services;

public sealed record SignedPayload(string? Domain, string? Nonce, string? Data)
{
    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = 64 };

    public static bool TryParse(byte[] payload, [NotNullWhen(true)] out SignedPayload? result)
    {
        result = null;
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload, ParseOptions);
        }
        catch (JsonException)
        {
            return false;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !IsWellFormed(root))
            {
                return false;
            }

            result = new SignedPayload(StringProperty(root, "domain"), StringProperty(root, "nonce"), StringProperty(root, "data"));
            return true;
        }
    }

    private static string? StringProperty(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool IsWellFormed(JsonElement element)
    {
        try
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        _ = property.Name;
                        if (!IsWellFormed(property.Value))
                        {
                            return false;
                        }
                    }

                    return true;
                case JsonValueKind.Array:
                    return element.EnumerateArray().All(IsWellFormed);
                case JsonValueKind.String:
                    _ = element.GetString();
                    return true;
                default:
                    return true;
            }
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
