using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace CsharpEd25519Example.Options;

public sealed class AuthOptionsValidator : IValidateOptions<AuthOptions>
{
    private const int KeyLength = 32;
    private static readonly Regex Base64Pattern = new(@"^[A-Za-z0-9+/]*={0,2}\z", RegexOptions.CultureInvariant);

    public ValidateOptionsResult Validate(string? name, AuthOptions options)
    {
        var errors = new List<string>();
        RequireNonBlank(errors, "KEY_ID", options.KeyId);
        RequireNonBlank(errors, "OPERATOR_ID", options.OperatorId);
        RequireKey(errors, "PRIVATE_KEY", options.PrivateKey);
        RequireKey(errors, "ROOT_PUBLIC_KEY", options.RootPublicKey);
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    private static void RequireNonBlank(List<string> errors, string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"{name} is not set");
        }
    }

    private static void RequireKey(List<string> errors, string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"{name} is not set");
            return;
        }

        if (value.Length % 4 != 0 || !Base64Pattern.IsMatch(value))
        {
            errors.Add($"{name} is not valid base64");
            return;
        }

        var key = Convert.FromBase64String(value);

        if (key.Length != KeyLength)
        {
            errors.Add($"{name} must be a {KeyLength}-byte raw Ed25519 key, got {key.Length} bytes");
        }
    }
}
