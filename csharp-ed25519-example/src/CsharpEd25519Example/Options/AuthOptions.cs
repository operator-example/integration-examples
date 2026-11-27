namespace CsharpEd25519Example.Options;

public sealed class AuthOptions
{
    [ConfigurationKeyName("KEY_ID")]
    public string KeyId { get; set; } = string.Empty;

    [ConfigurationKeyName("OPERATOR_ID")]
    public string OperatorId { get; set; } = string.Empty;

    [ConfigurationKeyName("PRIVATE_KEY")]
    public string PrivateKey { get; set; } = string.Empty;

    [ConfigurationKeyName("ROOT_PUBLIC_KEY")]
    public string RootPublicKey { get; set; } = string.Empty;
}
