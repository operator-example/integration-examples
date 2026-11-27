using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace CsharpEd25519Example.Tests;

public static class TestKeys
{
    public static readonly Ed25519PrivateKeyParameters Operator = new(Filled(1), 0);
    public static readonly Ed25519PrivateKeyParameters Root = new(Filled(2), 0);
    public const string KeyId = "test-key";
    public const string OperatorId = "test-operator";

    private static readonly SecureRandom Random = new();

    public static AuthOptions Options() => new()
    {
        KeyId = KeyId,
        OperatorId = OperatorId,
        PrivateKey = Convert.ToBase64String(Operator.GetEncoded()),
        RootPublicKey = Convert.ToBase64String(Root.GeneratePublicKey().GetEncoded()),
    };

    public static AuthService NewAuthService(TimeProvider timeProvider) =>
        new(Microsoft.Extensions.Options.Options.Create(Options()), new NonceStore(), timeProvider);

    public static Ed25519PrivateKeyParameters RandomKey() => new(Random);

    public static byte[] Sign(Ed25519PrivateKeyParameters key, byte[] data)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public static bool Verify(Ed25519PublicKeyParameters key, byte[] data, byte[] signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, key);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static byte[] Filled(byte value) => Enumerable.Repeat(value, 32).ToArray();
}
