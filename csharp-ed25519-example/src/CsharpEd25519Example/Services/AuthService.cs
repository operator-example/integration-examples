using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CsharpEd25519Example.Options;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace CsharpEd25519Example.Services;

public sealed class AuthService : IAuthService
{
    private const string ExpectedDomain = "five-gaming";
    private const long NonceMaxAgeSeconds = 5 * 60;
    private const long ClockSkewSeconds = 60;
    private static readonly Regex IntegerPattern = new(@"^-?[0-9]+\z", RegexOptions.CultureInvariant);
    private static readonly Regex Base64Pattern = new(@"^[A-Za-z0-9+/]*={0,2}\z", RegexOptions.CultureInvariant);
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private readonly string _keyId;
    private readonly string _operatorId;
    private readonly Ed25519PrivateKeyParameters _privateKey;
    private readonly byte[] _rootPublicKey;
    private readonly NonceStore _nonceStore;
    private readonly TimeProvider _timeProvider;

    public AuthService(IOptions<AuthOptions> options, NonceStore nonceStore, TimeProvider timeProvider)
    {
        _nonceStore = nonceStore;
        _timeProvider = timeProvider;
        _keyId = options.Value.KeyId;
        _operatorId = options.Value.OperatorId;
        _privateKey = new Ed25519PrivateKeyParameters(Convert.FromBase64String(options.Value.PrivateKey), 0);
        _rootPublicKey = Convert.FromBase64String(options.Value.RootPublicKey);
    }

    public SignedData Sign(byte[] body)
    {
        string data;
        try
        {
            data = StrictUtf8.GetString(body);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidBodyException("body is not valid UTF-8", exception);
        }

        var nonce = Guid.CreateVersion7(_timeProvider.GetUtcNow()).ToString();
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("data", data);
            writer.WriteString("nonce", nonce);
            writer.WriteEndObject();
        }

        var payload = buffer.ToArray();

        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        var signature = signer.GenerateSignature();

        return new SignedData(_keyId, _operatorId, Encoding.ASCII.GetString(payload), Convert.ToBase64String(signature));
    }

    public bool Verify(VerifyRequest request, byte[] body)
    {
        if (request.Version != "2")
        {
            return false;
        }

        if (!TryDecodeFromBase64(request.IntermediatePublicKey, 32, out var intermediatePublicKey))
        {
            return false;
        }

        if (!TryDecodeFromBase64(request.IntermediateSignature, 64, out var intermediateSignature))
        {
            return false;
        }

        if (!TryDecodeFromBase64(request.Signature, 64, out var signature))
        {
            return false;
        }

        if (!TryParseInteger(request.IntermediateNotBefore, out var notBefore))
        {
            return false;
        }

        if (!TryParseInteger(request.IntermediateNotAfter, out var notAfter))
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var certificate = string.Create(CultureInfo.InvariantCulture, $"{{\"not_after\":{notAfter},\"not_before\":{notBefore},\"public_key\":\"{Convert.ToBase64String(intermediatePublicKey)}\"}}");
        if (!Ed25519Verify(signature: intermediateSignature, publicKey: _rootPublicKey, data: Encoding.UTF8.GetBytes(certificate)))
        {
            return false;
        }

        if (now < notBefore || now > notAfter)
        {
            return false;
        }

        if (request.Payload is null)
        {
            return false;
        }

        var payload = Encoding.Latin1.GetBytes(request.Payload);
        if (!Ed25519Verify(signature: signature, publicKey: intermediatePublicKey, data: payload))
        {
            return false;
        }

        if (!SignedPayload.TryParse(payload, out var signedPayload))
        {
            return false;
        }

        if (signedPayload.Domain != ExpectedDomain || request.Domain != ExpectedDomain)
        {
            return false;
        }

        if (signedPayload.Nonce is null || signedPayload.Nonce != request.Nonce)
        {
            return false;
        }

        if (signedPayload.Data is null || !Encoding.UTF8.GetBytes(signedPayload.Data).AsSpan().SequenceEqual(body))
        {
            return false;
        }

        return IsNonceFresh(signedPayload.Nonce, now) && _nonceStore.TryMarkUsed(signedPayload.Nonce, now);
    }

    private static bool IsNonceFresh(string nonce, long now)
    {
        if (nonce.Length < 13)
        {
            return false;
        }

        if (!long.TryParse(nonce[..8] + nonce[9..13], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var unixMilli))
        {
            return false;
        }

        var signedAt = unixMilli / 1000;

        if (now - signedAt > NonceMaxAgeSeconds)
        {
            return false;
        }

        if (signedAt - now > ClockSkewSeconds)
        {
            return false;
        }

        return true;
    }

    private static bool Ed25519Verify(byte[] signature, byte[] publicKey, byte[] data)
    {
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool TryParseInteger(string? value, out long result)
    {
        result = 0;
        return value is not null
            && IntegerPattern.IsMatch(value)
            && long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out result);
    }

    private static bool TryDecodeFromBase64(string? value, int size, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        if (value is null || value.Length % 4 != 0 || !Base64Pattern.IsMatch(value))
        {
            return false;
        }

        var buffer = new byte[size];
        if (!Convert.TryFromBase64String(value, buffer, out var written) || written != size)
        {
            return false;
        }

        bytes = buffer;
        return true;
    }
}
