namespace CsharpEd25519Example.Services;

public sealed record VerifyRequest(
    string? Version,
    string? Domain,
    string? Nonce,
    string? Payload,
    string? Signature,
    string? IntermediatePublicKey,
    string? IntermediateSignature,
    string? IntermediateNotBefore,
    string? IntermediateNotAfter);
