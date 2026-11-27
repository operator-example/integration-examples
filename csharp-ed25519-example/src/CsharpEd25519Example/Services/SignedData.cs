namespace CsharpEd25519Example.Services;

public sealed record SignedData(string KeyId, string OperatorId, string Payload, string Signature);
