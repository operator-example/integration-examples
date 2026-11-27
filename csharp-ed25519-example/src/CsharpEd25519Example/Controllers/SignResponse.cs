namespace CsharpEd25519Example.Controllers;

public sealed record SignResponse(string KeyId, string OperatorId, string Payload, string Signature);
