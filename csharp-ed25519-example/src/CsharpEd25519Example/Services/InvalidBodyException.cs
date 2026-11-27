namespace CsharpEd25519Example.Services;

public sealed class InvalidBodyException(string message, Exception innerException) : Exception(message, innerException);
