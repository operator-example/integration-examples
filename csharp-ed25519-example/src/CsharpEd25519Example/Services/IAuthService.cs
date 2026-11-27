namespace CsharpEd25519Example.Services;

public interface IAuthService
{
    SignedData Sign(byte[] body);

    bool Verify(VerifyRequest request, byte[] body);
}
