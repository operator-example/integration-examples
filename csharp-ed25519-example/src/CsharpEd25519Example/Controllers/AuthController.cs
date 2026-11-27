using CsharpEd25519Example.Services;
using Microsoft.AspNetCore.Mvc;

namespace CsharpEd25519Example.Controllers;

[ApiController]
[Route("Auth")]
[BodyErrors]
[RequestSizeLimit(MaxBodySize)]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    public const int MaxBodySize = 8 << 20;

    [HttpPost("sign")]
    public async Task<SignResponse> Sign()
    {
        var signed = authService.Sign(await ReadBodyAsync());
        return new SignResponse(signed.KeyId, signed.OperatorId, signed.Payload, signed.Signature);
    }

    [HttpPost("verify")]
    public async Task<ActionResult<VerifyResponse>> Verify()
    {
        if (!authService.Verify(Request.Headers.ToVerifyRequest(), await ReadBodyAsync()))
        {
            return Unauthorized(new VerifyResponse(false));
        }

        return new VerifyResponse(true);
    }

    private async Task<byte[]> ReadBodyAsync()
    {
        using var buffer = new MemoryStream();
        try
        {
            await Request.Body.CopyToAsync(buffer, HttpContext.RequestAborted);
        }
        catch (BadHttpRequestException exception) when (exception.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            throw new BodyTooLargeException();
        }

        if (buffer.Length > MaxBodySize)
        {
            throw new BodyTooLargeException();
        }

        return buffer.ToArray();
    }
}
