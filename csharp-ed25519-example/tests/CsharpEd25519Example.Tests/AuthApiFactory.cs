using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace CsharpEd25519Example.Tests;

public sealed class AuthApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var options = TestKeys.Options();
        builder
            .UseSetting("KEY_ID", options.KeyId)
            .UseSetting("OPERATOR_ID", options.OperatorId)
            .UseSetting("PRIVATE_KEY", options.PrivateKey)
            .UseSetting("ROOT_PUBLIC_KEY", options.RootPublicKey);
    }
}
