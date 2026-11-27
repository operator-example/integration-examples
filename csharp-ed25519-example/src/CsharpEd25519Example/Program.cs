using System.Text;
using System.Text.Json;
using CsharpEd25519Example.Controllers;
using CsharpEd25519Example.Options;
using CsharpEd25519Example.Services;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.RequestHeaderEncodingSelector = _ => Encoding.Latin1;
    options.Limits.MaxRequestHeadersTotalSize = 8 << 20;
    options.Limits.MaxRequestBufferSize = null;
    options.Limits.MaxRequestBodySize = AuthController.MaxBodySize;
});

builder.Services.AddControllers()
    .AddJsonOptions(options => options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower);
builder.Services.AddOptions<AuthOptions>()
    .Bind(builder.Configuration)
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<AuthOptions>, AuthOptionsValidator>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<NonceStore>();
builder.Services.AddSingleton<IAuthService, AuthService>();

var app = builder.Build();

app.MapControllers();

AppDomain.CurrentDomain.UnhandledException += (_, _) => Environment.Exit(1);

app.Run();
