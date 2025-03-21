using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache();

var dataProtectionProvider = DataProtectionProvider.Create("yarpwebauthn");

var dataProtector = dataProtectionProvider.CreateProtector("securecookie")
    .ToTimeLimitedDataProtector();

builder.Services.AddAuthentication("TokenAuthentication")
    .AddScheme<TokenAuthenticationOptions, TokenAuthenticationHandler>("TokenAuthentication", opts => opts.DataProtector = dataProtector);

builder.Services.AddAuthorization();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseAuthentication();

app.UseAuthorization();

app.MapReverseProxy();

app.RegisterAuthEndpoints(builder.Configuration.GetSection("Hosts"), dataProtector);

app.Run("https://*:443");