using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache();

builder.Configuration.AddJsonFile("config/customsettings.json", false, true);

builder.Services.Configure<Hosts>(builder.Configuration.GetSection("Hosts"));

var dataProtector = DataProtectionProvider.Create("yarpwebauthn")
    .CreateProtector("securecookie")
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

app.RegisterAuthEndpoints(dataProtector);

app.Run("https://*:8443");