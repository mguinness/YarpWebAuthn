using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var cache = new MemoryCache(new MemoryCacheOptions());

var builder = WebApplication.CreateBuilder(args);

var hosts = builder.Configuration.GetSection("Hosts").Get<Dictionary<string, Dictionary<string, string>>>() ?? [];

var dataProtectionProvider = DataProtectionProvider.Create("yarpwebauthn");
var dataProtector = dataProtectionProvider.CreateProtector("securecookie").ToTimeLimitedDataProtector();

builder.Services.AddAuthentication("TokenAuthentication")
    .AddScheme<TokenAuthenticationOptions, TokenAuthenticationHandler>("TokenAuthentication", opts => opts.DataProtector = dataProtector);
builder.Services.AddAuthorization();

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

var auth = app.MapGroup("auth");

auth.MapGet("webauthn.js", () =>
{
    var path = Path.Combine(Environment.CurrentDirectory, "webauthn.js");
    return Results.File(path, MediaTypeNames.Text.JavaScript);
});

auth.MapGet("registerkey", () => {
    string html = "<body onload=\"registerkey()\"><script src=\"webauthn.js\"></script><div id=\"command\"/></body>";
    return Results.Content(html, MediaTypeNames.Text.Html);
});

auth.MapGet("login", () => {
    string html = "<body onload=\"existingKey()\"><script src=\"webauthn.js\"></script><div id=\"command\"/></body>";
    return Results.Content(html, MediaTypeNames.Text.Html);
});

auth.MapGet("logout", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete("session");
    ctx.Response.Redirect("/");
});

auth.MapPost("registerkey", (HttpContext ctx) =>
{
    var origin = new Uri(ctx.Request.Headers.Origin);

    var challenge = GenerateChallenge();

    var rp = new
    {
        id = origin.Host,
        name = "YARP Auth Server"
    };

    var user = new
    {
        id = "default",
        name = "Default user",
        displayName = "Default user"
    };

    var pubKeyCredParams = new[] {
        new {
            type = "public-key",
            alg = -7
        }
    };

    //https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#creating_a_public_key_credential
    var publicKey = new { publicKey = new { challenge, rp, user, pubKeyCredParams } };

    return Results.Json(publicKey);
});

auth.MapPost("existingkey", (HttpContext ctx) =>
{
    var origin = new Uri(ctx.Request.Headers.Origin);

    if (!hosts.ContainsKey(origin.Host))
    {
        return Results.Json(new { error = "not_configured" });
    }

    var challenge = cache.Set<string>(ctx.Connection.RemoteIpAddress, GenerateChallenge());

    var rpId = origin.Host;

    var allowCredentials = hosts[origin.Host].Select(x => new { type = "public-key", id = x.Key });

    var userVerification = "preferred";

    //https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#retrieving_a_public_key_credential
    var publicKey = new { publicKey = new { allowCredentials, challenge, rpId, userVerification } };

    return Results.Json(publicKey);
});

auth.MapPost("validatekey", (JsonElement data, HttpContext ctx) =>
{
    var origin = new Uri(ctx.Request.Headers.Origin);

    string challenge = cache.Get<string>(ctx.Connection.RemoteIpAddress);

    string authenticatorData = data.GetProperty("authenticatorData").GetString();
    string clientDataJSON = data.GetProperty("clientDataJSON").GetString();
    var dataToVerify = GenerateComparison(authenticatorData, clientDataJSON);

    hosts.TryGetValue(origin.Host, out var host);

    if (host.TryGetValue(data.GetProperty("id").GetString(), out var publicKey) &&
        IsDataValid(clientDataJSON, challenge.TrimEnd('='), origin.AbsoluteUri.TrimEnd('/')) &&
        IsSignatureValid(publicKey, data.GetProperty("signature").GetString(), dataToVerify))
    {
        string protectedPayload = dataProtector.Protect(ctx.Request.Headers.Host, DateTime.UtcNow.AddDays(1));
        ctx.Response.Cookies.Append("session", protectedPayload, new CookieOptions { HttpOnly = true, Secure = true, Expires = DateTime.UtcNow.AddDays(1) });
    }

    return Results.Ok();
});

app.Run("https://*:443");

string GenerateChallenge()
{
    var randomString = RandomNumberGenerator.GetString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 16);
    var bytes = ASCIIEncoding.ASCII.GetBytes(randomString);
    return Convert.ToBase64String(bytes);
}

bool IsDataValid(string encodedData, string challenge, string origin)
{
    var bytes = Convert.FromBase64String(encodedData);
    var data = ASCIIEncoding.ASCII.GetString(bytes);
    var clientData = JsonSerializer.Deserialize<JsonElement>(data);

    var typeValid = clientData.GetProperty("type").GetString().Equals("webauthn.get");
    var challengeValid = clientData.GetProperty("challenge").GetString().Equals(challenge);
    var originValid = clientData.GetProperty("origin").GetString().Equals(origin);

    return typeValid && challengeValid && originValid;
}

byte[] GenerateComparison(string authenticatorData, string clientDataJSON)
{
    var auth = Convert.FromBase64String(authenticatorData);
    using var sha256 = SHA256.Create();
    var hash = sha256.ComputeHash(Convert.FromBase64String(clientDataJSON));

    var data = new byte[auth.Length + hash.Length];
    auth.CopyTo(data, 0);
    hash.CopyTo(data, auth.Length);

    return data;
}

bool IsSignatureValid(string publicKey, string signature, byte[] comparison)
{
    var key = Convert.FromBase64String(publicKey);
    var sig = Convert.FromBase64String(signature);

    using var ecdsa = ECDsa.Create();
    ecdsa.ImportSubjectPublicKeyInfo(key, out _);

    return ecdsa.VerifyData(comparison, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
}
