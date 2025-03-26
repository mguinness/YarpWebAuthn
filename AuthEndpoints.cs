using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal class Hosts : Dictionary<string, Dictionary<string, string>>;

public static class AuthEndpoints
{
    public static void RegisterAuthEndpoints(this WebApplication app, ITimeLimitedDataProtector dataProtector)
    {
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

        auth.MapPost("existingkey", (HttpContext ctx, IMemoryCache cache, IOptionsMonitor<Hosts> hosts) =>
        {
            var origin = new Uri(ctx.Request.Headers.Origin);

            if (!hosts.CurrentValue.TryGetValue(origin.Host, out var creds) || creds.Count == 0)
            {
                return Results.Json(new { error = "not_configured" });
            }

            var challenge = cache.Set<string>(ctx.Connection.RemoteIpAddress, GenerateChallenge());

            var rpId = origin.Host;

            var allowCredentials = creds.Select(x => new { type = "public-key", id = x.Key });

            var userVerification = "preferred";

            //https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#retrieving_a_public_key_credential
            var publicKey = new { publicKey = new { allowCredentials, challenge, rpId, userVerification } };

            return Results.Json(publicKey);
        });

        auth.MapPost("validatekey", (JsonElement data, HttpContext ctx, IMemoryCache cache, IOptionsMonitor<Hosts> hosts) =>
        {
            var origin = new Uri(ctx.Request.Headers.Origin);

            string challenge = cache.Get<string>(ctx.Connection.RemoteIpAddress);

            string authenticatorData = data.GetProperty("authenticatorData").GetString();
            string clientDataJSON = data.GetProperty("clientDataJSON").GetString();
            var dataToVerify = GenerateComparison(authenticatorData, clientDataJSON);

            hosts.CurrentValue.TryGetValue(origin.Host, out var host);

            if (host.TryGetValue(data.GetProperty("id").GetString(), out var publicKey) &&
                IsDataValid(clientDataJSON, challenge.TrimEnd('='), origin.AbsoluteUri.TrimEnd('/')) &&
                IsSignatureValid(publicKey, data.GetProperty("signature").GetString(), dataToVerify))
            {
                string protectedPayload = dataProtector.Protect(ctx.Request.Headers.Host, DateTime.UtcNow.AddDays(1));
                ctx.Response.Cookies.Append("session", protectedPayload, new CookieOptions { HttpOnly = true, Secure = true, Expires = DateTime.UtcNow.AddDays(1) });
            }

            return Results.Ok();
        });
    }

    static string GenerateChallenge()
    {
        var randomString = RandomNumberGenerator.GetString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 16);
        var bytes = ASCIIEncoding.ASCII.GetBytes(randomString);
        return Convert.ToBase64String(bytes);
    }

    static byte[] GenerateComparison(string authenticatorData, string clientDataJSON)
    {
        var auth = Convert.FromBase64String(authenticatorData);
        var hash = SHA256.HashData(Convert.FromBase64String(clientDataJSON));

        var data = new byte[auth.Length + hash.Length];
        auth.CopyTo(data, 0);
        hash.CopyTo(data, auth.Length);

        return data;
    }

    static bool IsDataValid(string encodedData, string challenge, string origin)
    {
        var bytes = Convert.FromBase64String(encodedData);
        var data = ASCIIEncoding.ASCII.GetString(bytes);
        var clientData = JsonSerializer.Deserialize<JsonElement>(data);

        var typeValid = clientData.GetProperty("type").GetString().Equals("webauthn.get");
        var challengeValid = clientData.GetProperty("challenge").GetString().Equals(challenge);
        var originValid = clientData.GetProperty("origin").GetString().Equals(origin);

        return typeValid && challengeValid && originValid;
    }

    static bool IsSignatureValid(string publicKey, string signature, byte[] comparison)
    {
        var key = Convert.FromBase64String(publicKey);
        var sig = Convert.FromBase64String(signature);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(key, out _);

        return ecdsa.VerifyData(comparison, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
}