using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;

public class TokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public IDataProtector DataProtector { get; set; }
}

public class TokenAuthenticationHandler(IOptionsMonitor<TokenAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<TokenAuthenticationOptions>(options, logger, encoder)
{
    const string authScheme = "TokenAuthentication";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = AuthenticateResult.NoResult();

        try
        {
            var cookie = Request.Cookies["session"];
            if (!string.IsNullOrEmpty(cookie) && Options.DataProtector.Unprotect(cookie) == Request.Headers.Host)
            {
                var claims = new[] { new Claim(ClaimTypes.Name, "default") };
                var identity = new ClaimsIdentity(claims, authScheme);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, authScheme);

                result = AuthenticateResult.Success(ticket);
            }
        }
        catch (CryptographicException ex)
        {
            Response.Cookies.Delete("session");
            result = AuthenticateResult.Fail(ex);
        }

        return Task.FromResult(result);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Redirect("/auth/login");

        return Task.CompletedTask;
    }
}