using Aaron.Pina.Blog.Article._13.Shared;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Buffers.Text;

namespace Aaron.Pina.Blog.Article._13.Server;

public static class TokenGenerator
{
    public static string GenerateToken(
        RsaSecurityKey rsaKey,
        Guid jti,
        string clientId,
        string audience,
        string[] scopes,
        DateTime now,
        TimeSpan expiresIn)
    {
        List<Claim> claims = [
            new("sub", clientId),
            new("jti", jti.ToString())
        ];
        claims.AddRange(scopes.Select(scope => new Claim("scope", scope)));
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            IssuedAt = now,
            Audience = audience,
            Expires = now.Add(expiresIn),
            Subject = new ClaimsIdentity(claims),
            Issuer = Api.UrlFor(Api.Audience.Server.Name),
            SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
        };
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }

    public static string GenerateRefreshToken()  => GenerateOpaqueToken();
    
    public static string GenerateAuthCode()      => GenerateOpaqueToken();

    private static string GenerateOpaqueToken(int length = 32) =>
        Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(length));
}
