using Aaron.Pina.Blog.Article._13.Shared.Responses;
using Aaron.Pina.Blog.Article._13.Shared;
using Microsoft.Extensions.Options;

namespace Aaron.Pina.Blog.Article._13.Server;

public class TokenService(
    TokenRepository tokenRepo,
    JwksKeyManager keyManager,
    IOptionsSnapshot<TokenConfig> config,
    CredentialsValidator credentialsValidator)
{
    public async Task<TokenResult> HandleAccessTokenRequestAsync(string? clientId, string? clientSecret, string? scope)
    {
        if (string.IsNullOrEmpty(clientId)) return TokenResult.Fail("ClientId is required");
        if (string.IsNullOrEmpty(clientSecret)) return TokenResult.Fail("Client Secret is required");
        if (!credentialsValidator.TryValidateCredentials(clientId, clientSecret)) return TokenResult.Fail("Invalid credentials");
        if (string.IsNullOrEmpty(scope)) return TokenResult.Fail("Scope is required");
        if (!ScopeParser.TryExtractValues(scope, out var audience, out var scopes)) return TokenResult.Fail("Invalid scope");
        if (!Api.IsValidTarget(audience)) return TokenResult.Fail("Invalid audience");
        var token = tokenRepo.TryGetTokenByClientIdAndAudience(clientId, audience);
        if (token is not null) return TokenResult.Fail("An active token exists for this audience");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var signingKey = await keyManager.GetOrCreateSigningKeyAsync();
        var refreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(
            signingKey, jti, clientId, audience, scopes, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(
            jti, accessToken, refreshToken, config.Value.AccessTokenLifetime.TotalMinutes);
        tokenRepo.SaveToken(new TokenEntity
        {
            RefreshTokenExpiresAt = now.Add(config.Value.RefreshTokenLifetime),
            RefreshToken = refreshToken,
            ClientId = clientId,
            Audience = audience,
            CreatedAt = now,
            Scope = scope
        });
        return TokenResult.Success(response);
    }

    public async Task<TokenResult> HandleRefreshTokenRequestAsync(string? refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken)) return TokenResult.Fail("Refresh token is required");
        var token = tokenRepo.TryGetTokenByRefreshToken(refreshToken);
        if (token is null) return TokenResult.Fail("Invalid refresh token");
        if (token.RefreshTokenExpiresAt < DateTime.UtcNow) return TokenResult.Fail("Refresh token has expired");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var signingKey = await keyManager.GetOrCreateSigningKeyAsync();
        var newRefreshToken = TokenGenerator.GenerateRefreshToken();
        var scopes = ScopeParser.ExtractScopes(token.Scope);
        var accessToken = TokenGenerator.GenerateToken(
            signingKey, jti, token.ClientId, token.Audience, scopes, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(
            jti, accessToken, newRefreshToken, config.Value.AccessTokenLifetime.TotalMinutes);
        token.RefreshTokenExpiresAt = now.Add(config.Value.RefreshTokenLifetime);
        token.RefreshToken = newRefreshToken;
        tokenRepo.UpdateToken(token);
        return TokenResult.Success(response);
    }
}
