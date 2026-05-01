using Aaron.Pina.Blog.Article._13.Shared.Responses;
using Aaron.Pina.Blog.Article._13.Shared;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Buffers.Text;
using System.Text;

namespace Aaron.Pina.Blog.Article._13.Server;

public class TokenService(
    TokenRepository tokenRepo,
    JwksKeyManager keyManager,
    AuthCodeService authCodeService,
    IOptionsSnapshot<TokenConfig> config,
    CredentialsValidator credentialsValidator)
{
    public async Task<TokenResult> HandleAccessTokenRequestAsync(string? clientId, string? clientSecret, string? scope)
    {
        if (string.IsNullOrEmpty(clientId))     return TokenResult.Fail("invalid_request");
        if (string.IsNullOrEmpty(clientSecret)) return TokenResult.Fail("invalid_request");
        if (!credentialsValidator.TryValidateCredentials(clientId, clientSecret)) return TokenResult.Fail("invalid_client");
        if (string.IsNullOrEmpty(scope)) return TokenResult.Fail("invalid_request");
        if (!ScopeParser.TryExtractValues(scope, out var audience, out var scopes)) return TokenResult.Fail("invalid_scope");
        if (!Api.IsValidTarget(audience)) return TokenResult.Fail("invalid_scope");
        var token = tokenRepo.TryGetTokenByClientIdAndAudience(clientId, audience);
        if (token is not null) return TokenResult.Fail("invalid_request");
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
        if (string.IsNullOrEmpty(refreshToken)) return TokenResult.Fail("invalid_request");
        var token = tokenRepo.TryGetTokenByRefreshToken(refreshToken);
        if (token is null) return TokenResult.Fail("invalid_grant");
        if (token.RefreshTokenExpiresAt < DateTime.UtcNow) return TokenResult.Fail("invalid_grant");
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

    public async Task<TokenResult> HandleAuthCodeExchangeAsync(
        string? code, string? redirectUri, string? clientId, string? codeVerifier)
    {
        if (string.IsNullOrEmpty(code)
        ||  string.IsNullOrEmpty(clientId)
        ||  string.IsNullOrEmpty(redirectUri)
        ||  string.IsNullOrEmpty(codeVerifier)) return TokenResult.Fail("invalid_request");
        var authCode = await authCodeService.RedeemAsync(code);
        if (authCode is null
        ||  authCode.ClientId != clientId
        ||  authCode.RedirectUri != redirectUri
        ||  authCode.ExpiresAt < DateTime.UtcNow
        || !VerifyCodeChallenge(codeVerifier, authCode)) return TokenResult.Fail("invalid_grant");
        var audiences = ScopeParser.ExtractAudiences(authCode.Scopes);
        if (audiences.Length != 1) return TokenResult.Fail("invalid_grant");
        var audience = audiences[0];
        if (!Api.IsValidTarget(audience)) return TokenResult.Fail("invalid_grant");
        var jti = Guid.NewGuid();
        var now = DateTime.UtcNow;
        var signingKey = await keyManager.GetOrCreateSigningKeyAsync();
        var refreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(
            signingKey, jti, authCode.Subject, audience, authCode.Scopes, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(jti, accessToken, refreshToken, config.Value.AccessTokenLifetime.TotalMinutes);
        var existing = tokenRepo.TryGetTokenByClientIdAndAudience(authCode.Subject, audience);
        var scope = string.Join(' ', authCode.Scopes);
        if (existing is not null)
        {
            existing.RefreshTokenExpiresAt = now.Add(config.Value.RefreshTokenLifetime);
            existing.RefreshToken = refreshToken;
            tokenRepo.UpdateToken(existing);
        }
        else
        {
            tokenRepo.SaveToken(new TokenEntity
            {
                RefreshTokenExpiresAt = now.Add(config.Value.RefreshTokenLifetime),
                RefreshToken = refreshToken,
                ClientId = clientId,
                Audience = audience,
                CreatedAt = now,
                Scope = scope
            });
        }
        return TokenResult.Success(response);
    }

    private static bool VerifyCodeChallenge(string codeVerifier, AuthCode authCode)
    {
        if (authCode.CodeChallengeMethod != "S256") return false;
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64Url.EncodeToString(hash) == authCode.CodeChallenge;
    }
}
