using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._13.Shared.Requests;
using Microsoft.Extensions.Caching.Distributed;
using Aaron.Pina.Blog.Article._13.Shared;
using Aaron.Pina.Blog.Article._13.Server;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStackExchangeRedisCache(Configuration.RedisCache.Options);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options);
builder.Services.AddAuthorization(Configuration.Authorisation.Options);
builder.Services.AddTransient<CredentialsValidator>();
builder.Services.AddTransient<UserValidator>();
builder.Services.AddScoped<TokenRepository>();
builder.Services.AddScoped<JwksKeyManager>();
builder.Services.AddScoped<AuthCodeService>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddDbContext<ServerDbContext>(Configuration.DbContext.Options);
builder.Services.Configure<JwksConfig>(builder.Configuration.GetSection(nameof(JwksConfig)));
builder.Services.Configure<TokenConfig>(builder.Configuration.GetSection(nameof(TokenConfig)));
builder.Services.Configure<AuthCodeConfig>(builder.Configuration.GetSection(nameof(AuthCodeConfig)));
builder.Services.Configure<UserCredentials>(builder.Configuration.GetSection(nameof(UserCredentials)));
builder.Services.Configure<ClientCredentials>(builder.Configuration.GetSection(nameof(ClientCredentials)));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<ServerDbContext>().Database.EnsureCreated();

app.MapGet("/.well-known/openid-configuration", () => Results.Json(
        new
        {
            Issuer                 = Api.UrlFor(Api.Audience.Server.Name),
            JwksUri                = $"{Api.UrlFor(Api.Audience.Server.Name)}/.well-known/jwks.json",
            AuthorizationEndpoint  = $"{Api.UrlFor(Api.Audience.Server.Name)}/authorize",
            TokenEndpoint          = $"{Api.UrlFor(Api.Audience.Server.Name)}/token",
            ResponseTypesSupported = new[] { "code" }
        },
        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower }))
   .AllowAnonymous();

app.MapGet("/.well-known/jwks.json", async (JwksKeyManager keyManager) =>
    {
        var jwks = await keyManager.GetAllPublicKeysAsync();
        return Results.Json(jwks);
    })
   .WithName("JWKS")
   .AllowAnonymous();

app.MapGet("/authorize",
   ([FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod,
    [FromQuery(Name = "code_challenge")] string? codeChallenge,
    [FromQuery(Name = "response_type")] string? responseType,
    [FromQuery(Name = "redirect_uri")] string? redirectUri,
    [FromQuery(Name = "client_id")] string? clientId,
    [FromQuery(Name = "scope")] string? scope,
    [FromQuery(Name = "state")] string? state,
    CredentialsValidator credentialsValidator) =>
    {
        if (responseType != "code") return Results.BadRequest("unsupported_response_type");
        if (string.IsNullOrEmpty(scope)
        ||  string.IsNullOrEmpty(clientId)
        ||  string.IsNullOrEmpty(redirectUri)
        ||  string.IsNullOrEmpty(codeChallenge)) return Results.BadRequest("invalid_request");
        if (!credentialsValidator.TryValidateRedirectUri(clientId, redirectUri))
            return Results.BadRequest("unauthorized_client");
        return Results.Content(LoginPage.Build(
            clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod ?? "S256"), "text/html");
    })
   .AllowAnonymous();

app.MapPost("/authorize", async
   ([FromForm(Name = "code_challenge_method")] string? codeChallengeMethod,
    [FromForm(Name = "code_challenge")] string? codeChallenge,
    [FromForm(Name = "redirect_uri")] string? redirectUri,
    [FromForm(Name = "client_id")] string? clientId,
    [FromForm(Name = "username")] string? username,
    [FromForm(Name = "password")] string? password,
    [FromForm(Name = "scope")] string? scope,
    [FromForm(Name = "state")] string? state,
    CredentialsValidator credentialsValidator,
    AuthCodeService authCodeService,
    UserValidator userValidator) =>
    {
        if (string.IsNullOrEmpty(scope)
        ||  string.IsNullOrEmpty(clientId)
        ||  string.IsNullOrEmpty(redirectUri)
        ||  string.IsNullOrEmpty(codeChallenge)) return Results.BadRequest("invalid_request");
        if (!credentialsValidator.TryValidateRedirectUri(clientId, redirectUri))
            return Results.BadRequest("unauthorized_client");
        if (!userValidator.TryValidate(username, password))
        {
            return Results.Content(LoginPage.Build(
                clientId, redirectUri, scope, state, codeChallenge,
                codeChallengeMethod ?? "S256", "Invalid username or password"), "text/html");
        }
        var scopes = ScopeParser.ExtractScopes(scope);
        if (ScopeParser.ExtractAudiences(scopes).Length != 1) return Results.BadRequest("invalid_scope");
        var grant = new AuthCodeGrant
        {
            Scopes = scopes,
            ClientId = clientId,
            Subject = username!,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod ?? "S256"
        };
        var authCode = await authCodeService.StoreAsync(grant);
        var location = new StringBuilder().Append(redirectUri).Append("?code=").Append(Uri.EscapeDataString(authCode.Value));
        if (state is not null) location.Append("&state=").Append(Uri.EscapeDataString(state));
        return Results.Redirect(location.ToString());
    })
   .DisableAntiforgery()
   .AllowAnonymous();

app.MapPost("/token", async
   ([FromForm(Name = "refresh_token")] string? refreshToken,
    [FromForm(Name = "client_secret")] string? clientSecret,
    [FromForm(Name = "code_verifier")] string? codeVerifier,
    [FromForm(Name = "redirect_uri")] string? redirectUri,
    [FromForm(Name = "grant_type")] string grantType,
    [FromForm(Name = "client_id")] string? clientId,
    [FromForm(Name = "scope")] string? scope,
    [FromForm(Name = "code")] string? code,
    TokenService tokenService) =>
    {
        if (string.IsNullOrEmpty(grantType)) return Results.BadRequest("invalid_grant");
        var result = grantType switch
        {
            "refresh_token"      => await tokenService.HandleRefreshTokenRequestAsync(refreshToken),
            "client_credentials" => await tokenService.HandleAccessTokenRequestAsync(clientId, clientSecret, scope),
            "authorization_code" => await tokenService.HandleAuthCodeExchangeAsync(code, redirectUri, clientId, codeVerifier, clientSecret),
            _                    => await Task.FromResult(TokenResult.Fail("unsupported_grant_type"))
        };
        if (result.IsSuccess) return Results.Ok(result.Tokens);
        return Results.BadRequest(result.Error);
    })
   .DisableAntiforgery()
   .AllowAnonymous();

app.MapPost("/rotate-key", async (JwksKeyManager keyManager) =>
    {
        var key = await keyManager.RotateSigningKeyAsync();
        return Results.Ok(new { Kid = key.KeyId, Message = "Key rotated successfully" });
    })
   .RequireAuthorization("admin");

app.MapPost("/revoke-key/{kid}", async (JwksKeyManager keyManager, string kid) =>
    {
        await keyManager.RevokeKeyAsync(kid);
        return Results.Ok(new { Message = $"Key {kid} has been revoked" });
    })
   .RequireAuthorization("admin");

app.MapPost("/blacklist", async (IDistributedCache blacklist, BlacklistRequest request) =>
    {
        var expires = DateTimeOffset.UtcNow.AddSeconds(request.AccessTokenExpiresIn);
        if (expires < DateTimeOffset.UtcNow) return Results.BadRequest("Token already expired");
        await blacklist.SetStringAsync(RedisKeys.Blacklist(request.Jti.ToString()), "revoked",
            new DistributedCacheEntryOptions { AbsoluteExpiration = expires });
        return Results.Ok();
    })
   .RequireAuthorization("admin");

app.Run();
