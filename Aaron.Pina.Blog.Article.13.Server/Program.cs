using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._13.Shared.Requests;
using Microsoft.Extensions.Caching.Distributed;
using Aaron.Pina.Blog.Article._13.Shared;
using Aaron.Pina.Blog.Article._13.Server;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStackExchangeRedisCache(Configuration.RedisCache.Options);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options);
builder.Services.AddAuthorization(Configuration.Authorisation.Options);
builder.Services.AddTransient<CredentialsValidator>();
builder.Services.AddScoped<TokenRepository>();
builder.Services.AddScoped<JwksKeyManager>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddDbContext<ServerDbContext>(Configuration.DbContext.Options);
builder.Services.Configure<JwksConfig>(builder.Configuration.GetSection(nameof(JwksConfig)));
builder.Services.Configure<TokenConfig>(builder.Configuration.GetSection(nameof(TokenConfig)));
builder.Services.Configure<ClientCredentials>(builder.Configuration.GetSection(nameof(ClientCredentials)));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<ServerDbContext>().Database.EnsureCreated();

app.MapGet("/.well-known/openid-configuration", () => Results.Json(
        new
        {
            Issuer  = Api.UrlFor(Api.Audience.Server.Name),
            JwksUri = $"{Api.UrlFor(Api.Audience.Server.Name)}/.well-known/jwks.json"
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

app.MapPost("/token", async
   ([FromForm(Name = "grant_type")] string grantType,
    [FromForm(Name = "refresh_token")] string? refreshToken,
    [FromForm(Name = "client_secret")] string? clientSecret,
    [FromForm(Name = "client_id")] string? clientId,
    [FromForm(Name = "scope")] string? scope,
    TokenService tokenService) =>
    {
        if (string.IsNullOrEmpty(grantType)) return Results.BadRequest("invalid_grant");
        var result = grantType switch
        {
            "client_credentials" => await tokenService.HandleAccessTokenRequestAsync(clientId, clientSecret, scope),
            "refresh_token"      => await tokenService.HandleRefreshTokenRequestAsync(refreshToken),
            _                    => await Task.FromResult(TokenResult.Fail("invalid_grant"))
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
