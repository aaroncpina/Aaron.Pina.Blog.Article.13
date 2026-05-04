using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Aaron.Pina.Blog.Article._13.Server;

public class AuthCodeService(IDistributedCache cache, IOptionsSnapshot<AuthCodeConfig> config)
{
    public async Task<AuthCode> StoreAsync(AuthCodeGrant grant)
    {
        var authCode = new AuthCode(TokenGenerator.GenerateAuthCode());
        var expiresAt = DateTime.UtcNow.Add(config.Value.Lifetime);
        await cache.SetStringAsync(
            RedisKeys.AuthCode(authCode.Value),
            JsonSerializer.Serialize(grant with { ExpiresAt = expiresAt }),
            new DistributedCacheEntryOptions { AbsoluteExpiration = expiresAt });
        return authCode;
    }

    public async Task<AuthCodeGrant?> RedeemAsync(AuthCode authCode)
    {
        var key = RedisKeys.AuthCode(authCode.Value);
        var json = await cache.GetStringAsync(key);
        if (json is null) return null;
        await cache.RemoveAsync(key);
        return JsonSerializer.Deserialize<AuthCodeGrant>(json);
    }
}
