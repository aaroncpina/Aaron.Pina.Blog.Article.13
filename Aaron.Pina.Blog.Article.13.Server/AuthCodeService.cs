using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Aaron.Pina.Blog.Article._13.Server;

public class AuthCodeService(IDistributedCache cache, IOptionsSnapshot<AuthCodeConfig> config)
{
    public async Task<string> StoreAsync(AuthCode authCode)
    {
        var code = TokenGenerator.GenerateAuthCode();
        var expiry = DateTimeOffset.UtcNow.Add(config.Value.Lifetime);
        await cache.SetStringAsync(
            RedisKeys.AuthCode(code),
            JsonSerializer.Serialize(authCode with { ExpiresAt = expiry.UtcDateTime }),
            new DistributedCacheEntryOptions { AbsoluteExpiration = expiry });
        return code;
    }

    public async Task<AuthCode?> RedeemAsync(string code)
    {
        var key = RedisKeys.AuthCode(code);
        var json = await cache.GetStringAsync(key);
        if (json is null) return null;
        await cache.RemoveAsync(key);
        return JsonSerializer.Deserialize<AuthCode>(json);
    }
}
