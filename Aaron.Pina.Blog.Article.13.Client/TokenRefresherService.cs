using Aaron.Pina.Blog.Article._13.Shared.Responses;

namespace Aaron.Pina.Blog.Article._13.Client;

public class TokenRefresherService(
    IHttpClientFactory factory,
    IServiceProvider serviceProvider,
    ILogger<TokenRefresherService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            try
            {
                logger.LogInformation("Proactively checking expiry of tokens");
                using var scope = serviceProvider.CreateScope();
                var repository = scope.ServiceProvider.GetRequiredService<TokenRepository>();
                foreach (var (role, stores) in repository.TokenStores)
                foreach (var (_, store) in stores)
                {
                    if (!store.IsInitialised) continue;
                    var expiresIn = store.AccessTokenExpiresAt!.Value.Subtract(DateTime.UtcNow);
                    if (expiresIn > TimeSpan.FromMinutes(5))
                    {
                        logger.LogInformation("Access token expires in {ExpiresIn} minutes", expiresIn.TotalMinutes);
                        continue;
                    }
                    var client = factory.CreateClient($"{role}-server-api");
                    var request = new HttpRequestMessage(HttpMethod.Post, "/token");
                    request.Content = new FormUrlEncodedContent([
                        new KeyValuePair<string, string>("grant_type", "refresh_token"),
                        new KeyValuePair<string, string>("refresh_token", store.RefreshToken)
                    ]);
                    logger.LogInformation("Calling server to refresh tokens");
                    using var response = await client.SendAsync(request, stoppingToken);
                    if (!response.IsSuccessStatusCode)
                    {
                        logger.LogWarning("Server refresh token response failed");
                        continue;
                    }
                    var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>(stoppingToken);
                    if (tokens is null)
                    {
                        logger.LogWarning("Refresh token response content was invalid");
                        continue;
                    }
                    store.AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(tokens.AccessTokenExpiresIn);
                    store.RefreshToken = tokens.RefreshToken;
                    store.AccessToken = tokens.AccessToken;
                }
                logger.LogInformation("Refreshed tokens");
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Unexpected error in proactive token refresh loop");
            }
        }
    }
}
