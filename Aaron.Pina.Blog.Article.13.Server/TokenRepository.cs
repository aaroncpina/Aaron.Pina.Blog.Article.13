namespace Aaron.Pina.Blog.Article._13.Server;

public class TokenRepository(ServerDbContext dbContext)
{
    public void SaveToken(TokenEntity token)
    {
        dbContext.Tokens.Add(token);
        dbContext.SaveChanges();
    }

    public void UpdateToken(TokenEntity token)
    {
        dbContext.Tokens.Update(token);
        dbContext.SaveChanges();
    }

    public TokenEntity? TryGetTokenByRefreshToken(string refreshToken) =>
        dbContext.Tokens.FirstOrDefault(t => t.RefreshToken == refreshToken);

    public TokenEntity? TryGetTokenByClientIdAndAudience(string clientId, string audience) =>
        dbContext.Tokens.FirstOrDefault(t => t.ClientId == clientId && t.Audience == audience);
}
