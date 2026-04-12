namespace Aaron.Pina.Blog.Article._13.Server;

public class TokenEntity
{
    public Guid     Id                    { get; init; } = Guid.NewGuid();
    public string   ClientId              { get; init; } = string.Empty;   
    public string   Audience              { get; init; } = string.Empty;
    public string   Scope                 { get; init; } = string.Empty;
    public DateTime CreatedAt             { get; init; }
    public string   RefreshToken          { get; set;  } = string.Empty;
    public DateTime RefreshTokenExpiresAt { get; set;  }
}
