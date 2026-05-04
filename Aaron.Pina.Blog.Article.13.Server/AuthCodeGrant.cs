namespace Aaron.Pina.Blog.Article._13.Server;

public record AuthCodeGrant
{
    public string   ClientId            { get; init; } = string.Empty;
    public string   Subject             { get; init; } = string.Empty;
    public string   RedirectUri         { get; init; } = string.Empty;
    public string   CodeChallenge       { get; init; } = string.Empty;
    public string   CodeChallengeMethod { get; init; } = "S256";
    public string[] Scopes              { get; init; } = [];
    public DateTime ExpiresAt           { get; init; }
}
