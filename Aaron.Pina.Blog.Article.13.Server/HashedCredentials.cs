namespace Aaron.Pina.Blog.Article._13.Server;

public class HashedCredentials
{
    public string   ClientId            { get; init; } = string.Empty;
    public string   ClientSecretHash    { get; init; } = string.Empty;
    public string[] AllowedRedirectUris { get; init; } = [];
}
