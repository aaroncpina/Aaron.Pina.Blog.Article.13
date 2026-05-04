namespace Aaron.Pina.Blog.Article._13.Client;

public record PendingAuth(string Scope, string CodeVerifier, string RedirectUri);
