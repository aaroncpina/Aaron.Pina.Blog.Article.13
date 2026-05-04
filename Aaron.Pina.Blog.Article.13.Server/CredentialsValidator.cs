using Microsoft.Extensions.Options;

namespace Aaron.Pina.Blog.Article._13.Server;

public class CredentialsValidator(IOptionsSnapshot<ClientCredentials> snapshot)
{
    public bool TryValidateCredentials(string? clientId, string? clientSecret)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret)) return false;
        var stored = snapshot.Value.Credentials.FirstOrDefault(c => c.ClientId == clientId);
        if (stored is null) return false;
        return BCrypt.Net.BCrypt.Verify(clientSecret, stored.ClientSecretHash);
    }

    public bool TryValidateRedirectUri(string? clientId, string? redirectUri)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri)) return false;
        var stored = snapshot.Value.Credentials.FirstOrDefault(c => c.ClientId == clientId);
        if (stored is null) return false;
        return stored.AllowedRedirectUris.Contains(redirectUri, StringComparer.Ordinal);
    }
}
