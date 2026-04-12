using Microsoft.Extensions.Options;

namespace Aaron.Pina.Blog.Article._13.Server;

public class CredentialsValidator(IOptionsSnapshot<ClientCredentials> snapshot)
{
    public bool TryValidateCredentials(string? clientId, string? clientSecret)
    {
        if (string.IsNullOrEmpty(clientId)) return false;
        var storedCredentials = snapshot.Value.Credentials.FirstOrDefault(credential =>
            credential.ClientId == clientId);
        if (storedCredentials is null) return false;
        if (string.IsNullOrEmpty(clientSecret)) return false;
        return BCrypt.Net.BCrypt.Verify(clientSecret, storedCredentials.ClientSecretHash);
    }
}
