using Microsoft.Extensions.Options;

namespace Aaron.Pina.Blog.Article._13.Server;

public class UserValidator(IOptionsSnapshot<UserCredentials> snapshot)
{
    public bool TryValidate(string? username, string? password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return false;
        var stored = snapshot.Value.Users.FirstOrDefault(u => u.Username == username);
        if (stored is null) return false;
        return BCrypt.Net.BCrypt.Verify(password, stored.PasswordHash);
    }
}
