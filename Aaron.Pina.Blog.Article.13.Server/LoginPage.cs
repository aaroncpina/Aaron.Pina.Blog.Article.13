using System.Net;

namespace Aaron.Pina.Blog.Article._13.Server;

public static class LoginPage
{
    public static string Build(
        string  clientId,
        string  redirectUri,
        string  scope,
        string? state,
        string  codeChallenge,
        string  codeChallengeMethod,
        string? error = null)
    {
        string H(string? v) => WebUtility.HtmlEncode(v ?? string.Empty);
        var errorHtml = error is null ? string.Empty : $"<p style=\"color:red\">{H(error)}</p>";
        return $"""
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><title>Sign In</title></head>
            <body>
              <h2>Sign in to authorize access</h2>
              {errorHtml}
              <form method="post">
                <input type="hidden" name="client_id"             value="{H(clientId)}">
                <input type="hidden" name="redirect_uri"          value="{H(redirectUri)}">
                <input type="hidden" name="scope"                 value="{H(scope)}">
                <input type="hidden" name="state"                 value="{H(state)}">
                <input type="hidden" name="code_challenge"        value="{H(codeChallenge)}">
                <input type="hidden" name="code_challenge_method" value="{H(codeChallengeMethod)}">
                <p><label>Username<br><input type="text"     name="username" autocomplete="username"></label></p>
                <p><label>Password<br><input type="password" name="password" autocomplete="current-password"></label></p>
                <button type="submit">Sign In</button>
              </form>
            </body>
            </html>
            """;
    }
}
