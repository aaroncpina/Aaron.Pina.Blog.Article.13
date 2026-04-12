using static System.StringSplitOptions;

namespace Aaron.Pina.Blog.Article._13.Shared;

public static class ScopeParser
{
    public static bool TryExtractValues(string scope, out string audience, out string[] scopes)
    {
        scopes = [];
        audience = string.Empty;
        if (string.IsNullOrEmpty(scope)) return false;
        scopes = ExtractScopes(scope);
        var audiences = ExtractAudiences(scopes);
        if (audiences.Length != 1) return false;
        audience = audiences.Single();
        return true;
    }

    public static string[] ExtractAudiences(IEnumerable<string> scopes) =>
        scopes.Select(s => s.Split('.', 2))
              .Where(p => p.Length == 2)
              .Select(p => p.First())
              .Distinct(StringComparer.Ordinal)
              .ToArray();
    
    public static string[] ExtractScopes(string scope) =>
        scope.Split(' ', RemoveEmptyEntries | TrimEntries);
    
    public static string[] ExtractPermissions(IEnumerable<string> scopes) =>
        scopes.Select(s => s.Split('.', 2))
              .Where(p => p.Length == 2)
              .Select(p => p.Last())
              .Distinct(StringComparer.Ordinal)
              .ToArray();
}
