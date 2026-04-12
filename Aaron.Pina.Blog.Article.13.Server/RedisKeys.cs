namespace Aaron.Pina.Blog.Article._13.Server;

public static class RedisKeys
{
    private const string Root = "jwt-server";
    
    public static string Blacklist(string jti)  => $"{Root}:blacklist:{jti}";
    
    public static string AuthCode(string code)  => $"{Root}:auth:code:{code}";

    public static string CurrentKid()           => $"{Root}:jwks:current-kid";
    public static string PrivateKey(string kid) => $"{Root}:jwks:private:{kid}";
    public static string PublicKey(string kid)  => $"{Root}:jwks:public:{kid}";
    public static string KeyHistory()           => $"{Root}:jwks:key-history";
}
