using Aaron.Pina.Blog.Article._13.Shared.Responses;

namespace Aaron.Pina.Blog.Article._13.Server;

public record TokenResult
{
    public TokenResponse? Tokens { get; init; }
    public string?        Error  { get; init; }
    
    public bool           IsSuccess => Error is null;

    public static TokenResult Success(TokenResponse tokens) =>
        new() { Tokens = tokens };

    public static TokenResult Fail(string error) =>
        new() { Error = error };
}