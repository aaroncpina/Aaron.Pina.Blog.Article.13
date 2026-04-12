using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._13.Shared.Responses;
using Aaron.Pina.Blog.Article._13.Shared;
using Aaron.Pina.Blog.Article._13.Other;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/user", (HttpContext context) =>
    {
        var clientId = context.User.FindFirstValue("sub");
        if (string.IsNullOrEmpty(clientId)) return Results.BadRequest("No client id found");
        var claims = context.User.FindAll("scope").ToList();
        if (claims.Count == 0) return Results.BadRequest("No scopes found");
        var permissions = ScopeParser.ExtractPermissions(claims.Select(c => c.Value));
        return Results.Ok(new UserResponse(clientId, string.Join(',', permissions)));
    })
   .RequireAuthorization();

app.Run();
