using System.Security.Cryptography;
using System.Buffers.Text;

var secret = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(48));
var hashed = BCrypt.Net.BCrypt.HashPassword(secret);

Console.WriteLine($"secret: {secret}");
Console.WriteLine($"hash: {hashed}");