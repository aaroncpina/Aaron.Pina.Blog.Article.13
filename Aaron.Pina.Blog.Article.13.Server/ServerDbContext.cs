using Microsoft.EntityFrameworkCore;

namespace Aaron.Pina.Blog.Article._13.Server;

public class ServerDbContext(DbContextOptions<ServerDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.ClientId)
                    .HasMaxLength(128);

        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.RefreshToken)
                    .HasMaxLength(512);

        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.Scope)
                    .HasMaxLength(512);

        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.Audience)
                    .HasMaxLength(128);

        modelBuilder.Entity<TokenEntity>()
                    .HasIndex(t => new { t.ClientId, t.Audience })
                    .IsUnique();
    }
    
    public DbSet<TokenEntity> Tokens => Set<TokenEntity>();
}
