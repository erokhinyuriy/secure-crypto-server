using Microsoft.EntityFrameworkCore;
using SecureCryptoServer.Entities;

namespace SecureCryptoServer.Persistence;

public class MessengerDbContext : DbContext
{
    public DbSet<UserDevice> Users => Set<UserDevice>();
    public DbSet<OfflineMessage> OfflineMessages => Set<OfflineMessage>();

    public MessengerDbContext(DbContextOptions<MessengerDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserDevice>()
            .HasIndex(u => u.Username)
            .IsUnique();

        // Индекс по получателю для моментальной выгрузки при входе
        modelBuilder.Entity<OfflineMessage>()
            .HasIndex(m => m.Recipient);
    }
}
