using Microsoft.EntityFrameworkCore;
using SecureCryptoServer.Entities;

namespace SecureCryptoServer.Persistence;

public class MessengerDbContext : DbContext
{
    public DbSet<UserDevice> Users => Set<UserDevice>();
    public DbSet<OfflineMessage> OfflineMessages => Set<OfflineMessage>();

    public DbSet<GroupRoom> Groups => Set<GroupRoom>();

    public MessengerDbContext(DbContextOptions<MessengerDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Индекс для моментального поиска крипто-паспортов (Prekey Bundle)
        modelBuilder.Entity<UserDevice>()
            .HasIndex(u => u.Username)
            .IsUnique();

        // Индекс по получателю для моментальной выгрузки оффлайн-очереди при входе
        modelBuilder.Entity<OfflineMessage>()
            .HasIndex(m => m.Recipient);

        // ИСПРАВЛЕНО: Добавили индекс для моментального поиска комнат и участников групп по ID
        modelBuilder.Entity<GroupRoom>()
            .HasIndex(g => g.Id)
            .IsUnique();
    }
}
