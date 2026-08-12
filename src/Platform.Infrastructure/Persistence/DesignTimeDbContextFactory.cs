using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Platform.Infrastructure.Persistence;

public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<PlatformDbContext>
{
    public PlatformDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<PlatformDbContext>();
        optionsBuilder.UseNpgsql(
            "Host=localhost;Port=5432;Database=platform_db;Username=platform;Password=changeme",
            npg => npg.MigrationsAssembly(typeof(PlatformDbContext).Assembly.FullName));

        return new PlatformDbContext(optionsBuilder.Options);
    }
}
