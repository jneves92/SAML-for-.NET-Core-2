using Microsoft.EntityFrameworkCore;

namespace CheckForMetadataUpdates
{
    internal class MetadataContext : DbContext
    {
        public MetadataContext(DbContextOptions options) : base(options)
        {
        }

        public DbSet<MetadataRecord> MetadataRecords { get; set; } = null!;
    }
}
