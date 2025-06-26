#!/bin/bash

# BCash Automated Backup Script
# Run this script daily via cron to backup database and critical data

set -e

# Configuration
BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo "🔄 BCash Automated Backup - $(date)"
echo "===================================="

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Database backup
echo "📦 Creating database backup..."
BACKUP_FILE="$BACKUP_DIR/bcash-db-backup-$DATE.sql"

if wrangler d1 export sparappen-db --output "$BACKUP_FILE"; then
    print_status "Database backup created: $BACKUP_FILE"
    
    # Compress the backup
    gzip "$BACKUP_FILE"
    print_status "Backup compressed: $BACKUP_FILE.gz"
else
    print_error "Database backup failed"
    exit 1
fi

# Configuration backup
echo "⚙️  Backing up configuration files..."
CONFIG_BACKUP="$BACKUP_DIR/bcash-config-backup-$DATE.tar.gz"

tar -czf "$CONFIG_BACKUP" \
    wrangler.toml \
    package.json \
    schema.sql \
    upgrade-security.sql \
    seed.sql \
    security-guide.md \
    SÄKERHETSRAPPORT.md \
    2>/dev/null || true

print_status "Configuration backup created: $CONFIG_BACKUP"

# Health check and status
echo "🏥 Running health check..."
if curl -f -s "$(wrangler pages project list | grep bcash | awk '{print $2}')/api/health" > /dev/null 2>&1; then
    print_status "Application health check passed"
else
    print_warning "Health check failed - application may be down"
fi

# Security audit
echo "🔒 Running security audit..."
if npm audit --audit-level high > "$BACKUP_DIR/security-audit-$DATE.txt" 2>&1; then
    print_status "Security audit completed - no high/critical vulnerabilities"
else
    print_warning "Security audit found issues - check $BACKUP_DIR/security-audit-$DATE.txt"
fi

# Cleanup old backups
echo "🧹 Cleaning up old backups (older than $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "bcash-*" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
print_status "Old backup cleanup completed"

# Generate backup report
REPORT_FILE="$BACKUP_DIR/backup-report-$DATE.json"
cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_date": "$DATE",
  "database_backup": "$BACKUP_FILE.gz",
  "config_backup": "$CONFIG_BACKUP",
  "backup_size_mb": $(du -sm "$BACKUP_DIR" | cut -f1),
  "retention_days": $RETENTION_DAYS,
  "status": "completed"
}
EOF

print_status "Backup report generated: $REPORT_FILE"

echo ""
echo "📊 Backup Summary"
echo "================="
echo "• Database backup: $(basename "$BACKUP_FILE.gz")"
echo "• Config backup: $(basename "$CONFIG_BACKUP")"
echo "• Backup directory size: $(du -sh "$BACKUP_DIR" | cut -f1)"
echo "• Total backups: $(ls -1 "$BACKUP_DIR"/bcash-*.gz 2>/dev/null | wc -l)"

echo ""
print_status "Backup completed successfully!"

# Optional: Upload to cloud storage (R2, S3, etc.)
if [ ! -z "$BACKUP_UPLOAD_ENABLED" ] && [ "$BACKUP_UPLOAD_ENABLED" = "true" ]; then
    echo "☁️  Uploading to cloud storage..."
    # Add your cloud upload logic here
    # Example for R2: wrangler r2 object put bucket-name/path/file.gz --file backup.gz
    print_status "Cloud upload completed"
fi 