#!/bin/bash

# BCash Production Setup Script
# This script helps set up all necessary secrets and configuration for production deployment

set -e

echo "🔒 BCash Production Setup"
echo "========================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    print_error "Wrangler CLI is not installed. Please install it first:"
    echo "npm install -g wrangler"
    exit 1
fi

print_status "Wrangler CLI found"

# Check if user is logged in to Cloudflare
if ! wrangler whoami &> /dev/null; then
    print_warning "You are not logged in to Cloudflare. Please log in:"
    wrangler login
fi

print_status "Cloudflare authentication verified"

echo ""
echo "🔐 Setting up production secrets..."
echo ""

# Generate JWT Secret
echo "1. JWT Secret"
echo "============="
print_info "Generating a secure JWT secret..."

# Generate a 256-bit (32 byte) random secret
JWT_SECRET=$(openssl rand -hex 32)

echo "Generated JWT secret. Setting it in Wrangler..."
echo "$JWT_SECRET" | wrangler secret put JWT_SECRET

print_status "JWT_SECRET configured"
echo ""

# Sentry DSN
echo "2. Sentry Monitoring (Optional but Recommended)"
echo "==============================================="
print_info "Sentry provides error monitoring and performance tracking."
print_info "1. Go to https://sentry.io and create a new project"
print_info "2. Choose 'JavaScript' as the platform"
print_info "3. Copy the DSN (starts with https://...)"
echo ""

read -p "Do you want to configure Sentry now? (y/N): " configure_sentry

if [[ $configure_sentry =~ ^[Yy]$ ]]; then
    echo ""
    read -p "Enter your Sentry DSN: " sentry_dsn
    
    if [[ -n "$sentry_dsn" ]]; then
        echo "$sentry_dsn" | wrangler secret put SENTRY_DSN
        print_status "SENTRY_DSN configured"
    else
        print_warning "No Sentry DSN provided. Skipping..."
    fi
else
    print_info "Skipping Sentry configuration. You can set it up later with:"
    echo "wrangler secret put SENTRY_DSN"
fi

echo ""

# Database Setup
echo "3. Database Setup"
echo "================="
print_info "Setting up the database with security upgrades..."

# Run database migrations
echo "Running database migrations..."
wrangler d1 execute sparappen-db --file=./schema.sql
wrangler d1 execute sparappen-db --file=./seed.sql
wrangler d1 execute sparappen-db --file=./upgrade-security.sql

print_status "Database migrations completed"
echo ""

# Security Check
echo "4. Security Validation"
echo "======================"
print_info "Running security tests..."

if npm run security:check; then
    print_status "Security tests passed"
else
    print_error "Security tests failed. Please review and fix issues before deploying."
    exit 1
fi

echo ""

# Final deployment
echo "5. Deployment"
echo "============="
print_info "Ready to deploy to production!"

read -p "Deploy to production now? (y/N): " deploy_now

if [[ $deploy_now =~ ^[Yy]$ ]]; then
    echo ""
    print_info "Deploying to Cloudflare Workers..."
    
    if wrangler deploy; then
        print_status "Deployment successful!"
        echo ""
        echo "🎉 BCash is now live in production!"
        echo ""
        print_info "Next steps:"
        echo "• Test the application thoroughly"
        echo "• Set up monitoring alerts in Sentry"
        echo "• Configure Cloudflare security settings"
        echo "• Review GDPR compliance checklist"
    else
        print_error "Deployment failed. Please check the logs above."
        exit 1
    fi
else
    echo ""
    print_info "Deployment skipped. To deploy later, run:"
    echo "wrangler deploy"
fi

echo ""
echo "📋 Production Checklist"
echo "======================="
echo ""
echo "✅ Secrets configured (JWT_SECRET, SENTRY_DSN)"
echo "✅ Database migrations applied"
echo "✅ Security tests passed"

if [[ $deploy_now =~ ^[Yy]$ ]]; then
    echo "✅ Application deployed"
else
    echo "⏳ Application ready for deployment"
fi

echo ""
echo "🔧 Additional Production Setup:"
echo ""
echo "1. Cloudflare Dashboard Settings:"
echo "   • SSL/TLS: Full (strict)"
echo "   • Security Level: High"
echo "   • Bot Fight Mode: On"
echo "   • Web Application Firewall: Configure rules"
echo ""
echo "2. Sentry Configuration:"
echo "   • Set up error alerts"
echo "   • Configure performance monitoring"
echo "   • Add team members"
echo ""
echo "3. GDPR Compliance:"
echo "   • Review privacy policy"
echo "   • Test data export/deletion"
echo "   • Document data processing"
echo ""
echo "4. Monitoring:"
echo "   • Set up uptime monitoring"
echo "   • Configure log analysis"
echo "   • Plan backup schedule"
echo ""

print_status "BCash production setup completed!"
echo ""
print_info "Documentation: See SÄKERHETSRAPPORT.md for detailed security analysis"
print_info "Support: Check security-guide.md for ongoing maintenance"
echo "" 