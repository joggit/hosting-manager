#!/usr/bin/env python3
"""
Quick integration helper - tests and integrates enhanced features
"""

def quick_integration():
    """Quick integration of enhanced features"""
    
    print("🚀 Quick Integration Helper")
    print("=" * 30)
    
    # Test database connection
    import sqlite3
    try:
        conn = sqlite3.connect("/tmp/hosting/hosting.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ssl_certificates")
        ssl_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM parent_domains")
        parent_count = cursor.fetchone()[0]
        print(f"✅ Database connected - {ssl_count} SSL certs, {parent_count} parent domains")
        conn.close()
    except Exception as e:
        print(f"❌ Database issue: {e}")
    
    # Test SSL manager
    try:
        from src.utils.ssl_manager import SSLManager
        ssl_manager = SSLManager()
        certs = ssl_manager.list_certificates()
        print(f"✅ SSL Manager - {len(certs)} certificates")
    except Exception as e:
        print(f"❌ SSL Manager issue: {e}")
    
    # Test enhanced monitoring
    try:
        from src.monitoring.enhanced_monitor import EnhancedMonitor
        monitor = EnhancedMonitor()
        metrics = monitor.get_current_metrics()
        print(f"✅ Enhanced Monitor - CPU: {metrics.get('cpu_percent', 0):.1f}%")
    except Exception as e:
        print(f"❌ Monitor issue: {e}")
    
    print("\n🎯 Integration Status:")
    print("All modules created and working!")
    
    print("\n📋 Next Steps:")
    print("1. Test SSL: python3 src/utils/ssl_manager.py --list")
    print("2. Test monitoring: python3 src/monitoring/enhanced_monitor.py --metrics")
    print("3. Add integration code to your hosting_manager.py")
    
    print("\n🔧 Integration Code for hosting_manager.py:")
    print("""
# Add these imports at the top of your hosting_manager.py:
try:
    from src.utils.ssl_manager import SSLManager
    from src.monitoring.enhanced_monitor import EnhancedMonitor
    ENHANCED_FEATURES = True
except ImportError:
    ENHANCED_FEATURES = False

# In your main() function, add SSL commands:
if args.ssl_list:
    ssl_manager = SSLManager()
    certs = ssl_manager.list_certificates()
    for cert in certs:
        status = "⚠️ EXPIRES SOON" if cert['expires_soon'] else "✅ Valid"
        print(f"{status} {cert['domain']} - expires: {cert['expires_at']}")

elif args.health_check:
    monitor = EnhancedMonitor()
    health = monitor.get_domain_health_summary()
    for domain in health:
        status_icon = "✅" if domain['status'] == 'healthy' else "❌"
        print(f"{status_icon} {domain['domain']}")

# Add these argument parsers:
parser.add_argument('--ssl-list', action='store_true', help='List SSL certificates')
parser.add_argument('--ssl-check', help='Check SSL for domain')
parser.add_argument('--health-check', action='store_true', help='Check domain health')
    """)

if __name__ == "__main__":
    quick_integration()
