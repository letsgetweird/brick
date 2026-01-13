import sqlite3
import os
import ipaddress
import re

DB_PATH = os.getenv('DB_PATH', '/data/inventory.sqlite')

def is_valid_ip(ip_str):
    """Validate IP address format"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, AttributeError):
        return False

def is_valid_mac(mac_str):
    """Validate MAC address format"""
    if not mac_str:
        return True  # MAC is optional
    if not isinstance(mac_str, str):
        return False
    # Match format: XX:XX:XX:XX:XX:XX (case insensitive)
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac_str))

def init_db():
    db_dir = os.path.dirname(DB_PATH)
    os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    
    # Assets table
    conn.execute('''CREATE TABLE IF NOT EXISTS assets
                 (ip TEXT PRIMARY KEY, 
                  mac TEXT,
                  first_seen TIMESTAMP,
                  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Protocol observations table
    conn.execute('''CREATE TABLE IF NOT EXISTS protocols
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip TEXT,
                  protocol TEXT,
                  packet_count INTEGER DEFAULT 1,
                  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(ip) REFERENCES assets(ip),
                  UNIQUE(ip, protocol))''')
    
    # Connections table
    conn.execute('''CREATE TABLE IF NOT EXISTS connections
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  source_ip TEXT,
                  dest_ip TEXT,
                  dest_port INTEGER,
                  protocol TEXT,
                  packet_count INTEGER DEFAULT 1,
                  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(source_ip) REFERENCES assets(ip),
                  UNIQUE(source_ip, dest_ip, dest_port, protocol))''')
    
    conn.commit()
    conn.close()

def update_asset(ip, mac=None, timestamp=None):
    # Validate inputs
    if not is_valid_ip(ip):
        print(f"Invalid IP address rejected: {ip}")
        return
    
    if mac and not is_valid_mac(mac):
        print(f"Invalid MAC address rejected: {mac}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if asset exists
        cursor.execute("SELECT ip, first_seen FROM assets WHERE ip = ?", (ip,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing
            if mac:
                conn.execute('''UPDATE assets SET mac = ?, last_seen = CURRENT_TIMESTAMP 
                               WHERE ip = ?''', (mac, ip))
            else:
                conn.execute('''UPDATE assets SET last_seen = CURRENT_TIMESTAMP 
                               WHERE ip = ?''', (ip,))
        else:
            # Insert new
            first_seen = timestamp if timestamp else None
            conn.execute('''INSERT INTO assets (ip, mac, first_seen, last_seen)
                           VALUES (?, ?, ?, CURRENT_TIMESTAMP)''', (ip, mac, first_seen))
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error in update_asset: {e}")
    finally:
        conn.close()

def update_protocol(ip, protocol):
    """Track protocol usage for an asset"""
    # Validate input
    if not is_valid_ip(ip):
        return
    
    if not protocol or not isinstance(protocol, str):
        return
    
    # Sanitize protocol name (alphanumeric + underscore only)
    if not re.match(r'^[A-Za-z0-9_-]+$', protocol):
        print(f"Invalid protocol name rejected: {protocol}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('''INSERT INTO protocols (ip, protocol, packet_count, last_seen)
                       VALUES (?, ?, 1, CURRENT_TIMESTAMP)
                       ON CONFLICT(ip, protocol) DO UPDATE SET
                       packet_count = packet_count + 1,
                       last_seen = CURRENT_TIMESTAMP''', (ip, protocol))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error in update_protocol: {e}")
    finally:
        conn.close()

def update_connection(source_ip, dest_ip, dest_port, protocol):
    """Track connections between assets"""
    # Validate inputs
    if not is_valid_ip(source_ip) or not is_valid_ip(dest_ip):
        return
    
    if not isinstance(dest_port, int) or dest_port < 0 or dest_port > 65535:
        return
    
    if not protocol or not isinstance(protocol, str):
        return
    
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('''INSERT INTO connections (source_ip, dest_ip, dest_port, protocol, packet_count, last_seen)
                       VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                       ON CONFLICT(source_ip, dest_ip, dest_port, protocol) DO UPDATE SET
                       packet_count = packet_count + 1,
                       last_seen = CURRENT_TIMESTAMP''', (source_ip, dest_ip, dest_port, protocol))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error in update_connection: {e}")
    finally:
        conn.close()

def get_all_assets():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT ip, mac, first_seen, last_seen FROM assets ORDER BY last_seen DESC")
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except sqlite3.Error as e:
        print(f"Database error in get_all_assets: {e}")
        return []
    finally:
        conn.close()

def get_asset_protocols(ip):
    """Get all protocols seen for a specific IP"""
    if not is_valid_ip(ip):
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT protocol, packet_count, last_seen 
                         FROM protocols 
                         WHERE ip = ? 
                         ORDER BY packet_count DESC''', (ip,))
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except sqlite3.Error as e:
        print(f"Database error in get_asset_protocols: {e}")
        return []
    finally:
        conn.close()

def get_asset_connections(ip, limit=1000):
    """Get connections for a specific IP (limited to prevent DoS)"""
    if not is_valid_ip(ip):
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT dest_ip, dest_port, protocol, packet_count, last_seen 
                         FROM connections 
                         WHERE source_ip = ? 
                         ORDER BY packet_count DESC
                         LIMIT ?''', (ip, limit))
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except sqlite3.Error as e:
        print(f"Database error in get_asset_connections: {e}")
        return []
    finally:
        conn.close()

def get_protocols_summary(ip):
    """Get comma-separated list of protocols for display"""
    protocols = get_asset_protocols(ip)
    if not protocols:
        return "None"
    return ", ".join([p['protocol'] for p in protocols[:5]])  # Top 5
