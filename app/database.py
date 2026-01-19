import sqlite3
import os
import ipaddress
import re
from contextlib import contextmanager
from collections import defaultdict

DB_PATH = os.getenv('DB_PATH', '/data/inventory.sqlite')

# Connection pool - reuse connections
_connection = None

# Batch storage - collect operations before executing
_asset_batch = {}  # {ip: {'mac': mac, 'timestamp': ts}}
_protocol_batch = defaultdict(set)  # {ip: {proto1, proto2, ...}}
_connection_batch = {}  # {(src_ip, dst_ip, dst_port, proto): True}

# Batch configuration
_batch_size = 5000  # Increased for better performance with large files
_batch_counter = 0

def get_connection():
    """Get or create a persistent connection"""
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        # Enable WAL mode for better concurrent performance
        _connection.execute("PRAGMA journal_mode=WAL")
        _connection.execute("PRAGMA synchronous=NORMAL")
        _connection.execute("PRAGMA cache_size=10000")
        _connection.execute("PRAGMA temp_store=MEMORY")
    return _connection

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
    
    # Enable WAL mode
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    
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
    
    # Create indices for better performance
    conn.execute('CREATE INDEX IF NOT EXISTS idx_protocols_ip ON protocols(ip)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_connections_source ON connections(source_ip)')
    
    conn.commit()
    conn.close()

def _flush_assets(conn):
    """Flush asset batch to database"""
    global _asset_batch
    
    if not _asset_batch:
        return
    
    try:
        # Bulk upsert assets
        cursor = conn.cursor()
        
        for ip, data in _asset_batch.items():
            mac = data.get('mac')
            timestamp = data.get('timestamp')
            
            # Check if exists
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
        
        _asset_batch.clear()
        
    except sqlite3.Error as e:
        print(f"Database error in _flush_assets: {e}")
        _asset_batch.clear()

def _flush_protocols(conn):
    """Flush protocol batch to database"""
    global _protocol_batch
    
    if not _protocol_batch:
        return
    
    try:
        # Bulk upsert protocols
        for ip, protocols in _protocol_batch.items():
            for proto in protocols:
                conn.execute('''INSERT INTO protocols (ip, protocol, packet_count, last_seen)
                               VALUES (?, ?, 1, CURRENT_TIMESTAMP)
                               ON CONFLICT(ip, protocol) DO UPDATE SET
                               packet_count = packet_count + 1,
                               last_seen = CURRENT_TIMESTAMP''', (ip, proto))
        
        _protocol_batch.clear()
        
    except sqlite3.Error as e:
        print(f"Database error in _flush_protocols: {e}")
        _protocol_batch.clear()

def _flush_connections(conn):
    """Flush connection batch to database"""
    global _connection_batch
    
    if not _connection_batch:
        return
    
    try:
        # Bulk upsert connections
        for (source_ip, dest_ip, dest_port, protocol) in _connection_batch.keys():
            conn.execute('''INSERT INTO connections (source_ip, dest_ip, dest_port, protocol, packet_count, last_seen)
                           VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                           ON CONFLICT(source_ip, dest_ip, dest_port, protocol) DO UPDATE SET
                           packet_count = packet_count + 1,
                           last_seen = CURRENT_TIMESTAMP''', (source_ip, dest_ip, dest_port, protocol))
        
        _connection_batch.clear()
        
    except sqlite3.Error as e:
        print(f"Database error in _flush_connections: {e}")
        _connection_batch.clear()

def flush_batch(force=False):
    """Force flush all pending batches to database"""
    global _connection, _batch_counter
    
    if _connection is None:
        return
    
    try:
        # Start transaction
        _connection.execute("BEGIN")
        
        # Flush all batches
        _flush_assets(_connection)
        _flush_protocols(_connection)
        _flush_connections(_connection)
        
        # Commit transaction
        _connection.commit()
        _batch_counter = 0
        
    except sqlite3.Error as e:
        print(f"Database error in flush_batch: {e}")
        try:
            _connection.rollback()
        except:
            pass

def _maybe_flush():
    """Check if we should flush batches based on size"""
    global _batch_counter, _asset_batch, _protocol_batch, _connection_batch
    
    _batch_counter += 1
    
    # Calculate total items in all batches
    total_items = len(_asset_batch) + len(_protocol_batch) + len(_connection_batch)
    
    if total_items >= _batch_size:
        flush_batch()

def update_asset(ip, mac=None, timestamp=None):
    """Add asset to batch"""
    global _asset_batch
    
    # Validate inputs
    if not is_valid_ip(ip):
        print(f"Invalid IP address rejected: {ip}")
        return
    
    if mac and not is_valid_mac(mac):
        print(f"Invalid MAC address rejected: {mac}")
        return
    
    # Add to batch (latest update wins)
    if ip not in _asset_batch or mac:  # Update if new or has MAC
        _asset_batch[ip] = {'mac': mac, 'timestamp': timestamp}
    
    _maybe_flush()

def update_protocol(ip, protocol):
    """Add protocol to batch"""
    global _protocol_batch
    
    # Validate input
    if not is_valid_ip(ip):
        return
    
    if not protocol or not isinstance(protocol, str):
        return
    
    # Handle comma-separated protocols (e.g., "COTP,S7COMM")
    protocols = [p.strip() for p in protocol.split(',')]
    
    for proto in protocols:
        # Skip if too long
        if len(proto) > 50:
            print(f"Protocol name too long, skipping: {proto}")
            continue
        
        # Sanitize protocol name (alphanumeric + underscore + dash only)
        if not re.match(r'^[A-Za-z0-9_-]+$', proto):
            print(f"Invalid protocol name rejected: {proto}")
            continue
        
        # Add to batch
        _protocol_batch[ip].add(proto)
    
    _maybe_flush()

def update_connection(source_ip, dest_ip, dest_port, protocol):
    """Add connection to batch"""
    global _connection_batch
    
    # Validate inputs
    if not is_valid_ip(source_ip) or not is_valid_ip(dest_ip):
        return
    
    if not isinstance(dest_port, int) or dest_port < 0 or dest_port > 65535:
        return
    
    if not protocol or not isinstance(protocol, str):
        return
    
    # Add to batch (use tuple as key for deduplication)
    key = (source_ip, dest_ip, dest_port, protocol)
    _connection_batch[key] = True
    
    _maybe_flush()

def get_all_assets():
    # Flush any pending batches first
    flush_batch()
    
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT ip, mac, first_seen, last_seen FROM assets ORDER BY last_seen DESC")
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except sqlite3.Error as e:
        print(f"Database error in get_all_assets: {e}")
        return []

def get_asset_protocols(ip):
    """Get all protocols seen for a specific IP"""
    # Flush any pending batches first
    flush_batch()
    
    if not is_valid_ip(ip):
        return []
    
    conn = get_connection()
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

def get_asset_connections(ip, limit=1000):
    """Get connections for a specific IP (limited to prevent DoS)"""
    # Flush any pending batches first
    flush_batch()
    
    if not is_valid_ip(ip):
        return []
    
    conn = get_connection()
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

def get_protocols_summary(ip):
    """Get comma-separated list of protocols for display"""
    protocols = get_asset_protocols(ip)
    if not protocols:
        return "None"
    return ", ".join([p['protocol'] for p in protocols[:5]])  # Top 5

def get_batch_stats():
    """Get current batch statistics for monitoring"""
    return {
        'assets_queued': len(_asset_batch),
        'protocols_queued': sum(len(protos) for protos in _protocol_batch.values()),
        'connections_queued': len(_connection_batch),
        'batch_size': _batch_size
    }
