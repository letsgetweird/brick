"""Application state management"""

# Track expanded rows
expanded_rows = set()

# Track which IPs are showing all connections
show_all_connections = {}

def toggle_expansion(ip):
    """Toggle expansion state for an IP"""
    if ip in expanded_rows:
        expanded_rows.remove(ip)
    else:
        expanded_rows.add(ip)

def is_expanded(ip):
    """Check if an IP is expanded"""
    return ip in expanded_rows

def toggle_show_all(ip):
    """Toggle showing all connections for an IP"""
    show_all_connections[ip] = not show_all_connections.get(ip, False)

def is_showing_all(ip):
    """Check if showing all connections for an IP"""
    return show_all_connections.get(ip, False)
