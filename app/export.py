"""Export functionality for asset inventory"""
import csv
from datetime import datetime
import database


def export_inventory_csv():
    """
    Asset information from passive network analysis:
    - IP Address
    - MAC Address
    - Communication Protocols
    - Ports/Services
    - First Seen
    - Last Seen
    
    Returns:
        tuple: (filepath, filename) for download
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'brick_inventory_{timestamp}.csv'
    filepath = f'/tmp/{filename}'
    
    with open(filepath, 'w', newline='') as csvfile:
        fieldnames = [
            'IP Address',
            'MAC Address',
            'Protocols',
            'Ports',
            'First Seen',
            'Last Seen'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        assets = database.get_all_assets()
        
        for asset in assets:
            ip = asset['ip']
            mac = asset['mac'] or 'Unknown'
            protocols_summary = database.get_protocols_summary(ip)
            connections = database.get_asset_connections(ip)
            
            # Build ports summary from top connections
            unique_ports = set()
            for conn in connections[:10]:
                unique_ports.add(str(conn['dest_port']))
            ports_summary = ', '.join(sorted(unique_ports, key=int)) if unique_ports else 'N/A'
            
            writer.writerow({
                'IP Address': ip,
                'MAC Address': mac,
                'Protocols': protocols_summary,
                'Ports': ports_summary,
                'First Seen': asset['first_seen'] or 'Unknown',
                'Last Seen': asset['last_seen'] or 'Unknown'
            })
    
    return filepath, filename
