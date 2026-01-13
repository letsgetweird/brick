"""UI components for asset display"""
from nicegui import ui
from datetime import datetime
import database
import state

def format_timestamp(ts):
    """Format timestamp for display"""
    if not ts:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - dt
        
        if diff.total_seconds() < 60:
            return "Just now"
        elif diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)} mins ago"
        elif diff.total_seconds() < 86400:
            return f"{int(diff.total_seconds() / 3600)} hours ago"
        else:
            return dt.strftime("%Y-%m-%d %H:%M")
    except:
        return str(ts)

def create_protocol_section(protocols):
    """Create the protocols display section"""
    ui.label('Protocols Observed:').classes('text-md font-bold mb-2')
    if protocols:
        proto_columns = [
            {'name': 'protocol', 'label': 'Protocol', 'field': 'protocol', 'align': 'left'},
            {'name': 'packet_count', 'label': 'Packets', 'field': 'packet_count', 'align': 'right'},
        ]
        ui.table(columns=proto_columns, rows=protocols, row_key='protocol').classes('w-full').props('dense flat')
    else:
        ui.label('No protocol data').classes('text-gray-400 text-sm')

def create_connections_section(ip, connections, on_toggle_callback):
    """Create the connections display section"""
    show_all = state.is_showing_all(ip)
    
    with ui.row().classes('items-center justify-between w-full mb-2'):
        ui.label('Network Connections:').classes('text-md font-bold')
        if len(connections) > 10:
            ui.label(f'({len(connections)} total)').classes('text-xs text-gray-500')
    
    if connections:
        # Determine how many to show
        display_connections = connections if show_all else connections[:10]
        
        conn_columns = [
            {'name': 'dest_ip', 'label': 'Destination', 'field': 'dest_ip', 'align': 'left'},
            {'name': 'dest_port', 'label': 'Port', 'field': 'dest_port', 'align': 'left'},
            {'name': 'protocol', 'label': 'Proto', 'field': 'protocol', 'align': 'left'},
            {'name': 'packet_count', 'label': 'Pkts', 'field': 'packet_count', 'align': 'right'},
        ]
        
        # Scrollable container for many connections
        if show_all and len(connections) > 20:
            with ui.scroll_area().classes('w-full').style('max-height: 400px'):
                ui.table(columns=conn_columns, rows=display_connections, row_key='id').classes('w-full').props('dense flat')
        else:
            ui.table(columns=conn_columns, rows=display_connections, row_key='id').classes('w-full').props('dense flat')
        
        # Show more/less button
        if len(connections) > 10:
            if show_all:
                ui.button(
                    'Show Less',
                    icon='expand_less',
                    on_click=lambda: on_toggle_callback(ip)
                ).props('flat size=sm color=blue').classes('mt-2')
            else:
                ui.button(
                    f'Show All ({len(connections) - 10} more)',
                    icon='expand_more',
                    on_click=lambda: on_toggle_callback(ip)
                ).props('flat size=sm color=blue').classes('mt-2')
    else:
        ui.label('No connection data').classes('text-gray-400 text-sm')

def create_asset_card(asset, on_expand_callback, on_toggle_connections_callback):
    """Create a card for each asset with expandable details"""
    ip = asset['ip']
    protocols_summary = database.get_protocols_summary(ip)
    is_expanded = state.is_expanded(ip)
    
    with ui.card().classes('w-full'):
        # Header - always visible
        with ui.row().classes('w-full items-center justify-between'):
            with ui.row().classes('items-center gap-4 flex-grow'):
                # Expand/collapse button
                ui.button(
                    icon='expand_more' if not is_expanded else 'expand_less',
                    on_click=lambda: on_expand_callback(ip)
                ).props('flat dense round').classes('text-blue-400')
                
                ui.label(ip).classes('text-lg font-bold text-blue-300')
                ui.label(f"MAC: {asset['mac'] or 'Unknown'}").classes('text-sm text-gray-400')
                ui.label(f"{protocols_summary}").classes('text-sm text-green-400')
            
            with ui.row().classes('items-center gap-2'):
                ui.label(f"First: {format_timestamp(asset['first_seen'])}").classes('text-xs text-gray-500')
                ui.label(f"Last: {format_timestamp(asset['last_seen'])}").classes('text-xs text-green-500')
        
        # Expandable details
        if is_expanded:
            ui.separator().classes('my-2')
            
            protocols = database.get_asset_protocols(ip)
            connections = database.get_asset_connections(ip)
            
            with ui.row().classes('w-full gap-4'):
                # Left column - Protocols
                with ui.column().classes('flex-1'):
                    create_protocol_section(protocols)
                
                # Right column - Connections
                with ui.column().classes('flex-1'):
                    create_connections_section(ip, connections, on_toggle_connections_callback)

def create_upload_section():
    """Create the upload card"""
    with ui.card().classes('w-full'):
        ui.label('Upload PCAP File').classes('text-h6 mb-2')
        import upload_handler
        ui.upload(on_upload=upload_handler.handle_upload, 
                  label="Drop PCAP file here or click to browse", 
                  auto_upload=True).classes('w-full').props('accept=".pcap,.pcapng"')	
