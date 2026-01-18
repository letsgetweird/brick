"""Main UI layout and application entry point"""
from nicegui import ui
import database
import log_processor
import state
import components
import export

# Initialize
database.init_db()

# UI state references
asset_container = None
asset_count_label = None
asset_count_display = None  # Add this for the inventory card display

def refresh_ui():
    """Refresh just the UI without re-parsing logs"""
    asset_container.clear()
    assets = database.get_all_assets()
    
    with asset_container:
        if assets:
            for asset in assets:
                components.create_asset_card(
                    asset, 
                    on_expand_callback=handle_expansion,
                    on_toggle_connections_callback=handle_toggle_connections
                )
        else:
            ui.label('No assets discovered yet. Upload a PCAP to begin.').classes('text-gray-400 text-center p-8')

def refresh_data():
    """Parse logs and refresh UI"""
    log_processor.parse_asset_log()
    log_processor.parse_conn_log()
    refresh_ui()
    
    # Update both asset count displays
    asset_count = len(database.get_all_assets())
    asset_count_label.text = f'{asset_count} Assets'
    asset_count_display.text = f'{asset_count} device{"s" if asset_count != 1 else ""} found'

def handle_expansion(ip):
    """Handle asset expansion toggle"""
    state.toggle_expansion(ip)
    refresh_ui()

def handle_toggle_connections(ip):
    """Handle showing all connections toggle"""
    state.toggle_show_all(ip)
    refresh_ui()

def handle_export():
    """Handle CSV export"""
    try:
        assets = database.get_all_assets()
        if not assets:
            ui.notify('No assets to export. Upload a PCAP first.', type='warning')
            return
        
        filepath, filename = export.export_inventory_csv()
        ui.download(filepath, filename)
        ui.notify('Inventory exported successfully!', type='positive')
    except Exception as e:
        print(f"Export error: {e}")
        ui.notify(f'Export failed: {str(e)}', type='negative')

# Build UI
ui.dark_mode().enable()

with ui.header().classes('bg-slate-900 items-center justify-between shadow-2'):
    ui.label('BRICK | ICS Asset Discovery').classes('text-h5 font-mono font-bold')
    with ui.row():
        asset_count_label = ui.label('0 Assets')
        ui.button(icon='refresh', on_click=refresh_data).props('flat color=white')

with ui.column().classes('w-full max-w-6xl mx-auto p-6 gap-6'):
    # Upload section
    components.create_upload_section()
    
    # Export section - Between upload and assets
    with ui.card().classes('w-full'):
        with ui.row().classes('w-full justify-between items-center p-4'):
            with ui.column():
                ui.label('Asset Inventory').classes('text-xl font-bold')
                asset_count_display = ui.label('0 devices found').classes('text-sm text-gray-400')
            
            ui.button('Export CSV', icon='download', on_click=handle_export).props('color=green no-caps').style('width: 161.05px; height: 36px')
    
    # Assets section
    ui.label('Discovered Assets').classes('text-h5 mb-2')
    asset_container = ui.column().classes('w-full gap-2')

# Initial load and auto-refresh
refresh_data()
ui.timer(5.0, refresh_data)

ui.run(host='0.0.0.0', port=8080, title="Brick")
