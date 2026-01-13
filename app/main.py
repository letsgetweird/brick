"""Main UI layout and application entry point"""
from nicegui import ui
import database
import log_processor
import state
import components

# Initialize
database.init_db()

# UI state references
asset_container = None
asset_count_label = None

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
    asset_count_label.text = f'{len(database.get_all_assets())} Assets'

def handle_expansion(ip):
    """Handle asset expansion toggle"""
    state.toggle_expansion(ip)
    refresh_ui()

def handle_toggle_connections(ip):
    """Handle showing all connections toggle"""
    state.toggle_show_all(ip)
    refresh_ui()

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
    
    # Assets section
    ui.label('Discovered Assets').classes('text-h5 mb-2')
    asset_container = ui.column().classes('w-full gap-2')

# Initial load and auto-refresh
refresh_data()
ui.timer(5.0, refresh_data)

ui.run(host='0.0.0.0', port=8080, title="Brick")
