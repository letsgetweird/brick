import os
import asyncio
from nicegui import events

UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/uploads')

# Global UI element references
status_bar = None
progress_bar = None
progress_label = None
progress_container = None
show_progress = False

def set_status_bar(bar):
    """Set the global status bar reference"""
    global status_bar
    status_bar = bar

def set_progress_bar(bar, label, container):
    """Set the progress bar UI elements"""
    global progress_bar, progress_label, progress_container
    progress_bar = bar
    progress_label = label
    progress_container = container

def is_valid_pcap(data):
    """Validate if file is a valid PCAP by checking magic bytes"""
    if len(data) < 4:
        return False
    
    magic = data[:4]
    
    # Standard PCAP formats
    if magic in [b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d', 
                 b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1']:
        return True
    
    # PCAPNG format
    if magic == b'\x0a\x0d\x0d\x0a':
        return True
    
    return False

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def update_status(message, color='gray-400'):
    """Update the status bar"""
    if status_bar:
        status_bar.set_text(message)
        status_bar.classes(
            f'text-{color}', 
            remove='text-gray-400 text-blue-400 text-red-400 text-orange-400 text-green-400'
        )

def update_progress(stage, message):
    """
    Update progress bar (0-4 stages)
    stage 0 = hidden, 1 = 25%, 2 = 50%, 3 = 75%, 4 = 100%
    """
    if not progress_bar or not progress_container:
        return
    
    if stage == 0:
        # Hide progress bar
        progress_container.set_visibility(False)
    else:
        # Show and update progress bar
        progress_container.set_visibility(True)
        progress_value = stage / 4.0  # Convert to 0.0-1.0
        progress_bar.set_value(progress_value)
        
        # Update label if it exists (backward compatibility)
        if progress_label:
            progress_label.set_text(f"{stage * 25}%")
        
        update_status(message, 'blue-400')

async def monitor_zeek_simple():
    """
    Monitor Zeek by tracking log file growth
    Returns: True if successful
    """
    try:
        from zeek_progress import track_zeek_progress
        success = await track_zeek_progress(update_progress)
        return success
    except Exception as e:
        print(f"Zeek monitoring error: {e}")
        update_progress(0, "")  # Hide progress bar
        return False

async def process_large_file(data, temp_path, final_path, file_name, file_size):
    """Process large files with progress updates"""
    chunk_size = 5 * 1024 * 1024  # 5MB chunks
    bytes_written = 0
    last_progress = 0
    
    try:
        with open(temp_path, 'wb') as f:
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                f.write(chunk)
                bytes_written += len(chunk)
                
                progress = int((bytes_written / file_size) * 100)
                
                if progress - last_progress >= 10:
                    update_status(f'Writing file: {progress}%', 'blue-400')
                    last_progress = progress
                    await asyncio.sleep(0.01)
        
        os.rename(temp_path, final_path)
        
    except Exception as ex:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ex

async def handle_upload(e: events.UploadEventArguments):
    os.makedirs(UPLOAD_PATH, exist_ok=True)
    temp_path = os.path.join(UPLOAD_PATH, 'upload.tmp')
    final_path = os.path.join(UPLOAD_PATH, 'input.pcap')
    
    try:
        # Get filename
        file_name = 'uploaded file'
        for attr in ['name', 'filename']:
            if hasattr(e, attr) and getattr(e, attr):
                file_name = getattr(e, attr)
                break
        
        content = getattr(e, 'content', getattr(e, 'file', None))
        
        if content:
            for attr in ['filename', 'name']:
                if hasattr(content, attr) and getattr(content, attr):
                    file_name = getattr(content, attr)
                    break
        
        # Validate file extension
        if not file_name.lower().endswith(('.pcap', '.pcapng', '.cap')):
            update_status(f'✗ Invalid file type: must be .pcap or .pcapng', 'red-400')
            return
        
        if content:
            # Upload phase
            update_status(f'Uploading {file_name}...', 'blue-400')
            
            data = await content.read()
            file_size = len(data)
            file_size_formatted = format_file_size(file_size)
            
            await asyncio.sleep(0.1)  # Yield to event loop
            
            update_status(f'Received {file_name} ({file_size_formatted})', 'blue-400')
            await asyncio.sleep(0.5)
            
            # Validate PCAP
            if not is_valid_pcap(data):
                update_status(f'✗ Invalid PCAP format', 'red-400')
                return
            
            # Write file
            if file_size > 100 * 1024 * 1024:  # > 100MB
                update_status(f'Processing large file ({file_size_formatted})...', 'orange-400')
                await asyncio.sleep(0.5)
                await process_large_file(data, temp_path, final_path, file_name, file_size)
            else:
                update_status(f'Writing file...', 'blue-400')
                with open(temp_path, 'wb') as f:
                    f.write(data)
                os.rename(temp_path, final_path)
            
            update_status(f'✓ Upload complete ({file_size_formatted})', 'green-400')
            await asyncio.sleep(1)
            
            # Start Zeek monitoring with progress bar
            update_progress(1, "PCAP uploaded, waiting for Zeek...")
            success = await monitor_zeek_simple()
            
            if not success:
                update_progress(0, "")  # Hide progress bar
                update_status('Zeek processing (check logs for results)', 'orange-400')
        else:
            update_status("✗ Upload failed: No file content", 'red-400')
            
    except Exception as ex:
        update_status(f'✗ Upload error: {ex}', 'red-400')
        update_progress(0, "")  # Hide progress bar on error
        print(f"Upload error details: {ex}")
