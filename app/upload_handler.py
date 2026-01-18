import os
import asyncio
from nicegui import events, ui

UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/uploads')

# Global status bar reference
status_bar = None

def set_status_bar(bar):
    """Set the global status bar reference"""
    global status_bar
    status_bar = bar

def is_valid_pcap(data):
    """
    Validate if file is a valid PCAP by checking magic bytes
    
    PCAP magic bytes:
    - 0xA1B2C3D4 (standard PCAP, microsecond precision)
    - 0xA1B23C4D (standard PCAP, nanosecond precision)
    - 0xD4C3B2A1 (swapped endian, microsecond)
    - 0x4D3CB2A1 (swapped endian, nanosecond)
    
    PCAPNG magic bytes:
    - 0x0A0D0D0A (PCAPNG Section Header Block)
    """
    if len(data) < 4:
        return False
    
    # Check first 4 bytes for PCAP magic numbers
    magic = data[:4]
    
    # Standard PCAP formats
    if magic == b'\xa1\xb2\xc3\xd4':  # Microsecond precision
        return True
    if magic == b'\xa1\xb2\x3c\x4d':  # Nanosecond precision
        return True
    if magic == b'\xd4\xc3\xb2\xa1':  # Swapped endian, microsecond
        return True
    if magic == b'\x4d\x3c\xb2\xa1':  # Swapped endian, nanosecond
        return True
    
    # PCAPNG format
    if magic == b'\x0a\x0d\x0d\x0a':  # PCAPNG Section Header
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
    """Update the status bar if it exists"""
    if status_bar:
        status_bar.set_text(message)
        # Remove all color classes and add the new one
        status_bar.classes(
            f'text-{color}', 
            remove='text-gray-400 text-blue-400 text-red-400 text-orange-400 text-green-400'
        )

async def process_large_file(data, temp_path, final_path, file_name, file_size):
    """
    Process large files with status bar updates to prevent websocket timeout
    
    Args:
        data: File content bytes
        temp_path: Temporary file path
        final_path: Final destination path
        file_name: Original filename
        file_size: File size in bytes
    """
    chunk_size = 5 * 1024 * 1024  # 5MB chunks
    bytes_written = 0
    last_progress = 0
    
    try:
        # Write file in chunks with periodic status updates
        with open(temp_path, 'wb') as f:
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                f.write(chunk)
                bytes_written += len(chunk)
                
                # Calculate progress
                progress = int((bytes_written / file_size) * 100)
                
                # Update every 10% to avoid excessive updates
                if progress - last_progress >= 10:
                    update_status(f'Processing {file_name}: {progress}%', 'blue-400')
                    last_progress = progress
                    
                    # Yield control to event loop to keep websocket alive
                    await asyncio.sleep(0.01)
        
        # Atomically move to final location (prevents Zeek from reading partial file)
        os.rename(temp_path, final_path)
        
        # Final success status
        file_size_formatted = format_file_size(file_size)
        update_status(f'✓ Uploaded {file_name} ({file_size_formatted})', 'green-400')
        
    except Exception as ex:
        # Clean up temp file on error
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ex

async def handle_upload(e: events.UploadEventArguments):
    os.makedirs(UPLOAD_PATH, exist_ok=True)
    temp_path = os.path.join(UPLOAD_PATH, 'upload.tmp')
    final_path = os.path.join(UPLOAD_PATH, 'input.pcap')
    
    try:
        # Try to get filename from event or content object
        file_name = 'uploaded file'
        
        # Check event attributes
        for attr in ['name', 'filename']:
            if hasattr(e, attr) and getattr(e, attr):
                file_name = getattr(e, attr)
                break
        
        # Get the file content from the upload event
        content = getattr(e, 'content', getattr(e, 'file', None))
        
        # Also check content object attributes
        if content:
            for attr in ['filename', 'name']:
                if hasattr(content, attr) and getattr(content, attr):
                    file_name = getattr(content, attr)
                    break
        
        # Check file extension first
        if not file_name.lower().endswith(('.pcap', '.pcapng', '.cap')):
            update_status(f'✗ Invalid file type: {file_name} must be .pcap or .pcapng', 'red-400')
            return
        
        if content:
            # Show initial upload status
            update_status(f'Uploading {file_name}...', 'blue-400')
            
            # Read file data asynchronously
            data = await content.read()
            file_size = len(data)
            file_size_formatted = format_file_size(file_size)
            
            # Show file size in status
            update_status(f'Received {file_name} ({file_size_formatted})', 'blue-400')
            await asyncio.sleep(0.5)  # Brief pause so user can see the size
            
            # Validate PCAP format by magic bytes
            if not is_valid_pcap(data):
                update_status(f'✗ Invalid PCAP format: {file_name}', 'red-400')
                return
            
            # Show warning for large files
            if file_size > 100 * 1024 * 1024:  # > 100MB
                update_status(f'Processing large file ({file_size_formatted})...', 'orange-400')
                await asyncio.sleep(0.5)
                
                # Process large files with progress updates
                await process_large_file(data, temp_path, final_path, file_name, file_size)
            else:
                # Small files - process directly without progress updates
                update_status(f'Processing {file_name}...', 'blue-400')
                
                with open(temp_path, 'wb') as f:
                    f.write(data)
                
                # Atomically move to final location
                os.rename(temp_path, final_path)
                
                update_status(f'✓ Uploaded {file_name} ({file_size_formatted})', 'green-400')
        else:
            update_status("✗ Upload failed: No file content", 'red-400')
            
    except Exception as ex:
        update_status(f'✗ Upload error: {ex}', 'red-400')
        print(f"Upload error details: {ex}")
