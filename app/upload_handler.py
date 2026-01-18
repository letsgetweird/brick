import os
from nicegui import events, ui

UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/uploads')

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
            ui.notify(
                f'Invalid file type: {file_name} must be a .pcap or .pcapng file',
                type='negative',
                position='top'
            )
            return
        
        if content:
            # Read file data asynchronously
            data = await content.read()
            
            # Validate PCAP format by magic bytes
            if not is_valid_pcap(data):
                ui.notify(
                    f'Invalid file format: {file_name} is not a valid PCAP or PCAPNG file',
                    type='negative',
                    position='top'
                )
                return
            
            # Write to temporary file first
            with open(temp_path, 'wb') as f:
                f.write(data)
            
            # Atomically move to final location (prevents Zeek from reading partial file)
            os.rename(temp_path, final_path)
            
            ui.notify(f'Uploaded {file_name}', type='positive')
        else:
            ui.notify("Upload failed: No file content found", type='negative')
            
    except Exception as ex:
        ui.notify(f'Upload error: {ex}', type='negative')
        print(f"Upload error details: {ex}")
