import os
from nicegui import events, ui

UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/uploads')

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
        
        if content:
            # Read file data asynchronously
            data = await content.read()
            
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
