import os
from nicegui import events, ui

UPLOAD_PATH = os.getenv('UPLOAD_PATH', '/uploads')

async def handle_upload(e: events.UploadEventArguments):
    os.makedirs(UPLOAD_PATH, exist_ok=True)
    temp_path = os.path.join(UPLOAD_PATH, 'upload.tmp')
    final_path = os.path.join(UPLOAD_PATH, 'input.pcap')

    try:
        # 1. identify content object
        content = getattr(e, 'content', getattr(e, 'file', None))
        
        # 2. get the filename for the notification
        # Check e.name, then content.filename, then default to 'unknown_file'
        file_name = getattr(e, 'name', getattr(content, 'filename', 'unknown_file'))

        if content:
            # 3. handle async read
            data = await content.read()
            
            with open(temp_path, 'wb') as f:
                f.write(data)
                
            # 4. atomic move for Zeek
            os.rename(temp_path, final_path)
            ui.notify(f'PCAP "{file_name}" uploaded.', type='info')
        else:
            ui.notify("Upload failed: No content stream found.", type='negative')
            
    except Exception as ex:
        ui.notify(f'Upload error: {ex}', type='negative')
        print(f"Detailed Error: {ex}")
