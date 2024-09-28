import os
import subprocess
import pypandoc
import chardet
import docx
import magic # pip install python-magic-bin (for Windows)
from PyPDF2 import PdfReader
from datetime import datetime
import PySimpleGUI as sg

def read_file(file_path):
    # Determine the file type based on extension
    if file_path.lower().endswith('.docx'):
        return read_docx(file_path)
    elif file_path.lower().endswith('.pdf'):
        return read_pdf(file_path)
    else:
        # For text files or unknown types, try to detect encoding
        with open(file_path, 'rb') as file:
            raw_data = file.read()
        detected = chardet.detect(raw_data)
        encoding = detected['encoding']

        try:
            return raw_data.decode(encoding)
        except UnicodeDecodeError:
            # If decoding fails, return as binary
            return raw_data

def markdown_to_docx(markdown_text: str, output_file: str) -> bool:
    """Convert markdown text to a .docx file."""
    try:
        pypandoc.convert_text(markdown_text, 'docx', format='md', outputfile=output_file)
        return True
    except RuntimeError as e:
        print(f"Error during conversion: {e}")
        return False

def save_report(content, filename):
    """Save content to a file, either as plain text, Word document, or convert from markdown."""
    try:
        # Get the current date and time
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Split the filename into name and extension
        name, ext = os.path.splitext(filename)
        
        # Create a new filename with the current timestamp
        new_filename = f"{name}_{current_time}{ext}"
        
        # Ensure the 'Reports' directory exists
        if not os.path.exists('Reports'):
            os.makedirs('Reports')
        
        # Create the full path for the new file
        full_path = os.path.join('Reports', new_filename)
        
        # Ensure the file doesn't already exist (although it's unlikely with the timestamp)
        counter = 1
        while os.path.exists(full_path):
            new_filename = f"{name}_{current_time}_{counter}{ext}"
            full_path = os.path.join('Reports', new_filename)
            counter += 1
        
        if markdown_to_docx(content, full_path):
            return full_path
        else:
            return None
    except Exception as e:
        sg.popup_error(f"Error saving report: {str(e)}")
        return None

def open_file(file_path):
    """Open a file using the default system application."""
    try:
        if os.name == 'nt':  # For Windows
            os.startfile(file_path)
        elif os.name == 'posix':  # For macOS and Linux
            subprocess.call(('open', file_path))
        else:
            raise OSError("Unsupported operating system")
    except Exception as e:
        sg.popup_error(f"Error opening file: {str(e)}")

def save_to_file(content, prefix, extension):
    """Save content to a file with a given prefix and extension."""
    try:
        i = 1
        while True:
            filename = f"{prefix}_{i}{extension}"
            if not os.path.exists(filename):
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                return filename
            i += 1
    except Exception as e:
        sg.popup_error(f"Error saving file: {str(e)}")
        return None
    
def read_docx(file_path):
    doc = docx.Document(file_path)
    full_text = []
    for para in doc.paragraphs:
        full_text.append(para.text)
    return '\n'.join(full_text)

def read_pdf(file_path):
    with open(file_path, 'rb') as file:
        pdf_reader = PdfReader(file)
        text = ''
        for page in pdf_reader.pages:
            text += page.extract_text()
    return text

def is_valid_file(filename):
    """Check if a file exists and is readable."""
    return os.path.isfile(filename) and os.access(filename, os.R_OK)

def is_valid_directory(directory):
    """Check if a directory exists and is accessible."""
    return os.path.isdir(directory) and os.access(directory, os.R_OK)

def create_directory_if_not_exists(directory):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_file_size(file_path):
    """Get the size of a file in bytes."""
    return os.path.getsize(file_path)

def get_file_extension(file_path):
    """Get the extension of a file."""
    return os.path.splitext(file_path)[1]

def list_files_in_directory(directory):
    """List all files in a directory."""
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

def move_file(source, destination):
    """Move a file from source to destination."""
    try:
        os.rename(source, destination)
    except Exception as e:
        sg.popup_error(f"Error moving file: {str(e)}")

def delete_file(file_path):
    """Delete a file."""
    try:
        os.remove(file_path)
    except Exception as e:
        sg.popup_error(f"Error deleting file: {str(e)}")

def get_file_creation_time(file_path):
    """Get the creation time of a file."""
    return os.path.getctime(file_path)

def get_file_modification_time(file_path):
    """Get the last modification time of a file."""
    return os.path.getmtime(file_path)

def is_file_empty(file_path):
    """Check if a file is empty."""
    return os.path.getsize(file_path) == 0

def get_file_permissions(file_path):
    """Get the permissions of a file."""
    return oct(os.stat(file_path).st_mode)[-3:]

def change_file_permissions(file_path, permissions):
    """Change the permissions of a file."""
    try:
        os.chmod(file_path, int(permissions, 8))
    except Exception as e:
        sg.popup_error(f"Error changing file permissions: {str(e)}")

def get_file_owner(file_path):
    """Get the owner of a file."""
    return os.stat(file_path).st_uid

def get_file_group(file_path):
    """Get the group of a file."""
    return os.stat(file_path).st_gid

def compress_file(file_path, archive_name):
    """Compress a file into a zip archive."""
    try:
        import zipfile
        with zipfile.ZipFile(archive_name, 'w') as zipf:
            zipf.write(file_path, os.path.basename(file_path))
    except Exception as e:
        sg.popup_error(f"Error compressing file: {str(e)}")

def decompress_file(archive_path, extract_path):
    """Decompress a zip archive."""
    try:
        import zipfile
        with zipfile.ZipFile(archive_path, 'r') as zipf:
            zipf.extractall(extract_path)
    except Exception as e:
        sg.popup_error(f"Error decompressing file: {str(e)}")

def is_executable(data):
    """Check magic bytes"""
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(data)
    
    executable_mime_types = [
        'application/x-executable',
        'application/x-dosexec',
        'application/x-msdos-program',
        'application/x-msdownload',
        'application/vnd.microsoft.portable-executable'
    ]
    
    if file_type in executable_mime_types:
        return True
    
    # Check file extensions in the Content-Disposition header
    executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.msi', '.ps1', '.vbs', '.js', '.jar']
    if b'Content-Disposition' in data:
        for ext in executable_extensions:
            if ext.encode() in data.lower():
                return True
    
    return False