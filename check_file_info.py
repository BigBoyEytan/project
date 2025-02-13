import magic
import hashlib
import os
from typing import Dict, Optional
import mimetypes


class FileInformationEngine:
    def __init__(self):
        self.magic = magic.Magic(mime=True)
        mimetypes.init()

    def get_file_info(self, file_path: str) -> Dict[str, Optional[str]]:
        try:
            if os.name == 'nt':
                file_path = os.path.abspath(file_path)

            # Try getting MIME type with file-magic
            try:
                mime_type = magic.Magic(mime=True).from_file(file_path)
                file_type = magic.Magic().from_file(file_path)
            except:
                # Fallback to mimetypes library
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type:
                    file_type = mime_type.split('/')[-1].upper() + ' file'
                else:
                    # Final fallback based on extension
                    ext = os.path.splitext(file_path)[1].lower()
                    mime_map = {
                        '.doc': 'application/msword',
                        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        '.pdf': 'application/pdf',
                        '.jpg': 'image/jpeg',
                        '.png': 'image/png'
                    }
                    mime_type = mime_map.get(ext)
                    file_type = ext[1:].upper() + ' file'

            return {
                'mime_type': mime_type,
                'file_type': file_type
            }
        except Exception as e:
            print(f"Error getting file info: {e}")
            return {'mime_type': None, 'file_type': None}

    def calculate_file_hashes(self, file_path: str) -> Dict[str, Optional[str]]:
        hashers = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }

        try:
            file_path_str = str(file_path).encode('mbcs').decode('mbcs')
            with open(file_path_str, 'rb') as f:
                while chunk := f.read(8192):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            return {name: hasher.hexdigest() for name, hasher in hashers.items()}
        except Exception as e:
            print(f"Error calculating hashes: {e}")
            return {name: None for name in hashers}


def test_file_information_engine(file_path: str):
    if not os.path.isfile(file_path):
        print(f"Error: File {file_path} not found")
        return

    engine = FileInformationEngine()

    print("File Info:")
    print(engine.get_file_info(file_path))

    print("\nFile Hashes:")
    print(engine.calculate_file_hashes(file_path))


if __name__ == "__main__":
    test_file_information_engine("test.txt")  # Replace with your file path