import socket
import platform
import hashlib
from datetime import datetime

def get_device_info(root):
    """Get information about the current device"""
    try:
        device_info = {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'device_id': generate_device_id(),
            'screen_resolution': f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}",
            'timestamp': datetime.now().isoformat()
        }
        return device_info
    except Exception as e:
        print(f"Error getting device info: {e}")
        return {'error': str(e)}

def generate_device_id():
    """Generate a unique device ID"""
    try:
        # Generate a device ID based on hardware info
        system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.md5(system_info.encode()).hexdigest()
    except Exception:
        # Fallback to a random ID
        return hashlib.md5(str(datetime.now()).encode()).hexdigest()