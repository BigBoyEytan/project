import subprocess
import threading
import multiprocessing
import time


def upgrade_app(app_id):
    """Upgrade a single app using winget.

    Args:
        app_id (str): The ID of the application to upgrade

    Returns:
        bool: True if upgrade was successful, False otherwise
    """
    try:
        result = subprocess.run(
            f'winget upgrade --id "{app_id}" --accept-source-agreements',
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            shell=True,
            timeout=300  # 5-minute timeout to avoid hanging
        )

        if result.returncode != 0:
            return False
        else:
            return True
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def upgrade_apps(app_list):
    """Upgrade multiple apps using multithreading.

    Args:
        app_list (list): List of app dictionaries to upgrade
    """
    if not app_list:
        return

    # Create a thread-safe counter for completion tracking
    class Counter:
        def __init__(self):
            self.value = 0
            self.lock = threading.Lock()

        def increment(self):
            with self.lock:
                self.value += 1
                return self.value

    completed = Counter()
    total = len(app_list)

    # Function for threads to run
    def upgrade_and_track(app):
        try:
            upgrade_app(app['id'])
            completed.increment()
        except Exception:
            pass

    # Determine max threads based on CPU count
    max_threads = min(multiprocessing.cpu_count(), 4)  # Limit to 4 threads max
    threads = []

    # Start threads
    for app in app_list:
        # Wait for active threads to drop below max before starting new ones
        while len([t for t in threads if t.is_alive()]) >= max_threads:
            time.sleep(0.5)

        # Clean up completed threads
        threads = [t for t in threads if t.is_alive()]

        # Start new thread
        thread = threading.Thread(target=upgrade_and_track, args=(app,))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()