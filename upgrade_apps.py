import subprocess
import threading
import multiprocessing


def upgrade_app(app_id):
    """Upgrade a single app using winget."""
    try:
        result = subprocess.run(
            ['winget', 'upgrade', '--id', app_id, '--silent'],  # Upgrade one app
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            shell=True
        )

        if result.returncode != 0:
            print(f"Error upgrading {app_id}")
    except Exception as e:
        print(f"An error occurred while upgrading {app_id}")


def upgrade_apps(app_list):
    """Upgrade apps one by one using multithreading."""
    threads = []
    max_threads = multiprocessing.cpu_count()
    for app in app_list:
        if len(threads) <= max_threads:
            app_thread = threading.Thread(target=upgrade_app, args=(app['id'],))
            threads.append(app_thread)
            app_thread.start()

        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()