import subprocess

def upgrade_apps():
    try:
        print("\n⬆️  Upgrading all applications...")
        result = subprocess.run(
            ['winget', 'upgrade', '--all'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            shell=True
        )

        if result.returncode == 0:
            print("✅ Upgrade process completed.")
        else:
            print("❌ Error during upgrade:")
            print(result.stderr)
    except Exception as e:
        print(f"An error occurred during upgrade: {e}")
