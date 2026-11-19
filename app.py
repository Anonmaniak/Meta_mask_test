"""
Zyphra Chat Platform — Root Entrypoint Trampoline (Case-Insensitive).
Allows running `python App.py` directly from project root.
"""
import os
import sys
import subprocess

if __name__ == "__main__":
    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
    script = os.path.join(backend_dir, "app.py")
    sys.exit(subprocess.call([sys.executable, script] + sys.argv[1:], cwd=backend_dir))
