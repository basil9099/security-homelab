import os
import sys

# Make the project root importable so tests can `from config import ...`,
# `from models import ...`, etc. — mirroring how the honeypot runs.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
