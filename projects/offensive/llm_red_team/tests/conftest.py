"""Put the project root on sys.path so tests import modules as the tool does."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
