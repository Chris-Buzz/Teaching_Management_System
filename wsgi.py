"""
WSGI entry point for production servers (Vercel, Heroku, etc.)
This file is used by application servers to run the Flask app.
"""

import os
import sys

# Ensure the app directory is in the path
sys.path.insert(0, os.path.dirname(__file__))

from app import app

# This is the entry point for WSGI servers
if __name__ == '__main__':
    app.run()
