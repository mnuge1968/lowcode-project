# Lowcode Project

A lightweight Flask application that serves a simple greeting page at the root route.

## Overview

This project demonstrates a minimal Python web app built with Flask. The application exposes a single endpoint:

- `/` returns the text `Hello from Michael`

## Requirements

- Python 3.11+
- Flask 3.0.3

## Setup

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Run the app

Start the Flask development server:

```bash
python app.py
```

Then open the app in your browser at:

```text
http://127.0.0.1:5000/
```

## Project files

- `app.py` — Flask application definition and route logic
- `requirements.txt` — Python dependencies
