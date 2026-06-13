# BlackBox-Core

Flask-powered CTF helper toolkit for cryptography, network recon, forensics, web testing, and utility workflows.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Configuration

Create or edit `.env`:

```text
SECRET_KEY=change-this-to-a-random-secret
PORT=5000
REQUIRE_API_KEY=false
API_KEYS=key1,key2
UPLOAD_FOLDER=temp/uploads
MAX_CONTENT_LENGTH=104857600
ENABLE_RATE_LIMIT=true
RATE_LIMIT_PER_MINUTE=60
```

## Layout

- `app.py` - Flask main app
- `core/` - backend modules
- `templates/` - Flask HTML templates
- `static/css/` - interface styles
- `static/js/` - frontend tool logic
- `static/libs/` - local browser libraries
- `assets/wordlists/` - built-in password wordlists for cracking tools

## Built-In Wordlists

The ZIP Password Cracker can use these local lists:

- `rockyou-mini.txt` - compact common-password list
- `ctf-common.txt` - CTF-focused defaults

Add more `.txt` wordlists to `assets/wordlists/`; they will appear in the ZIP cracker dropdown.
