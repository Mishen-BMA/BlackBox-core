# BlackBox Core

BlackBox Core is a FastAPI scaffold for CTF and security challenge helper tooling.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./start.sh
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn server:app --reload
```

API health check:

```text
GET /health
```

## Layout

- `config/` stores application settings, constants, and safe tool allowlists.
- `modules/` contains CTF helper modules by challenge category.
- `utils/` contains shared helpers, validation, conversion, and logging utilities.
- `models/` contains Pydantic request and response schemas.
- `middleware/` contains authentication, rate limiting, and request logging.
- `workers/` contains long-running or background task helpers.
- `wordlists/` and `payloads/` contain local testing dictionaries.
- `data/`, `logs/`, `temp/`, and `uploads/` are runtime directories.

