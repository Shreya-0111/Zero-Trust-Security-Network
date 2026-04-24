# Break-Glass (Emergency Access) — Local Setup & Run Guide (macOS)

This guide is for running **only** the Break-Glass / Emergency Access feature locally:
- Backend (Flask) on `http://localhost:5001`
- Frontend (Next.js) on `http://localhost:3000` (or the next free port)

## Prerequisites

- macOS + zsh
- `python3` available (`python3 --version`)
- Node.js available (`node --version` + `npm --version`)
- Optional: `pnpm` (the repo uses it in places, but `npm` works)

### Windows prerequisites

- Windows 10/11
- PowerShell 5.1+ (or PowerShell 7)
- Python 3.11+ installed and available as `python`
- Node.js 18+ installed (`node` + `npm` on PATH)

## Fast path (recommended): one command

From the repo root:

```bash
chmod +x run_break_glass_local.sh
./run_break_glass_local.sh
```

### Windows (PowerShell)

From the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_break_glass_local.ps1
```

What it does:
- creates `backend/venv` if missing
- installs backend deps (default: `backend/requirements_minimal.txt`)
- installs frontend deps if `apps/security-ui/node_modules` is missing
- starts backend + frontend
- waits until `GET http://localhost:5001/health` succeeds

Then open the UI:
- `http://localhost:3000/emergency-access` (or the printed port)

### Useful options

```bash
# Install full backend deps instead of minimal
BACKEND_REQUIREMENTS_FILE=requirements.txt ./run_break_glass_local.sh

# Skip installs (if you already installed deps)
SKIP_BACKEND_INSTALL=1 SKIP_FRONTEND_INSTALL=1 ./run_break_glass_local.sh
```

## Manual path (step-by-step)

### 1) Backend setup + run

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements_minimal.txt
python run.py
```

Windows (PowerShell):

```powershell
cd backend
python -m venv venv
. .\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements_minimal.txt
python run.py
```

Validate backend:

```bash
curl -f http://localhost:5001/health
```

### 2) Frontend setup + run

In a new terminal:

```bash
cd apps/security-ui
npm install
npm run dev
```

Windows (PowerShell):

```powershell
cd apps\security-ui
npm install
npm run dev
```

Open:
- `http://localhost:3000`
- Go to `/emergency-access`

## Using Dev Login (no Firebase web config required)

In local development, the UI supports dev-login so you can exercise break-glass flows without configuring Firebase web env vars.

Typical flow:
1. Open the UI
2. Use Dev Login (choose role)
3. Navigate to `/emergency-access`
4. Submit a request as a non-admin user
5. Log in as an admin user and approve/deny in the pending list

## Common issues & fixes

### “Exit code 127” when running scripts

Exit code `127` usually means **command not found** or the script is not executable.

Try:

```bash
chmod +x start_all.sh run_break_glass_local.sh backend/start_proper.sh
```

Also confirm tools exist:

```bash
command -v python3
command -v node
command -v npm
```

### Backend won’t start / keeps getting killed (exit 137/143)

- `137` often means the process was killed (OOM / external kill / SIGKILL).
- `143` is usually SIGTERM.

What to do:
- Check if port `5001` is already in use:
  ```bash
  lsof -nP -iTCP:5001 -sTCP:LISTEN
  ```
- Stop any old backend process that’s still running.
- Run the backend in the foreground (`python run.py`) and read the traceback.

### Port already in use

Backend (5001):

```bash
lsof -nP -iTCP:5001 -sTCP:LISTEN
```

Frontend (3000):

```bash
lsof -nP -iTCP:3000 -sTCP:LISTEN
```

The one-command script auto-picks a free frontend port starting at 3000.

### CORS errors in the browser

CORS errors can mask real backend errors.
- First confirm the backend responds to `/health`.
- Then check the failing API route directly in terminal (after dev-login cookies are set, you can use the browser network tab to see the exact URL).

## Where things live

- Backend entrypoint: `backend/run.py`
- Break-glass routes: `backend/app/routes/break_glass_routes.py`
- Break-glass logic: `backend/app/services/break_glass_service.py`
- UI page: `apps/security-ui/app/emergency-access/page.tsx`

## Quick verification checklist

- `curl -f http://localhost:5001/health` returns 200
- UI loads at `http://localhost:3000` (or printed port)
- Dev login works and sets cookies
- `/emergency-access` shows request form + pending approvals (for admin)
- Approve/Deny updates the list and shows a toast
