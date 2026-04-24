# Windows Setup & Run Guide (PowerShell)

This guide provides step-by-step instructions to set up and run the **Break-Glass (Emergency Access)** feature on a Windows 10/11 machine using PowerShell.

## ✅ Prerequisites

Before you begin, ensure you have the following installed and configured:

1.  **Windows 10 or 11**.
2.  **PowerShell**: The script is compatible with PowerShell 5.1 (which comes with Windows) and PowerShell 7+.
3.  **Python**:
    *   Version 3.11 or newer.
    *   Make sure it's available on your system's `PATH` as `python`. You can verify this by opening PowerShell and running `python --version`.
    *   During Python installation, be sure to check the box that says **"Add Python to PATH"**.
4.  **Node.js**:
    *   Version 18 (LTS) or newer.
    *   This will also install `npm`.
    *   Verify by running `node --version` and `npm --version` in PowerShell.
5.  **Git**: Required to clone the repository. Verify with `git --version`.

---

## 🚀 Fast Path: One-Command Script (Recommended)

This is the easiest and fastest way to get the application running.

1.  **Open PowerShell**: Open your terminal. You can search for "PowerShell" in the Start Menu.
2.  **Navigate to Project Root**: `cd` into the `Zero-Trust-Security-Framework-main` directory.
3.  **Run the Script**: Execute the following command.

    ```powershell
    powershell -ExecutionPolicy Bypass -File .\run_break_glass_local.ps1
    ```

This single command will:
- Create a Python virtual environment for the backend if it doesn't exist.
- Install all required Python packages.
- Install all required Node.js packages for the frontend.
- Start the backend server on `http://localhost:5001`.
- Start the frontend server on the next available port, starting at `http://localhost:3000`.
- Wait for the backend to be healthy before launching the frontend.

Once it's running, you can access the application at the URLs printed in the terminal.

---

## 🔧 Manual Setup (Step-by-Step)

If you prefer to run each component manually, follow these steps.

### 1. Backend Setup

First, set up and run the Python Flask backend.

```powershell
# 1. Navigate to the backend directory
cd backend

# 2. Create a Python virtual environment
python -m venv venv

# 3. Activate the virtual environment
#    You should see (venv) appear at the start of your prompt.
. .\venv\Scripts\Activate.ps1

# 4. Install the required Python packages
pip install -r requirements_minimal.txt

# 5. Run the backend server
python run.py
```

The backend will now be running at `http://localhost:5001`. You can leave this terminal running.

### 2. Frontend Setup

Open a **new, separate PowerShell terminal** to set up and run the Next.js frontend.

```powershell
# 1. Navigate to the frontend directory from the project root
cd apps\security-ui

# 2. Install the required Node.js packages
npm install

# 3. Run the frontend development server
npm run dev
```

The frontend will now be running at `http://localhost:3000`.

### 3. Access the Application

-   **Backend API**: `http://localhost:5001`
-   **Frontend UI**: `http://localhost:3000`
-   **Break-Glass Feature**: Navigate to `http://localhost:3000/emergency-access` in your browser.

---

## 🐛 Troubleshooting

-   **`ExecutionPolicy` Error**: If you get an error about scripts being disabled, the `powershell -ExecutionPolicy Bypass` command should fix it for that single run.
-   **`python` or `node` not found**: This means Python or Node.js are not correctly added to your system's PATH. Reinstall them, ensuring you check the "Add to PATH" option.
-   **Port Already in Use**: If a port is taken, you can find the process using it with `Get-Process -Id (Get-NetTCPConnection -LocalPort 5001).OwningProcess` and stop it from Task Manager. The one-command script automatically handles this for the frontend.
-   **Firewall Prompts**: When you first run the Python or Node servers, Windows Defender Firewall might ask for permission. Allow access for private networks.

This guide should provide everything you need to run the feature on Windows.