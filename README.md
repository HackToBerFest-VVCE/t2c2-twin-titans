# t2c2-twin-titans

Private hackathon repository for Twin Titans.

## RepoReality

RepoReality is a local Streamlit app that checks documentation claims against the contents of a repository ZIP. It detects explicitly documented file paths, common installation commands, runtime version requirements, dependency names, and configuration variables; technology mentions alone are not treated as file claims. Each detected claim is marked **Verified**, **Failed**, or **Unverified**, with evidence and a correction suggestion only when repository evidence supports one. Checks that cannot be concluded reliably (such as an absent configuration variable or a manifest in an unspecified subfolder) remain unverified. A single top-level project folder in a ZIP is normalized before checks. Verification reports can be downloaded as JSON.

The analyzer reads supported text files in memory; it does not extract archives to disk, execute repository code, or run shell commands. It uses deterministic local checks and does not need an API key.

### Requirements

- Python 3.11 or later
- Windows PowerShell (instructions below), macOS, or Linux

### Run on Windows

From the repository folder, create and activate a virtual environment, install dependencies, and launch Streamlit:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If PowerShell blocks virtual-environment activation, use the environment's Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL printed by Streamlit, then upload a repository `.zip` file in the sidebar.

### Run tests

```powershell
py -m unittest discover -v
```

The core analyzer tests use Python's standard library and do not need Streamlit to run.

### Inspection limits

For safe, predictable local inspection, archives are limited to 5,000 entries, 50 MB total uncompressed content, and 5 MB per file. Supported text formats are decoded as UTF-8; binary and unrecognized files are skipped. The current deterministic checks support common Python, Node.js, Go, Rust, and Composer manifests; unsupported claim formats remain unverified or are not reported.
