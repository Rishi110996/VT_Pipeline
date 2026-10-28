# VT Pipeline

Automated VirusTotal malware hunting pipeline for Android malware families.

## Overview

This pipeline runs on a schedule (via cron) and performs the following for each
tracked malware family:

1. **VT Search** — Query VirusTotal Intelligence for new samples
2. **Download** — Fetch APK samples to external storage (`/mnt/ext_storage2/`)
3. **YARA Pre-Scan** — Filter out samples already detected by existing YARA rules
4. **LLM Analysis** — Run androAiV2 analysis on undetected samples (10 per case)
5. **Report Parsing** — Extract verdicts, IOCs, and generated YARA rules
6. **Artifact Build** — Bundle reports + YARA rules into a ZIP
7. **Zintel Case** — Create a Z-Intel case with the artifact attached
8. **Cleanup** — Delete samples, persist processed hash records

## Project Structure

```
vt_pipeline/
├── config.yaml              # Configuration (families, paths, API keys)
├── vt_pipeline.py           # Main pipeline orchestrator
├── update_yara_export.py    # Daily YARA export updater
├── modules/
│   ├── vt_search.py         # VT Intelligence search & download
│   ├── yara_scanner.py      # YARA pre-scan filtering
│   ├── androai_runner.py    # androAiV2 analysis wrapper
│   ├── report_parser.py     # Parse verdict JSONs
│   ├── artifact_builder.py  # Build ZIP artifacts
│   ├── zintel_client.py     # Z-Intel API client
│   └── state_manager.py     # Persistent state management
├── data/                    # Runtime data (processed hashes, history)
├── logs/                    # Per-run log files
├── setup_cron.sh            # Cron setup helper
├── requirements.txt
└── .gitignore
```

## Setup

### 1. Clone and create virtualenv

```bash
cd /home/metamorphosis/workspace
git clone <repo-url> vt_pipeline
cd vt_pipeline
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

Edit `config.yaml` to set:
- **Paths** to androAiV2, sample storage, YARA rules
- **API keys** for Zintel and VirusTotal
- **Researchers** and their assigned malware families
- **Malware families** with VT queries and enabled/disabled flags

### 3. Install cron jobs

```bash
bash setup_cron.sh    # shows the cron entries
crontab -e            # paste them in
```

**Cron schedule:**
| Job | Schedule | Time |
|-----|----------|------|
| YARA export update | Daily | 1:00 AM |
| VT Pipeline | Mon & Thu | 2:00 AM |

## Usage

### Normal run (all enabled families)
```bash
python3 vt_pipeline.py
```

### Dry run (no analysis or case creation)
```bash
python3 vt_pipeline.py --dry-run
```

### Process a specific family
```bash
python3 vt_pipeline.py --family cerberus
```

### Update YARA export manually
```bash
python3 update_yara_export.py
```

### Custom config file
```bash
python3 vt_pipeline.py --config /path/to/other_config.yaml
```

## Configuration Details

### Malware Families

Each family in `config.yaml` has:
- `name` — family identifier
- `enabled` — `true`/`false` toggle
- `vt_query` — VT Intelligence search query

### Researcher Assignment

Researchers are mapped to families in the config. When a Zintel case is
created for a family, it is automatically assigned to the researcher
responsible for that family.

### YARA Pre-Scan

The pipeline scans downloaded samples against:
1. **Main YARA export** (`zstatic-apk-sig.yara`) — updated daily
2. **LLM-generated rules** (`generated_rules/yara/`) — from prior runs

Only samples with **zero YARA matches** proceed to LLM analysis,
ensuring the pipeline focuses on truly undetected threats.

## Data Files

| File | Purpose |
|------|---------|
| `data/processed_hashes.json` | All SHA256s ever processed (never re-download) |
| `data/run_history.json` | Audit log of every pipeline run |
| `data/artifacts/*.zip` | Zintel case artifact ZIPs |
| `data/export_<id>.zip` | Cached YARA export (for change detection) |
