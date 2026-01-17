# Cloudpath Configuration Extractor

Extracts configuration data from a Cloudpath Enrollment System deployment via REST API and outputs to JSON.

Supports Cloudpath 5.11+ using the `/admin/publicApi` endpoint with JWT authentication.

## Setup

1. Install dependencies:
   ```bash
   pip install requests python-dotenv
   ```

2. Create a `.env` file in the script directory:
   ```
   CP_FQDN=your-cloudpath-server.com
   CP_USERNAME=admin@example.com
   CP_PASSWORD=your-password
   CP_VERIFY_SSL=true
   ```

## Usage

### Full Extraction (all endpoints)

```bash
python cloudpath_extractor.py
```

Discovers and extracts all available endpoints including:
- Authentication servers (with users and groups)
- RADIUS attribute groups
- Certificate templates
- DPSK pools (with DPSKs and devices)
- Enrollments
- Policies
- And more...

### Extract from a Specific DPSK Pool

```bash
python cloudpath_extractor.py --pool-id AccountDpskPool-e0b5b92b-600f-4620-81f8-4faaa68a013c
```

Runs full extraction but only pulls DPSKs from the specified pool.

### Fast DPSK-Only Mode

```bash
python cloudpath_extractor.py --dpsk-only --pool-id AccountDpskPool-e0b5b92b-600f-4620-81f8-4faaa68a013c
```

Skips all endpoint discovery and other resources. Directly hits `/dpskPools/{id}/dpsks` for minimal, fast extraction.

### Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--pool-id` | `-p` | Extract DPSKs only from this specific pool ID/GUID |
| `--dpsk-only` | | Fast mode: only extract DPSKs (requires `--pool-id`) |
| `--output-dir` | `-o` | Output directory for JSON files (default: `./output`) |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CP_FQDN` | Yes | Cloudpath server FQDN |
| `CP_USERNAME` | Yes | Admin username |
| `CP_PASSWORD` | Yes | Admin password |
| `CP_API_KEY` | No | API key (if required) |
| `CP_VERIFY_SSL` | No | Verify SSL certificates (default: `true`) |
| `CP_DPSK_POOL_ID` | No | Default pool ID filter |
| `OUTPUT_DIR` | No | Output directory (default: `./output`) |

## Output

JSON files are saved to the output directory with the naming pattern:
```
cloudpath_{fqdn}_{timestamp}.json
```

The script maintains only the last 5 output files, automatically deleting older ones.

### Example Output (DPSK-only mode)

```json
{
  "metadata": {
    "extracted_at": "2026-01-16T14:28:23",
    "cloudpath_fqdn": "cp.example.com",
    "mode": "dpsk_only",
    "pool_id": "AccountDpskPool-..."
  },
  "dpsks": [
    {
      "guid": "AccountDpsk-...",
      "name": "User1",
      "passphrase": "abc123",
      "status": "ACTIVE",
      "vlanid": "100",
      "deviceCount": 2
    }
  ]
}
```

## Logs

Log files are stored in the `logs/` directory with timestamps. The last 5 log files are retained.
