# Cloudpath Configuration Extractor

Extracts configuration data from a Cloudpath Enrollment System deployment via REST API and outputs to JSON or Cloudpath-compatible CSV import files.

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

### List Available DPSK Pools (Default)

When run without arguments, the script lists all available DPSK pools:

```bash
python cloudpath_extractor.py
```

Output shows pool IDs, names, SSID lists, and DPSK counts to help you choose which pool to extract.

### Extract from a Specific DPSK Pool

```bash
python cloudpath_extractor.py --pool-id AccountDpskPool-e0b5b92b-600f-4620-81f8-4faaa68a013c
```

Extracts all DPSKs from the specified pool. This is the primary usage mode.

### Filter by SSID

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --ssid-match "@SiteName"
```

Only returns DPSKs whose SSID list contains the specified string. Uses "contains" matching.

**SSID Inheritance:** DPSKs can inherit their SSID list from the parent pool. If a DPSK has an empty `ssidList`, the filter checks against the pool's SSID list instead. The output will populate empty `ssidList` fields with the inherited pool values.

### Filter by Name

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --name-match "chris"
```

Only returns DPSKs whose name contains the specified string (case-insensitive).

### Filter and Strip from Name

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --name-match-and-strip "sitename_foo"
```

Filters DPSKs by name (like `--name-match`) AND removes the matched string from the output names.

Example transformation:
- `chris13_sitename_foo_fast` becomes `chris13_fast`

The script handles double delimiters that may result from removal (e.g., `__` becomes `_`). The original name is preserved in an `originalName` field.

### Fetch Full DPSK Details

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --full-details
```

Fetches complete details for each DPSK individually. This is slower but captures all fields including any SSID overrides specific to each DPSK.

### Export as CSV

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --csv
```

Generates two Cloudpath-compatible CSV import files alongside the JSON output:

- **DPSK Import CSV** (`*_dpsk_import.csv`) — Columns: `Username`, `Passphrase`, `VLAN ID`, `Expiration Date`, `Start Date`, `Days Until Expiration`, `User Group` (last four left blank). Maps DPSK `name` → Username, `passphrase` → Passphrase, `vlanid` → VLAN ID.

- **Identity Import CSV** (`*_identity_import.csv`) — Columns: `Name`, `Email`, `Description`, `Vlan`. Maps DPSK `name` → Name, `guid` → Description, `vlanid` → Vlan. Email is left blank.

### Chunked Output

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --chunk 500
python cloudpath_extractor.py -p AccountDpskPool-... --csv --chunk 500
```

Splits output into multiple files of N DPSKs each. Useful for large deployments where Cloudpath import has size limits.

For 3,000 DPSKs with `--chunk 500`, you get 6 files with `_chunk1of6`, `_chunk2of6`, etc. in the filenames. Works with both JSON and CSV output. Each chunked file includes chunk metadata (chunk number, total chunks, DPSKs in chunk).

### Extract All Pools (Use with Caution)

```bash
python cloudpath_extractor.py --all-pools-yes-really
```

Extracts DPSKs from ALL pools. This can be slow and generate large output files. Requires explicit confirmation flag.

### Combining Filters

Filters can be combined:

```bash
python cloudpath_extractor.py -p AccountDpskPool-... --ssid-match "@SiteA" --name-match "guest" --full-details
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--pool-id` | `-p` | Extract DPSKs from this specific pool ID/GUID |
| `--ssid-match` | | Filter DPSKs to those with this string in their SSID list |
| `--name-match` | | Filter DPSKs to those with this string in their name |
| `--name-match-and-strip` | | Filter by name AND remove matched string from output names |
| `--full-details` | | Fetch full details for each DPSK (slower, but complete) |
| `--all-pools-yes-really` | | Extract from ALL pools (requires explicit flag) |
| `--csv` | | Export Cloudpath-compatible DPSK and Identity import CSV files |
| `--chunk` | | Split output into chunks of N DPSKs per file |
| `--output-dir` | `-o` | Output directory for JSON/CSV files (default: `./output`) |

## Environment Variables

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

Files are saved to the output directory with the naming pattern:
```
cloudpath_{fqdn}_{timestamp}.json
cloudpath_{fqdn}_{timestamp}_dpsk_import.csv      (with --csv)
cloudpath_{fqdn}_{timestamp}_identity_import.csv   (with --csv)
cloudpath_{fqdn}_{timestamp}_chunk1of3.json        (with --chunk)
```

The script maintains only the last 5 output files, automatically deleting older ones.

HATEOAS `links` objects from the Cloudpath API are automatically stripped at ingestion time and will not appear in any output.

### Example Output

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
      "ssidList": ["Corp-WiFi", "Guest-WiFi"],
      "vlanid": "100",
      "deviceCount": 2
    }
  ]
}
```

When using `--name-match-and-strip`, entries include both modified and original names:

```json
{
  "name": "chris13_fast",
  "originalName": "chris13_sitename_foo_fast",
  ...
}
```

## Logs

Log files are stored in the `logs/` directory with timestamps. The last 5 log files are retained.
