# bbb

A Go fork of [boostedblob](https://github.com/hauntsaninja/boostedblob) — a fast, concurrent CLI for working with local files, Azure Blob Storage (`az://`), and Hugging Face (`hf://`).

## Why a fork of boostedblob

1. Need a single binary for multi-platform support
2. Add login user and network debug logs

## Installation

Download the latest release from the [Releases](https://github.com/tg123/bbb/releases) page, or build from source:

```bash
go install github.com/tg123/bbb@latest
```

## Supported Path Types

| Prefix | Description | Example |
|--------|-------------|---------|
| *(none)* | Local filesystem | `/tmp/data/`, `./file.txt` |
| `az://` | Azure Blob Storage | `az://myaccount/mycontainer/path/to/blob` |
| `hf://` | Hugging Face Hub | `hf://meta-llama/Llama-2-7b/weights.bin`, `hf://datasets/org/repo/data.csv` |

## Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--loglevel` | `info` | Log level: `debug`, `info`, `warn`, `error` (env: `BBB_LOG_LEVEL`) |

**Debug logging example** — use `--loglevel debug` to inspect DNS resolution and the Azure AD token issuer (`iss`), which is useful for diagnosing connectivity or authentication problems:

```bash
bbb --loglevel debug ls az://myaccount/mycontainer/
```

Example debug output (sensitive fields redacted):

```
time=... level=DEBUG msg="DNS lookup" host=myaccount.blob.core.windows.net addrs=["198.51.100.1"]
time=... level=DEBUG msg="Decoded JWT payload" payload="{\"aud\":\"https://storage.azure.com\",\"iss\":\"https://sts.windows.net/<tenant-id>/\",…}"
```

The `DNS lookup` line shows the resolved IP addresses for the storage account, and the `Decoded JWT payload` line contains the full token claims including `iss` (the token issuer) and `aud` (audience), letting you verify the correct identity and tenant are being used.

> **Warning:** Debug output may include personally identifiable information such as tenant IDs, object IDs, and other token claims. Do not share debug logs publicly or paste them into tickets without redacting sensitive fields.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BBB_LOG_LEVEL` | `info` | Same as `--loglevel` flag |
| `BBB_DNS_CACHE` | *(off)* | Set to `1`, `true`, `yes`, or `on` to enable process-local DNS caching |
| `BBB_AZBLOB_ACCOUNTKEY` | | Azure Storage shared key for all accounts |
| `SRC_BBB_AZBLOB_ACCOUNTKEY` | | Shared key for source storage accounts only |
| `DST_BBB_AZBLOB_ACCOUNTKEY` | | Shared key for destination storage accounts only |

### Multi-Tenant / Multi-Account Authentication (`SRC_` / `DST_` Env Vars)

When copying or syncing between Azure Storage accounts in **different tenants** (or using different credentials), prefix any standard Azure identity environment variable with `SRC_` or `DST_` to scope it to source or destination accounts respectively.

bbb uses `DefaultAzureCredential` under the hood, so all credential types are supported: service principal (secret or certificate), workload identity (OIDC / AKS), managed identity, and Azure CLI.

**Supported env vars** — prefix with `SRC_` or `DST_`:

| Variable | Category |
|----------|----------|
| `AZURE_CLIENT_ID` | Core identity |
| `AZURE_TENANT_ID` | Core identity |
| `AZURE_CLIENT_SECRET` | Service principal (secret) |
| `AZURE_CLIENT_CERTIFICATE_PATH` | Service principal (certificate) |
| `AZURE_CLIENT_CERTIFICATE_PASSWORD` | Service principal (certificate) |
| `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN` | Service principal (certificate) |
| `AZURE_FEDERATED_TOKEN_FILE` | Workload identity (OIDC / AKS) |
| `IDENTITY_ENDPOINT` | Managed identity |
| `IDENTITY_HEADER` | Managed identity |
| `MSI_ENDPOINT` | Managed identity |
| `MSI_SECRET` | Managed identity |
| `IMDS_ENDPOINT` | Managed identity |
| `AZURE_AUTHORITY_HOST` | Cloud / authority |
| `AZURE_USERNAME` | Developer cache hint |
| `AZURE_CONFIG_DIR` | Azure CLI integration |
| `BBB_AZBLOB_ACCOUNTKEY` | Shared key (bbb-specific) |

**Example — service principal per tenant:**

```bash
# Source tenant credentials
export SRC_AZURE_TENANT_ID=<tenant-a>
export SRC_AZURE_CLIENT_ID=<sp-a-id>
export SRC_AZURE_CLIENT_SECRET=<sp-a-secret>

# Destination tenant credentials
export DST_AZURE_TENANT_ID=<tenant-b>
export DST_AZURE_CLIENT_ID=<sp-b-id>
export DST_AZURE_CLIENT_SECRET=<sp-b-secret>

bbb cp az://src-account/container/ az://dst-account/container/
```

**Example — shared key per account:**

```bash
export SRC_BBB_AZBLOB_ACCOUNTKEY=<key-for-source>
export DST_BBB_AZBLOB_ACCOUNTKEY=<key-for-destination>

bbb sync az://src-account/data/ az://dst-account/data/
```

**Credential resolution order** (first match wins):

1. Role-specific env credential (`SRC_AZURE_*` / `DST_AZURE_*`) via `DefaultAzureCredential`
2. Shared key (`SRC_BBB_AZBLOB_ACCOUNTKEY` / `DST_BBB_AZBLOB_ACCOUNTKEY`, or `BBB_AZBLOB_ACCOUNTKEY`)
3. Tenant-specific AzureCLI credential (auto-discovered from storage endpoint)
4. Interactive browser login (fallback)

### `BBB_DNS_CACHE`

When enabled, bbb caches DNS resolution results in memory so that repeated connections to the same hostname (e.g. an Azure Storage endpoint) skip the DNS lookup. Cached entries expire after 5 minutes.

```bash
BBB_DNS_CACHE=1 bbb cp ./data/ az://myaccount/mycontainer/data/
```

**Caveats:**

- DNS records that change during the TTL window (e.g. IP rotations) will not be picked up until the cached entry expires.
- Because cached addresses are dialled as IP literals, Go's standard Happy Eyeballs (RFC 6555) connection racing is bypassed. For Azure Blob Storage endpoints (typically single-stack) this has no practical impact.

### Taskfile

A taskfile is a plain-text file with one `src dst` pair per line, separated by whitespace. Empty lines are ignored.

> **Note:** Paths containing spaces are not supported in the taskfile format because fields are split on whitespace. Use `cp` or `sync` with positional arguments instead for such paths.

Example `tasks.txt`:

```
./data/model.bin   az://myaccount/mycontainer/models/model.bin
./data/config.json az://myaccount/mycontainer/models/config.json
./data/vocab.txt   az://myaccount/mycontainer/models/vocab.txt
```

Use `--taskfile` to pass the file to `cp` or `sync`. Use `-` to read from stdin:

```bash
# Copy all pairs listed in the taskfile
bbb cp --taskfile tasks.txt

# Sync all pairs listed in the taskfile
bbb sync --taskfile tasks.txt

# Pipe pairs from another command
find ./models -name '*.bin' | awk '{print $0, "az://myaccount/mycontainer/"$0}' | bbb cp --taskfile -
```

### State file

A state file tracks completed work so interrupted operations can be resumed. Pass `--state` to `cp` or `sync` and re-run the same command after a failure — already-finished items are skipped automatically.

```bash
# Start a large copy with crash recovery
bbb cp --taskfile tasks.txt --state copy.state

# If the process is interrupted, re-run the exact same command.
# Completed files are skipped; only remaining work is executed.
bbb cp --taskfile tasks.txt --state copy.state
```

`--state` also works without `--taskfile`:

```bash
bbb cp --state copy.state ./huge-dataset/ az://myaccount/mycontainer/dataset/
```

The state file is a plain-text append-only log. Each successfully copied **file** is recorded as `src -> dst`, and when all files in a taskfile pair are finished the pair is marked complete with a `TASK\t` prefix so the entire pair can be skipped on resume:

```
./data/model.bin -> az://myaccount/mycontainer/models/model.bin
./data/config.json -> az://myaccount/mycontainer/models/config.json
TASK	./data/model.bin -> az://myaccount/mycontainer/models/model.bin
```

## Commands

### `ls` — List directory contents

List files and directories at a given path.

```
bbb ls [flags] [path]
```

| Flag | Description |
|------|-------------|
| `-l`, `--long` | Show file type, size, and modification time |
| `-a` | Include hidden files (entries starting with `.`) |
| `-s`, `--relative` | Show relative paths instead of full paths |
| `--machine` | Machine-readable tab-separated output |

**Examples:**

```bash
# List local directory
bbb ls /tmp/data/

# Long listing of an Azure Blob container
bbb ls -l az://myaccount/mycontainer/

# List Hugging Face repo files with relative paths
bbb ls -s hf://meta-llama/Llama-2-7b/
```

---

### `ll` — Long listing (alias for `ls -l`)

Aliases: `du`

```
bbb ll [flags] [path]
```

| Flag | Description |
|------|-------------|
| `-s`, `--relative` | Show relative paths |
| `--machine` | Machine-readable tab-separated output |

**Example:**

```bash
# Show sizes and timestamps of blobs in a container
bbb ll az://myaccount/mycontainer/models/
```

---

### `lstree` — Recursively list all files

Aliases: `lsr`

Recursively lists all files (not directories) under a path, with a summary of total count and size.

```
bbb lstree [flags] [path]
```

| Flag | Description |
|------|-------------|
| `-l`, `--long` | Show file type, size, and modification time |
| `-s`, `--relative` | Show relative paths |
| `--machine` | Machine-readable tab-separated output |

**Examples:**

```bash
# Recursively list all files under a local directory
bbb lstree /home/user/project/

# Machine-readable recursive listing of a blob container
bbb lstree --machine az://myaccount/mycontainer/data/
```

---

### `llr` — Long recursive file list

Equivalent to `lstree -l`.

```
bbb llr [flags] [path]
```

| Flag | Description |
|------|-------------|
| `-s`, `--relative` | Show relative paths |
| `--machine` | Machine-readable tab-separated output |

**Example:**

```bash
bbb llr az://myaccount/mycontainer/
```

---

### `cat` — Print file contents to stdout

```
bbb cat path [path ...]
```

**Examples:**

```bash
# Print a local file
bbb cat /tmp/config.yaml

# Print a blob from Azure
bbb cat az://myaccount/mycontainer/config.json

# Print multiple files
bbb cat file1.txt file2.txt
```

---

### `touch` — Create or ensure file exists

Creates empty files if they don't exist. For local files, also updates the modification timestamp. For Azure blobs, creates an empty blob only when it doesn't already exist — it does **not** update the timestamp on existing blobs.

```
bbb touch path [path ...]
```

**Examples:**

```bash
# Create an empty local file
bbb touch /tmp/newfile.txt

# Touch a blob in Azure
bbb touch az://myaccount/mycontainer/marker.txt
```

---

### `cp` — Copy files or directories

Aliases: `cpr`, `cptree`

Copy one or more source files/directories to a destination. Supports local and Azure Blob paths in any combination. Hugging Face (`hf://`) paths are supported as a **source only** (the `hf://` backend is read-only).

```
bbb cp [flags] src [src ...] dst
```

| Flag | Description |
|------|-------------|
| `--taskfile FILE` | Batch task file with one `src dst` pair per line; use `-` for stdin |
| `--state FILE` | State file for crash recovery / resuming interrupted operations |
| `-f` | Force overwrite existing files |
| `-q`, `--quiet` | Suppress output |
| `--concurrency N` | Number of concurrent transfers (default: CPU cores) |
| `--retry-count N` | Number of retries on failure (default: `0`) |

**Examples:**

```bash
# Copy a local file to Azure Blob Storage
bbb cp ./model.bin az://myaccount/mycontainer/models/model.bin

# Copy an entire directory to Azure
bbb cp ./data/ az://myaccount/mycontainer/data/

# Download from Azure to local
bbb cp az://myaccount/mycontainer/results/ ./results/

# Server-side copy between Azure containers
bbb cp az://myaccount/src-container/data/ az://myaccount/dst-container/data/

# Download from Hugging Face (hf:// is source-only)
bbb cp hf://meta-llama/Llama-2-7b/ ./llama-model/

# Copy multiple sources to one destination
bbb cp file1.txt file2.txt az://myaccount/mycontainer/uploads/

# Copy with higher concurrency and retries
bbb cp --concurrency 16 --retry-count 3 ./big-dataset/ az://myaccount/mycontainer/dataset/
```

#### Taskfile Mode

Use `--taskfile` to provide a file of `src dst` pairs (one per line). See [Taskfile](#taskfile) for the file format.

```bash
# From a file
bbb cp --taskfile tasks.txt

# From stdin (pipe)
echo "local.txt az://myaccount/c/remote.txt" | bbb cp --taskfile -
```

#### Crash Recovery with State File

Use `--state` to resume interrupted copies. See [State file](#state-file) for details.

```bash
# First run — starts copying and records progress
bbb cp --taskfile tasks.txt --state copy.state

# If interrupted, re-run the same command — already-copied files are skipped
bbb cp --taskfile tasks.txt --state copy.state
```

---

### `rm` — Remove files

```
bbb rm [flags] path [path ...]
```

| Flag | Description |
|------|-------------|
| `-f` | Ignore nonexistent files |
| `-q`, `--quiet` | Suppress output |
| `--concurrency N` | Number of concurrent deletions (default: CPU cores) |
| `--retry-count N` | Number of retries on failure (default: `0`) |

**Examples:**

```bash
# Remove a local file
bbb rm /tmp/old-file.txt

# Remove a blob from Azure
bbb rm az://myaccount/mycontainer/old-model.bin

# Force-remove (no error if missing)
bbb rm -f az://myaccount/mycontainer/maybe-exists.txt
```

---

### `rmtree` — Remove a directory tree

Aliases: `rmr`

Recursively deletes an entire directory and all of its contents.

```
bbb rmtree [flags] path
```

| Flag | Description |
|------|-------------|
| `-q`, `--quiet` | Suppress output |
| `--concurrency N` | Number of concurrent deletions (default: CPU cores) |
| `--retry-count N` | Number of retries on failure (default: `0`) |

**Examples:**

```bash
# Remove a local directory tree
bbb rmtree /tmp/scratch/

# Remove an Azure Blob virtual directory
bbb rmtree az://myaccount/mycontainer/old-experiment/
```

---

### `sync` — Synchronise two directory trees

Unidirectional sync: copies new and updated files from source to destination.

```
bbb sync [flags] src dst
```

| Flag | Description |
|------|-------------|
| `--taskfile FILE` | Batch task file with one `src dst` pair per line; use `-` for stdin |
| `--state FILE` | State file for crash recovery / resuming interrupted operations |
| `--dry-run` | Show what would be done without making changes |
| `--delete` | Delete destination files that don't exist in source |
| `-x`, `--exclude PATTERN` | Exclude files matching this regex pattern |
| `-q`, `--quiet` | Suppress output |
| `--concurrency N` | Number of concurrent transfers (default: CPU cores) |
| `--retry-count N` | Number of retries on failure (default: `0`) |

**Examples:**

```bash
# Sync a local directory to Azure
bbb sync ./data/ az://myaccount/mycontainer/data/

# Sync from Azure to local
bbb sync az://myaccount/mycontainer/data/ ./local-data/

# Mirror (delete extra files at destination)
bbb sync --delete ./source/ az://myaccount/mycontainer/dest/

# Preview changes without applying
bbb sync --dry-run ./data/ az://myaccount/mycontainer/data/

# Exclude certain file patterns
bbb sync --exclude '\.tmp$' ./project/ az://myaccount/mycontainer/project/

# Sync with taskfile and crash recovery (see Taskfile and State file sections above)
bbb sync --taskfile tasks.txt --state sync.state
```

---

### `md5sum` — Compute MD5 checksums

```
bbb md5sum path [path ...]
```

**Examples:**

```bash
# Checksum a local file
bbb md5sum ./model.bin

# Checksum an Azure blob
bbb md5sum az://myaccount/mycontainer/model.bin

# Checksum multiple files
bbb md5sum file1.txt file2.txt file3.txt
```

---

### `share` — Print browser-accessible link for a file

```
bbb share path
```

For Azure Blob paths, prints an Azure Portal link and a direct blob URL. For local files, prints a `file://` URL.

**Examples:**

```bash
# Get a shareable link for an Azure blob
bbb share az://myaccount/mycontainer/report.pdf
# Output:
#   Azure Portal: https://portal.azure.com/#blade/...
#   Direct Blob (if public): https://myaccount.blob.core.windows.net/mycontainer/report.pdf

# Get a file:// link for a local file
bbb share ./report.pdf
```

---

### `edit` — Open a file in your editor (local only)

Opens a local file in the editor specified by the `$EDITOR` environment variable (defaults to `vi`). Creates the file and parent directories if they don't exist. Remote paths (`az://`, `hf://`) are not supported.

```
bbb edit path
```

**Example:**

```bash
# Edit a local config file
bbb edit /etc/myapp/config.yaml
```

---

### `az mkcontainer` — Create an Azure Blob container

```
bbb az mkcontainer az://account/container
```

**Example:**

```bash
# Create a new Azure Blob container
bbb az mkcontainer az://myaccount/newcontainer
```

## License

See [LICENSE](LICENSE) for details.
