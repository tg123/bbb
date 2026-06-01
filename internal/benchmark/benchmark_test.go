// Package benchmark_test compares bbb (this repo) upload/download/server-to-server
// throughput against azcopy and boostedblob (py-bbb) using the Azurite emulator.
//
// It is the Go port of the former benchmark.sh. Each tool's download is verified
// against the source file's MD5 so a corrupt or truncated transfer fails the run
// rather than being reported as a (fast but wrong) result.
//
// The emulator must already be running and reachable at
// https://${BENCH_ACCOUNT}.blob.core.windows.net (port 443). The Compose stack
// (docker-compose.yaml) runs Azurite as its own service and maps that host to it;
// setup-emulator.sh only arranges the TLS cert and trust. py-bbb (boostedblob)
// hardcodes that host, so all three tools are pointed at it for an
// apples-to-apples comparison. When the endpoint is not reachable (for example a
// plain `go test ./...` run) the benchmark skips itself.
//
// Environment:
//
//	BENCH_ACCOUNT      Storage account name             (default: devstoreaccount1)
//	BENCH_KEY          Shared key for the account
//	                   (default: the well-known Azurite key)
//	BENCH_CONTAINER    Container to use, created if missing (default: bench)
//	BENCH_SIZE_MB      Test file size in MiB             (default: 1024)
//	BENCH_RUNS         Timed runs per tool/direction     (default: 3)
//	BENCH_ATTEMPTS     Retries per timed run             (default: 3)
//	BENCH_CONCURRENCY  Concurrency passed to bbb/azcopy  (default: NumCPU)
//	BBB_BIN            Path to the bbb binary under test (default: bbb on PATH)
//	BBB_VERSION        Identifier shown for bbb in the report, e.g. the repo's
//	                   short commit sha (default: unset)
//	PYBBB              Command to invoke py-bbb           (default: python -m boostedblob)
//	AZCOPY_BIN         Path to azcopy                    (default: azcopy on PATH)
//	BENCH_FAIL_FACTOR  If set, fail when bbb is slower than the fastest other
//	                   tool by more than this factor (e.g. 1.05 = 5%). Empty =
//	                   report only.
//	BENCH_PYTHON       Python used to resolve the boostedblob version for the
//	                   report (best effort).             (default: python3)
//	BENCH_SUMMARY_FILE When set, the results table is also appended to this file.
package benchmark_test

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
)

const defaultAzuriteKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// config holds the resolved benchmark settings derived from the environment.
type config struct {
	account     string
	key         string
	container   string
	sizeMB      int
	runs        int
	attempts    int
	concurrency int
	bbbBin      string
	pybbb       []string
	azcopyBin   string
	failFactor  string
	summaryFile string

	host     string // ${account}.blob.core.windows.net
	blobHost string // https://${host}
}

func loadConfig() config {
	c := config{
		account:     envOr("BENCH_ACCOUNT", "devstoreaccount1"),
		key:         envOr("BENCH_KEY", defaultAzuriteKey),
		container:   envOr("BENCH_CONTAINER", "bench"),
		sizeMB:      envIntOr("BENCH_SIZE_MB", 1024),
		runs:        envIntOr("BENCH_RUNS", 3),
		attempts:    envIntOr("BENCH_ATTEMPTS", 3),
		concurrency: envIntOr("BENCH_CONCURRENCY", runtime.NumCPU()),
		bbbBin:      envOr("BBB_BIN", "bbb"),
		pybbb:       strings.Fields(envOr("PYBBB", "python -m boostedblob")),
		azcopyBin:   envOr("AZCOPY_BIN", "azcopy"),
		failFactor:  os.Getenv("BENCH_FAIL_FACTOR"),
		summaryFile: os.Getenv("BENCH_SUMMARY_FILE"),
	}
	c.host = c.account + ".blob.core.windows.net"
	c.blobHost = "https://" + c.host
	return c
}

func (c config) az(name string) string {
	return fmt.Sprintf("az://%s/%s/%s", c.account, c.container, name)
}

// result is a timed measurement for a single tool/direction. na marks a
// measurement that could not be taken (e.g. azcopy operations Azurite does not
// implement) so the rest of the table is still reported.
type result struct {
	na   bool
	secs float64
}

func (r result) seconds() string {
	if r.na {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", r.secs)
}

func (r result) mbps(sizeMB int) string {
	if r.na || r.secs <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", float64(sizeMB)/r.secs)
}

// timeCmd runs a command, discarding its stdout, and returns the wall-clock
// time it took. On failure it returns the elapsed time and an error carrying
// the tail of the command's stderr.
func timeCmd(name string, args ...string) (time.Duration, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, fmt.Errorf("command failed (%v): %s %s\n%s", err, name, strings.Join(args, " "), tailLines(stderr.String(), 30))
	}
	return elapsed, nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// bestOf runs fn cfg.runs times and returns the fastest duration. Each run is
// retried up to cfg.attempts times to tolerate transient Azurite flakes (HTTP
// 500 on PutBlockList etc.) without aborting the whole benchmark.
func bestOf(t *testing.T, cfg config, fn func() (time.Duration, error)) (time.Duration, error) {
	t.Helper()
	var best time.Duration
	haveBest := false
	for run := 0; run < cfg.runs; run++ {
		var (
			d       time.Duration
			ok      bool
			lastErr error
		)
		for attempt := 1; attempt <= cfg.attempts; attempt++ {
			d, lastErr = fn()
			if lastErr == nil {
				ok = true
				break
			}
			t.Logf("bestOf: attempt %d/%d failed: %v", attempt, cfg.attempts, lastErr)
		}
		if !ok {
			return 0, fmt.Errorf("aborting after %d attempts: %w", cfg.attempts, lastErr)
		}
		if !haveBest || d < best {
			best = d
			haveBest = true
		}
	}
	return best, nil
}

// runOrNA runs the timed benchmark and, for azcopy only, downgrades a failure
// to an "n/a" result so bbb and py-bbb numbers still get reported. Any other
// tool failing aborts the benchmark so real regressions aren't masked.
func runOrNA(t *testing.T, cfg config, tool string, fn func() (time.Duration, error)) result {
	t.Helper()
	d, err := bestOf(t, cfg, fn)
	if err != nil {
		if tool == "azcopy" {
			t.Logf("azcopy step failed, recording n/a: %v", err)
			return result{na: true}
		}
		t.Fatalf("%s step failed: %v", tool, err)
	}
	return result{secs: d.Seconds()}
}

func fileMD5(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// verifyMD5 fails the benchmark when file does not round-trip the source MD5,
// so a corrupt or truncated transfer can never be reported as a fast result.
func verifyMD5(t *testing.T, label, file, srcMD5 string) {
	t.Helper()
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("INTEGRITY: %s produced no downloaded file (%s)", label, file)
	}
	if got := fileMD5(t, file); got != srcMD5 {
		t.Fatalf("INTEGRITY: %s MD5 mismatch — expected %s, got %s", label, srcMD5, got)
	}
	t.Logf("%s round-trip MD5 OK", label)
}

// containerSAS mints a container SAS from the account key, mirroring the SAS the
// former benchmark.sh generated with azure-storage-blob for azcopy.
func containerSAS(t *testing.T, cfg config) string {
	t.Helper()
	cred, err := azblob.NewSharedKeyCredential(cfg.account, cfg.key)
	if err != nil {
		t.Fatalf("shared key credential: %v", err)
	}
	perms := (&sas.ContainerPermissions{
		Read: true, Add: true, Create: true, Write: true, Delete: true, List: true,
	}).String()
	qp, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		ContainerName: cfg.container,
		Permissions:   perms,
		ExpiryTime:    time.Now().UTC().Add(2 * time.Hour),
	}.SignWithSharedKey(cred)
	if err != nil {
		t.Fatalf("sign container SAS: %v", err)
	}
	return qp.Encode()
}

func toolVersionLabel(name, version string) string {
	if version == "" {
		return name
	}
	return fmt.Sprintf("%s (%s)", name, version)
}

func TestBenchmark(t *testing.T) {
	cfg := loadConfig()

	// Skip gracefully (e.g. on a plain `go test ./...`) when the emulator the
	// benchmark needs is not reachable.
	addr := net.JoinHostPort(cfg.host, "443")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Skipf("benchmark endpoint %s not reachable: %v", addr, err)
	}
	_ = conn.Close()

	// ---------------------------------------------------------------------
	// Per-tool auth.
	// ---------------------------------------------------------------------
	// bbb (this repo) talks to the production-style host via BBB_AZBLOB_ENDPOINT
	// and authenticates with the shared key.
	t.Setenv("BBB_AZBLOB_ENDPOINT", "https://%s.blob.core.windows.net/")
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", cfg.key)
	// py-bbb (boostedblob) uses AZURE_STORAGE_ACCOUNT(+_KEY) and the hardcoded host.
	t.Setenv("AZURE_STORAGE_ACCOUNT", cfg.account)
	t.Setenv("AZURE_STORAGE_ACCOUNT_KEY", cfg.key)
	// azcopy: keep its own log quiet.
	t.Setenv("AZCOPY_LOG_LEVEL", "ERROR")
	// bbb's S2S code path defaults to 256 parallel StageBlockFromURL calls,
	// which overwhelms Azurite's single-process loopback emulator. Cap it to the
	// same concurrency the other tools use so the benchmark stays stable.
	if os.Getenv("BBB_AZBLOB_COPY_CONCURRENCY_MAX") == "" {
		t.Setenv("BBB_AZBLOB_COPY_CONCURRENCY_MAX", strconv.Itoa(cfg.concurrency))
	}

	t.Logf("Ensuring container %s exists", cfg.container)
	_ = exec.Command(cfg.bbbBin, "az", "mkcontainer", fmt.Sprintf("az://%s/%s", cfg.account, cfg.container)).Run()

	saSig := containerSAS(t, cfg)

	workdir := t.TempDir()
	srcFile := filepath.Join(workdir, "testfile.bin")
	t.Logf("Generating %d MiB test file", cfg.sizeMB)
	if err := writeRandomFile(srcFile, cfg.sizeMB); err != nil {
		t.Fatalf("generate test file: %v", err)
	}
	srcMD5 := fileMD5(t, srcFile)
	t.Logf("Test file MD5: %s", srcMD5)

	// ---------------------------------------------------------------------
	// Per-tool transfer commands. Each tool gets its own blob name so runs do
	// not clobber one another.
	// ---------------------------------------------------------------------
	conc := strconv.Itoa(cfg.concurrency)
	azcopyBlob := func(name string) string {
		return fmt.Sprintf("%s/%s/%s?%s", cfg.blobHost, cfg.container, name, saSig)
	}

	type transfers struct {
		upload, download, s2s func() (time.Duration, error)
		downloadPath          string
		s2sBlob               string
	}

	tools := map[string]transfers{
		"bbb": {
			upload: func() (time.Duration, error) {
				return timeCmd(cfg.bbbBin, "cp", "-f", "--concurrency", conc, srcFile, cfg.az("bench-bbb.bin"))
			},
			download: func() (time.Duration, error) {
				return timeCmd(cfg.bbbBin, "cp", "-f", "--concurrency", conc, cfg.az("bench-bbb.bin"), filepath.Join(workdir, "dl-bbb.bin"))
			},
			s2s: func() (time.Duration, error) {
				return timeCmd(cfg.bbbBin, "cp", "-f", "--concurrency", conc, cfg.az("bench-bbb.bin"), cfg.az("bench-bbb-s2s.bin"))
			},
			downloadPath: filepath.Join(workdir, "dl-bbb.bin"),
			s2sBlob:      cfg.az("bench-bbb-s2s.bin"),
		},
		"pybbb": {
			upload: func() (time.Duration, error) {
				return timeCmd(cfg.pybbb[0], pybbbArgs(cfg, "cp", srcFile, cfg.az("bench-pybbb.bin"))...)
			},
			download: func() (time.Duration, error) {
				return timeCmd(cfg.pybbb[0], pybbbArgs(cfg, "cp", cfg.az("bench-pybbb.bin"), filepath.Join(workdir, "dl-pybbb.bin"))...)
			},
			s2s: func() (time.Duration, error) {
				return timeCmd(cfg.pybbb[0], pybbbArgs(cfg, "cp", cfg.az("bench-pybbb.bin"), cfg.az("bench-pybbb-s2s.bin"))...)
			},
			downloadPath: filepath.Join(workdir, "dl-pybbb.bin"),
			s2sBlob:      cfg.az("bench-pybbb-s2s.bin"),
		},
		"azcopy": {
			upload: func() (time.Duration, error) {
				return timeCmd(cfg.azcopyBin, "copy", srcFile, azcopyBlob("bench-azcopy.bin"), "--overwrite=true")
			},
			download: func() (time.Duration, error) {
				return timeCmd(cfg.azcopyBin, "copy", azcopyBlob("bench-azcopy.bin"), filepath.Join(workdir, "dl-azcopy.bin"), "--overwrite=true")
			},
			s2s: func() (time.Duration, error) {
				return timeCmd(cfg.azcopyBin, "copy", azcopyBlob("bench-azcopy.bin"), azcopyBlob("bench-azcopy-s2s.bin"), "--overwrite=true", "--s2s-preserve-access-tier=false")
			},
			downloadPath: filepath.Join(workdir, "dl-azcopy.bin"),
			s2sBlob:      cfg.az("bench-azcopy-s2s.bin"),
		},
	}

	order := []string{"bbb", "pybbb", "azcopy"}

	// Prime each upload once so the download benchmark has a blob to read and so
	// the first (often slower) connection setup is not counted in the timing.
	t.Log("Priming uploads")
	for _, tool := range order {
		if _, err := tools[tool].upload(); err != nil {
			t.Fatalf("%s upload failed during priming: %v", tool, err)
		}
	}

	up := map[string]result{}
	down := map[string]result{}
	s2s := map[string]result{}

	for _, tool := range order {
		tr := tools[tool]
		t.Logf("Benchmarking %s upload (%d runs)", tool, cfg.runs)
		up[tool] = runOrNA(t, cfg, tool, tr.upload)
		t.Logf("Benchmarking %s download (%d runs)", tool, cfg.runs)
		down[tool] = runOrNA(t, cfg, tool, tr.download)
	}

	// Integrity check: every tool's last download must round-trip the test file.
	t.Log("Verifying upload/download integrity (MD5)")
	verifyMD5(t, "bbb", tools["bbb"].downloadPath, srcMD5)
	verifyMD5(t, "py-bbb", tools["pybbb"].downloadPath, srcMD5)
	if !down["azcopy"].na {
		verifyMD5(t, "azcopy", tools["azcopy"].downloadPath, srcMD5)
	}

	for _, tool := range order {
		t.Logf("Benchmarking %s s2s copy (%d runs)", tool, cfg.runs)
		s2s[tool] = runOrNA(t, cfg, tool, tools[tool].s2s)
	}

	// Integrity check (S2S): each tool's S2S destination blob must match the
	// source MD5 when the S2S command succeeded.
	t.Log("Verifying S2S integrity (MD5)")
	for _, tool := range order {
		if s2s[tool].na {
			t.Logf("%s S2S skipped (command failed), not verifying", tool)
			continue
		}
		local := filepath.Join(workdir, "dl-"+tool+"-s2s.bin")
		if err := exec.Command(cfg.bbbBin, "cp", "-f", tools[tool].s2sBlob, local).Run(); err != nil {
			t.Fatalf("failed to download %s S2S output: %v", tool, err)
		}
		verifyMD5(t, tool+" (s2s)", local, srcMD5)
	}

	// ---------------------------------------------------------------------
	// Report.
	// ---------------------------------------------------------------------
	bbbLabel := "bbb (this repo)"
	if v := os.Getenv("BBB_VERSION"); v != "" {
		bbbLabel = fmt.Sprintf("bbb (%s)", v)
	}
	pybbbLabel := toolVersionLabel("boostedblob", boostedblobVersion())
	azcopyLabel := toolVersionLabel("azcopy", azcopyVersion(cfg.azcopyBin))

	var report strings.Builder
	fmt.Fprintf(&report, "### Transfer benchmark (Azurite emulator) — %d MiB, best of %d, concurrency %d\n\n", cfg.sizeMB, cfg.runs, cfg.concurrency)
	report.WriteString("| Tool | Upload (s) | Upload MB/s | Download (s) | Download MB/s | S2S Copy (s) | S2S MB/s |\n")
	report.WriteString("|------|-----------:|------------:|-------------:|--------------:|-------------:|---------:|\n")
	row := func(label, tool string) {
		fmt.Fprintf(&report, "| %s | %s | %s | %s | %s | %s | %s |\n",
			label,
			up[tool].seconds(), up[tool].mbps(cfg.sizeMB),
			down[tool].seconds(), down[tool].mbps(cfg.sizeMB),
			s2s[tool].seconds(), s2s[tool].mbps(cfg.sizeMB))
	}
	row(bbbLabel, "bbb")
	row(pybbbLabel, "pybbb")
	row(azcopyLabel, "azcopy")
	report.WriteString("\n")
	report.WriteString("> The Azurite emulator is CPU/loopback-bound, so absolute numbers measure client-side overhead rather than real network throughput. On Azurite, azcopy's S2S step always exits 1 because Azurite returns NotImplementedError on the PutBlobFromUrl API (Azure/Azurite#2402) — bbb and py-bbb each handle that case with a fallback (bbb falls back to StageBlockFromURL + CommitBlockList; py-bbb uses async StartCopyFromURL which Azurite acks instantly). S2S regressions are therefore not gated on Azurite — the only honest peer here is real Azure storage.\n")

	fmt.Print(report.String())
	if cfg.summaryFile != "" {
		if err := os.WriteFile(cfg.summaryFile, []byte(report.String()), 0o644); err != nil {
			t.Fatalf("write summary file %s: %v", cfg.summaryFile, err)
		}
	}

	// ---------------------------------------------------------------------
	// Cleanup blobs.
	// ---------------------------------------------------------------------
	t.Log("Cleaning up benchmark blobs")
	for _, name := range []string{"bench-bbb.bin", "bench-pybbb.bin", "bench-azcopy.bin", "bench-bbb-s2s.bin", "bench-pybbb-s2s.bin", "bench-azcopy-s2s.bin"} {
		_ = exec.Command(cfg.bbbBin, "rm", "-f", cfg.az(name)).Run()
	}

	// ---------------------------------------------------------------------
	// Optional regression gate. Only Upload and Download are gated — see the
	// report note above for why S2S can't be honestly gated on Azurite.
	// ---------------------------------------------------------------------
	if cfg.failFactor != "" {
		factor, err := strconv.ParseFloat(cfg.failFactor, 64)
		if err != nil {
			t.Fatalf("invalid BENCH_FAIL_FACTOR %q: %v", cfg.failFactor, err)
		}
		failed := false
		for _, dir := range []struct {
			name    string
			results map[string]result
		}{{"upload", up}, {"download", down}} {
			peers := []result{dir.results["pybbb"], dir.results["azcopy"]}
			best := -1.0
			for _, p := range peers {
				if p.na {
					continue
				}
				if best < 0 || p.secs < best {
					best = p.secs
				}
			}
			if best < 0 {
				t.Logf("skip %s gate (no peer baseline)", dir.name)
				continue
			}
			if dir.results["bbb"].secs > best*factor {
				t.Errorf("REGRESSION: bbb %s %.3fs is slower than %.3fs * %s", dir.name, dir.results["bbb"].secs, best, cfg.failFactor)
				failed = true
			}
		}
		if failed {
			t.FailNow()
		}
	}

	t.Log("Benchmark complete")
}

// pybbbArgs prepends any extra words from the (possibly multi-word) PYBBB
// command — e.g. "python -m boostedblob" — to the boostedblob subcommand args.
func pybbbArgs(cfg config, args ...string) []string {
	return append(append([]string{}, cfg.pybbb[1:]...), args...)
}

// writeRandomFile writes sizeMB MiB of random data to path in 1 MiB chunks.
func writeRandomFile(path string, sizeMB int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 1<<20)
	for i := 0; i < sizeMB; i++ {
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		if _, err := f.Write(buf); err != nil {
			return err
		}
	}
	return f.Close()
}

// boostedblobVersion resolves the installed boostedblob version for the report
// label on a best-effort basis (empty if it can't be determined).
func boostedblobVersion() string {
	python := envOr("BENCH_PYTHON", "python3")
	out, err := exec.Command(python, "-m", "pip", "show", "boostedblob").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return ""
}

// azcopyVersion resolves the installed azcopy version for the report label on a
// best-effort basis (empty if it can't be determined).
func azcopyVersion(bin string) string {
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}
