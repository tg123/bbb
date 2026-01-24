package e2e_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/tg123/bbb/internal/hf"
)

const (
	waitTimeout    = time.Second * 10
	azuriteAccount = "devstoreaccount1"
	azuriteHost    = azuriteAccount + ".blob.localhost:10000"
)

var (
	preferredHFFileNames = []string{"config.json", "README.md", "tokenizer.json"}
	hfAzCopyPrefix       = fmt.Sprintf("az://%s/test/hf-copy", azuriteAccount)
)

func parseMD5Output(out []byte) string {
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func waitForEndpointReady(addr string) {
	waitForEndpointReadyWithTimeout(addr, waitTimeout)
}

func waitForEndpointReadyWithTimeout(addr string, timeout time.Duration) {
	now := time.Now()
	timeout = max(timeout, waitTimeout)
	for {
		if time.Since(now) > timeout {
			log.Panic("timeout waiting for endpoint " + addr)
		}

		conn, err := net.Dial("tcp", addr)
		if err == nil {
			log.Printf("endpoint %s is ready", addr)
			conn.Close()
			break
		}
		time.Sleep(time.Second)
	}
}

func runCmd(cmd string, args ...string) (*exec.Cmd, io.Writer, io.Reader, error) {
	newargs := append([]string{cmd}, args...)
	newargs = append([]string{"-i0", "-o0", "-e0"}, newargs...)
	c := exec.Command("stdbuf", newargs...)
	c.Env = os.Environ()
	f, err := pty.Start(c)
	if err != nil {
		return nil, nil, nil, err
	}

	var buf bytes.Buffer
	r := io.TeeReader(f, &buf)
	go func() {
		_, _ = io.Copy(os.Stdout, r)
	}()

	log.Printf("starting %v", c.Args)

	return c, f, &buf, nil
}

func runAndGetStdout(cmd string, args ...string) ([]byte, error) {
	c, _, stdout, err := runCmd(cmd, args...)
	if err != nil {
		return nil, err
	}

	if err := c.Wait(); err != nil {
		return nil, err
	}

	return io.ReadAll(stdout)
}

func runBBB(args ...string) ([]byte, error) {

	bin := os.Getenv("BBB_TEST_BIN_PATH")
	if bin == "" {
		bin = "bbb"
	}

	return runAndGetStdout(bin, args...)
}

func bbbLs(path string, recursive bool) ([]string, error) {
	cmd := "ls"
	if recursive {
		cmd = "lsr"
	}
	stdout, err := runBBB(cmd, path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")

	if recursive {
		if len(lines) > 0 {
			last := strings.TrimSpace(lines[len(lines)-1])
			fields := strings.Fields(last)
			if len(fields) == 2 && fields[1] == "files" {
				lines = lines[:len(lines)-1]
			}
		}
	}

	filtered := make([]string, 0, len(lines))
	for _, l := range lines {
		l := strings.TrimSpace(l)
		if l == "" {
			continue
		}
		filtered = append(filtered, l)
	}

	return filtered, nil
}

func cleanFolder(t *testing.T, path string) {
	files, err := bbbLs(path, true)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("ls results:", files)
	for _, file := range files {
		t.Log("removing", file)
		_, err := runBBB("rm", file)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBasic(t *testing.T) {

	waitForEndpointReady(azuriteHost)

	// create container
	{
		_, err := runBBB("mkcontainer", "az://"+azuriteAccount+"/test")
		if err != nil {
			t.Fatal(err)
		}
	}

	// ls containers
	{
		stdout, err := runBBB("ls", "az://"+azuriteAccount+"/")
		if err != nil {
			t.Fatal(err)
		}

		output := strings.TrimSpace(string(stdout))

		if output != "az://"+azuriteAccount+"/test" {
			t.Errorf("unexpected ls output: %s", output)
		}
	}

	{
		stdout, err := runBBB("ls", "az://"+azuriteAccount)
		if err != nil {
			t.Fatal(err)
		}

		output := strings.TrimSpace(string(stdout))

		if output != "az://"+azuriteAccount+"/test" {
			t.Errorf("unexpected ls output: %s", output)
		}
	}

	{
		cleanFolder(t, "az://"+azuriteAccount+"/test")
	}

	{
		touchPath := "az://" + azuriteAccount + "/test/touched.txt"
		if _, err := runBBB("touch", touchPath); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs("az://"+azuriteAccount+"/test", false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{touchPath}
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files after touch: got %v, want %v", files, expected)
		}
		if _, err := runBBB("rm", touchPath); err != nil {
			t.Fatal(err)
		}
	}

	tmpFile, err := os.CreateTemp("", "bbb-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := []byte("hello world")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	// upload
	{
		_, err := runBBB("cp", tmpFile.Name(), "az://"+azuriteAccount+"/test")
		if err != nil {
			t.Fatal(err)
		}
	}

	// upload
	{
		_, err := runBBB("cp", tmpFile.Name(), "az://"+azuriteAccount+"/test/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}
	}

	// upload
	{
		_, err := runBBB("cp", tmpFile.Name(), "az://"+azuriteAccount+"/test/dir/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}
	}

	// ls
	{
		files, err := bbbLs("az://"+azuriteAccount+"/test", false)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			fmt.Sprintf("az://%s/test/%s", azuriteAccount, tmpFile.Name()[len(os.TempDir())+1:]),
			"az://" + azuriteAccount + "/test/dir",
			"az://" + azuriteAccount + "/test/testfile.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files: got %v, want %v", files, expected)
		}

	}

	// lsr
	{
		files, err := bbbLs("az://"+azuriteAccount+"/test", true)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			fmt.Sprintf("az://%s/test/%s", azuriteAccount, tmpFile.Name()[len(os.TempDir())+1:]),
			"az://" + azuriteAccount + "/test/dir/testfile.txt",
			"az://" + azuriteAccount + "/test/testfile.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files: got %v, want %v", files, expected)
		}
	}

	// cp az az
	{
		_, err := runBBB("cp", "az://"+azuriteAccount+"/test/testfile.txt", "az://"+azuriteAccount+"/test/testfile2.txt")
		if err != nil {
			t.Fatal(err)
		}

		files, err := bbbLs("az://"+azuriteAccount+"/test/testfile*", false)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			"az://" + azuriteAccount + "/test/testfile.txt",
			"az://" + azuriteAccount + "/test/testfile2.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files: got %v, want %v", files, expected)
		}
	}

	// cat
	{
		stdout, err := runBBB("cat", "az://"+azuriteAccount+"/test/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}

		output := string(stdout)
		if output != "hello world" {
			t.Errorf("unexpected cat output: %s", output)
		}
	}

	// md5sum
	{
		expected := fmt.Sprintf("%x", md5.Sum(content))
		stdout, err := runBBB("md5sum", "az://"+azuriteAccount+"/test/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseMD5Output(stdout); got != expected {
			t.Fatalf("unexpected az md5sum: got %s, want %s", got, expected)
		}
		stdout, err = runBBB("md5sum", tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		if got := parseMD5Output(stdout); got != expected {
			t.Fatalf("unexpected local md5sum: got %s, want %s", got, expected)
		}
	}

	// cat via http blob URL
	{
		httpURL := fmt.Sprintf("http://%s/test/testfile.txt", azuriteHost)
		stdout, err := runBBB("cat", httpURL)
		if err != nil {
			t.Fatal(err)
		}
		if string(stdout) != "hello world" {
			t.Errorf("unexpected cat output via http: %s", stdout)
		}
	}

	// download
	{
		downloadPath := tmpFile.Name() + ".downloaded"
		defer os.Remove(downloadPath)

		_, err := runBBB("cp", "az://"+azuriteAccount+"/test/testfile.txt", downloadPath)
		if err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(downloadPath)
		if err != nil {
			t.Fatal(err)
		}

		if string(data) != "hello world" {
			t.Errorf("unexpected downloaded file content: %s", data)
		}
	}

	// download via http blob URL
	{
		downloadPath := tmpFile.Name() + ".http.downloaded"
		defer os.Remove(downloadPath)

		httpURL := fmt.Sprintf("http://%s/test/testfile.txt", azuriteHost)
		if _, err := runBBB("cp", httpURL, downloadPath); err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(downloadPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "hello world" {
			t.Errorf("unexpected downloaded file content via http: %s", data)
		}
	}

	{
		localDir, err := os.MkdirTemp("", "bbb-touch-local-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(localDir)
		localFile := filepath.Join(localDir, "new.txt")
		if _, err := runBBB("touch", localFile); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(localFile)
		if err != nil {
			t.Fatalf("expected local file missing: %v", err)
		}
		if info.IsDir() {
			t.Fatalf("expected file got directory: %s", localFile)
		}
		if info.Size() != 0 {
			t.Fatalf("expected zero byte file, got %d", info.Size())
		}
	}

	{
		cleanFolder(t, "az://"+azuriteAccount+"/test/")
	}

	// cpr
	{
		localDir, err := os.MkdirTemp("", "bbb-cpr-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(localDir)

		if err := os.WriteFile(localDir+"/1.txt", content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(localDir+"/2.txt", content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(localDir+"/test", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(localDir+"/test/3.txt", content, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := runBBB("cpr", localDir, "az://"+azuriteAccount+"/test/"); err != nil {
			t.Fatal(err)
		}

		files, err := bbbLs("az://"+azuriteAccount+"/test", true)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			"az://" + azuriteAccount + "/test/1.txt",
			"az://" + azuriteAccount + "/test/2.txt",
			"az://" + azuriteAccount + "/test/test/3.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files after cpr: got %v, want %v", files, expected)
		}
	}

	// cpr to local
	{
		localOut, err := os.MkdirTemp("", "bbb-cpr-local-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(localOut)

		if _, err := runBBB("cpr", "az://"+azuriteAccount+"/test/", localOut); err != nil {
			t.Fatal(err)
		}

		expectedLocal := []string{
			"1.txt",
			"2.txt",
			"test/3.txt",
		}

		for _, rel := range expectedLocal {
			full := filepath.Join(localOut, rel)
			st, err := os.Stat(full)
			if err != nil {
				t.Fatalf("expected file missing: %s (%v)", full, err)
			}
			if st.IsDir() {
				t.Fatalf("expected file got dir: %s", full)
			}
			data, err := os.ReadFile(full)
			if err != nil {
				t.Fatalf("read failed: %s (%v)", full, err)
			}
			if string(data) != "hello world" {
				t.Fatalf("unexpected content in %s: %q", full, string(data))
			}
		}

		// Ensure no extra files (simple walk)
		collected := map[string]struct{}{}
		err = filepath.WalkDir(localOut, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := strings.CutPrefix(path, localOut+string(filepath.Separator))
			collected[rel] = struct{}{}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, rel := range expectedLocal {
			if _, ok := collected[rel]; !ok {
				t.Fatalf("missing expected file: %s", rel)
			}
			delete(collected, rel)
		}
		if len(collected) != 0 {
			t.Fatalf("unexpected extra files: %v", collected)
		}
	}

	t.Run("hf to az", func(t *testing.T) {
		repo := "hf-internal-testing/tiny-random-BertModel"
		files, err := hfListFiles(t, repo)
		if err != nil {
			if isNetworkError(err) {
				t.Skipf("huggingface unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatal("no huggingface files returned")
		}
		candidate := ""
		for _, name := range preferredHFFileNames {
			if slices.Contains(files, name) {
				candidate = name
				break
			}
		}
		if candidate == "" {
			candidate = files[0]
		}
		hfData, err := hfDownload(t, repo, candidate)
		if err != nil {
			if isNetworkError(err) {
				t.Skipf("huggingface unavailable: %v", err)
			}
			t.Fatal(err)
		}
		{
			expected := fmt.Sprintf("%x", md5.Sum(hfData))
			stdout, err := runBBB("md5sum", "hf://"+repo+"/"+candidate)
			if err != nil {
				t.Fatal(err)
			}
			if got := parseMD5Output(stdout); got != expected {
				t.Fatalf("unexpected hf md5sum: got %s, want %s", got, expected)
			}
		}
		dstPrefix := hfAzCopyPrefix
		cleanFolder(t, dstPrefix)
		if _, err := runBBB("cp", "hf://"+repo, dstPrefix); err != nil {
			t.Fatal(err)
		}
		normalized := strings.ReplaceAll(candidate, "\\", "/")
		azFile, err := url.JoinPath(strings.TrimSuffix(dstPrefix, "/"), normalized)
		if err != nil {
			t.Fatal(err)
		}
		list, err := bbbLs(dstPrefix, true)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(list, azFile) {
			t.Fatalf("expected az file missing: %s", azFile)
		}
		out, err := os.CreateTemp("", "bbb-hf-az-")
		if err != nil {
			t.Fatal(err)
		}
		outPath := out.Name()
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(outPath); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(outPath)
		if _, err := runBBB("cp", azFile, outPath); err != nil {
			t.Fatal(err)
		}
		azData, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(azData, hfData) {
			t.Fatalf("hf to az content mismatch for %s", candidate)
		}
	})

}

func TestHuggingFaceDownload(t *testing.T) {
	repo := "hf-internal-testing/tiny-random-BertModel"
	files, err := hfListFiles(t, repo)
	if err != nil {
		if isNetworkError(err) {
			t.Skipf("huggingface unavailable: %v", err)
		}
		t.Fatal(err)
	}
	tempDir, err := os.MkdirTemp("", "bbb-hf-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	if _, err := runBBB("cp", "hf://"+repo, tempDir); err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		localPath := filepath.Join(tempDir, filepath.FromSlash(file))
		localData, err := os.ReadFile(localPath)
		if err != nil {
			t.Fatalf("missing local file %s: %v", file, err)
		}
		remoteData, err := hfDownload(t, repo, file)
		if err != nil {
			if isNetworkError(err) {
				t.Skipf("huggingface unavailable: %v", err)
			}
			t.Fatalf("download failed for %s: %v", file, err)
		}
		if !bytes.Equal(localData, remoteData) {
			t.Fatalf("content mismatch for %s", file)
		}
	}
}

func hfListFiles(t *testing.T, repo string) ([]string, error) {
	ctx, cancel := hfTestContext(t)
	defer cancel()
	files, err := hf.ListFiles(ctx, hf.Path{Repo: repo})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	return files, nil
}

func hfDownload(t *testing.T, repo, file string) ([]byte, error) {
	ctx, cancel := hfTestContext(t)
	defer cancel()
	return hf.Download(ctx, hf.Path{Repo: repo, File: file})
}

func hfTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	if deadline, ok := t.Deadline(); ok {
		return context.WithDeadline(context.Background(), deadline)
	}
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func isNetworkError(err error) bool {
	var dnsErr *net.DNSError
	var urlErr *url.Error
	var opErr *net.OpError
	return errors.As(err, &dnsErr) || errors.As(err, &urlErr) || errors.As(err, &opErr)
}
