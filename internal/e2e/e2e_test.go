package e2e_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

const waitTimeout = time.Second * 10

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

	waitForEndpointReady("devstoreaccount1.blob.localhost:10000")

	// create container
	{
		_, err := runBBB("mkcontainer", "az://devstoreaccount1/test")
		if err != nil {
			t.Fatal(err)
		}
	}

	// ls containers
	{
		stdout, err := runBBB("ls", "az://devstoreaccount1/")
		if err != nil {
			t.Fatal(err)
		}

		output := strings.TrimSpace(string(stdout))

		if output != "az://devstoreaccount1/test" {
			t.Errorf("unexpected ls output: %s", output)
		}
	}

	{
		stdout, err := runBBB("ls", "az://devstoreaccount1")
		if err != nil {
			t.Fatal(err)
		}

		output := strings.TrimSpace(string(stdout))

		if output != "az://devstoreaccount1/test" {
			t.Errorf("unexpected ls output: %s", output)
		}
	}

	{
		cleanFolder(t, "az://devstoreaccount1/test")
	}

	{
		touchPath := "az://devstoreaccount1/test/touched.txt"
		if _, err := runBBB("touch", touchPath); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs("az://devstoreaccount1/test", false)
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
		_, err := runBBB("cp", tmpFile.Name(), "az://devstoreaccount1/test")
		if err != nil {
			t.Fatal(err)
		}
	}

	// upload
	{
		_, err := runBBB("cp", tmpFile.Name(), "az://devstoreaccount1/test/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}
	}

	// upload
	{
		_, err := runBBB("cp", tmpFile.Name(), "az://devstoreaccount1/test/dir/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}
	}

	// ls
	{
		files, err := bbbLs("az://devstoreaccount1/test", false)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			fmt.Sprintf("az://devstoreaccount1/test/%s", tmpFile.Name()[len(os.TempDir())+1:]),
			"az://devstoreaccount1/test/dir",
			"az://devstoreaccount1/test/testfile.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files: got %v, want %v", files, expected)
		}

	}

	// lsr
	{
		files, err := bbbLs("az://devstoreaccount1/test", true)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			fmt.Sprintf("az://devstoreaccount1/test/%s", tmpFile.Name()[len(os.TempDir())+1:]),
			"az://devstoreaccount1/test/dir/testfile.txt",
			"az://devstoreaccount1/test/testfile.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files: got %v, want %v", files, expected)
		}
	}

	// cp az az
	{
		_, err := runBBB("cp", "az://devstoreaccount1/test/testfile.txt", "az://devstoreaccount1/test/testfile2.txt")
		if err != nil {
			t.Fatal(err)
		}

		files, err := bbbLs("az://devstoreaccount1/test/testfile*", false)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			"az://devstoreaccount1/test/testfile.txt",
			"az://devstoreaccount1/test/testfile2.txt",
		}

		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files: got %v, want %v", files, expected)
		}
	}

	// cat
	{
		stdout, err := runBBB("cat", "az://devstoreaccount1/test/testfile.txt")
		if err != nil {
			t.Fatal(err)
		}

		output := string(stdout)
		if output != "hello world" {
			t.Errorf("unexpected cat output: %s", output)
		}
	}

	// download
	{
		downloadPath := tmpFile.Name() + ".downloaded"
		defer os.Remove(downloadPath)

		_, err := runBBB("cp", "az://devstoreaccount1/test/testfile.txt", downloadPath)
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
		cleanFolder(t, "az://devstoreaccount1/test/")
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

		if _, err := runBBB("cpr", localDir, "az://devstoreaccount1/test/"); err != nil {
			t.Fatal(err)
		}

		files, err := bbbLs("az://devstoreaccount1/test", true)
		if err != nil {
			t.Fatal(err)
		}

		expected := []string{
			"az://devstoreaccount1/test/1.txt",
			"az://devstoreaccount1/test/2.txt",
			"az://devstoreaccount1/test/test/3.txt",
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

		if _, err := runBBB("cpr", "az://devstoreaccount1/test/", localOut); err != nil {
			t.Fatal(err)
		}

		expectedLocal := []string{
			"1.txt",
			"2.txt",
			"test/3.txt",
		}

		for _, rel := range expectedLocal {
			full := localOut + "/" + rel
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
			rel, _ := strings.CutPrefix(path, localOut+"/")
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

}
