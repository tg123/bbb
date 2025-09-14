package e2e_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

const waitTimeout = time.Second * 10

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

func runCmdAndWait(cmd string, args ...string) error {
	c, _, _, err := runCmd(cmd, args...)
	if err != nil {
		return err
	}

	return c.Wait()
}

func waitForStdoutContains(stdout io.Reader, text string, cb func(string)) {
	st := time.Now()
	for {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, text) {
				cb(line)
				return
			}
		}

		if time.Since(st) > waitTimeout {
			log.Panicf("timeout waiting for [%s] from prompt", text)
			return
		}

		time.Sleep(time.Second) // stdout has no data yet
	}
}

func killCmd(c *exec.Cmd) {
	if c.Process != nil {
		if err := c.Process.Kill(); err != nil {
			log.Printf("failed to kill ssh process, %v", err)
		}
	}
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
	}
}
