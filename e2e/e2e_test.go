package e2e_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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
		// clean up
		stdout, err := runBBB("ls", "az://devstoreaccount1/test/")
		if err != nil {
			t.Fatal(err)
		}

		lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
		for _, line := range lines {
			_, err := runBBB("rm", line)
			if err != nil {
				t.Fatal(err)
			}
		}
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

		// ls
		{
			stdout, err := runBBB("ls", "az://devstoreaccount1/test")
			if err != nil {
				t.Fatal(err)
			}

			output := strings.TrimSpace(string(stdout))
			if output != fmt.Sprintf("az://devstoreaccount1/test/%s", tmpFile.Name()[len(os.TempDir())+1:])+"\naz://devstoreaccount1/test/testfile.txt" {
				t.Errorf("unexpected ls output: %s", output)
			}
		}
	}
}
