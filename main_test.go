package main

import "testing"

func TestIsAzHTTPS(t *testing.T) {
	if !isAz("https://myacct.blob.core.windows.net/container") {
		t.Fatalf("expected https blob url to be treated as az path")
	}
	if isAz("https://example.com/file") {
		t.Fatalf("non-blob https url should not be treated as az path")
	}
}
