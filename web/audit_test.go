package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditChainVerifyClean(t *testing.T) {
	dir := t.TempDir()
	a := newAuditor(dir)
	a.log("login", "alice", "1.1.1.1", "")
	a.log("sent", "alice", "1.1.1.1", "bob")
	a.log("logout", "alice", "1.1.1.1", "")
	if err := a.verify(); err != nil {
		t.Fatalf("verify clean log: %v", err)
	}
}

func TestAuditTamperDetected(t *testing.T) {
	dir := t.TempDir()
	a := newAuditor(dir)
	a.log("login", "alice", "1.1.1.1", "")
	a.log("sent", "alice", "1.1.1.1", "bob")
	a.log("logout", "alice", "1.1.1.1", "")

	logPath := filepath.Join(dir, "audit.log")
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], "bob", "eve", 1) // edit a recipient
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.verify(); err == nil {
		t.Fatal("expected tamper to be detected")
	}
}

func TestAuditTruncationDetected(t *testing.T) {
	dir := t.TempDir()
	a := newAuditor(dir)
	a.log("e1", "u", "", "")
	a.log("e2", "u", "", "")
	a.log("e3", "u", "", "")

	// Drop the last entry but leave the head pointing at seq 3.
	logPath := filepath.Join(dir, "audit.log")
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if err := os.WriteFile(logPath, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.verify(); err == nil {
		t.Fatal("expected tail truncation to be detected via head pointer")
	}
}

func TestAuditChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a := newAuditor(dir)
	a.log("e1", "u", "", "")
	a.log("e2", "u", "", "")

	// New auditor over the same dir resumes the chain; further entries verify.
	b := newAuditor(dir)
	b.log("e3", "u", "", "")
	if err := b.verify(); err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
}
