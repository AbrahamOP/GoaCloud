package services

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

// ListPlaybooks scans the given directory and returns a map of categories to playbook files.
func ListPlaybooks(dir string) (map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}

	playbooks := make(map[string][]string)
	playbooks["Général"] = []string{}

	for _, e := range entries {
		if e.IsDir() {
			subEntries, err := os.ReadDir(dir + "/" + e.Name())
			if err == nil {
				var subList []string
				for _, sub := range subEntries {
					if !sub.IsDir() && (strings.HasSuffix(sub.Name(), ".yml") || strings.HasSuffix(sub.Name(), ".yaml")) {
						subList = append(subList, e.Name()+"/"+sub.Name())
					}
				}
				if len(subList) > 0 {
					playbooks[e.Name()] = subList
				}
			}
		} else if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
			playbooks["Général"] = append(playbooks["Général"], e.Name())
		}
	}

	if len(playbooks["Général"]) == 0 {
		delete(playbooks, "Général")
	}

	return playbooks, nil
}

// RunPlaybook executes an ansible-playbook command and returns a streaming reader.
// The caller MUST call the returned cleanup function after consuming all output.
func RunPlaybook(playbookPath string, targetIP string, privateKey string) (io.ReadCloser, func(), error) {
	// Validate IP to prevent command injection via inventory parameter
	if ip := net.ParseIP(targetIP); ip == nil {
		return nil, nil, fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	tmpKey, err := os.CreateTemp("", "ansible-key-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp key: %v", err)
	}
	tmpKeyName := tmpKey.Name()

	if err := os.Chmod(tmpKeyName, 0600); err != nil {
		os.Remove(tmpKeyName)
		return nil, nil, fmt.Errorf("failed to chmod temp key: %v", err)
	}
	if _, err := tmpKey.WriteString(privateKey); err != nil {
		os.Remove(tmpKeyName)
		return nil, nil, fmt.Errorf("failed to write temp key: %v", err)
	}
	tmpKey.Close()

	cmd := exec.Command("ansible-playbook",
		"-i", fmt.Sprintf("%s,", targetIP),
		playbookPath,
		"--private-key", tmpKeyName,
		"--user", "root",
		"--ssh-common-args", "-o StrictHostKeyChecking=accept-new",
	)

	pr, pw, err := os.Pipe()
	if err != nil {
		os.Remove(tmpKeyName)
		return nil, nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		os.Remove(tmpKeyName)
		return nil, nil, err
	}

	go func() {
		cmd.Wait()
		pw.Close()
	}()

	cleanup := func() {
		os.Remove(tmpKeyName)
	}

	return pr, cleanup, nil
}
