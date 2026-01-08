package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ListPlaybooks scans the "playbooks" directory and returns a map of categories to files
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
			// Scan subdirectory
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
	
	// Remove General if empty
	if len(playbooks["Général"]) == 0 {
		delete(playbooks, "Général")
	}

	return playbooks, nil
}

// RunPlaybook executes an ansible-playbook command
// Returns: stdout pipe, cleanup function, error
// The caller MUST call cleanup() after reading the output to remove the temp key.
func RunPlaybook(playbookPath string, targetIP string, privateKey string) (io.ReadCloser, func(), error) {

	// 1. Create Temp Private Key File
	tmpKey, err := os.CreateTemp("", "ansible-key-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp key: %v", err)
	}
    tmpKeyName := tmpKey.Name()
    
    // Cleanup helper
    cleanup := func() {
        os.Remove(tmpKeyName)
    }

	// Important: SSH requires strict permissions
    if err := os.Chmod(tmpKeyName, 0600); err != nil {
        cleanup()
        return nil, nil, fmt.Errorf("failed to chmod temp key: %v", err)
    }
	if _, err := tmpKey.WriteString(privateKey); err != nil {
        cleanup()
		return nil, nil, fmt.Errorf("failed to write temp key: %v", err)
	}
	tmpKey.Close()

    // Command Construction
    cmd := exec.Command("ansible-playbook", 
        "-i", fmt.Sprintf("%s,", targetIP), 
        playbookPath, 
        "--private-key", tmpKeyName,
        "--user", "root",
        "--ssh-common-args", "-o StrictHostKeyChecking=no",
    )
    
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        cleanup()
        return nil, nil, err
    }
    cmd.Stderr = cmd.Stdout // Merge stderr into stdout

    if err := cmd.Start(); err != nil {
        cleanup()
        return nil, nil, err
    }
    
    // We need to keep the file until the process is done.
    // The caller reads log stream (stdout). When stream ends (EOF), likely process is done.
    // However, technically Wait() is needed.
    // For simplicity in this specific "Fire & Stream" use case:
    // We provided a cleanup function. The Handler will call it when loop breaks.
    
    return stdout, cleanup, nil 
}

// Helper to clean up securely
func CleanupAnsibleKey(path string) {
    os.Remove(path)
}
