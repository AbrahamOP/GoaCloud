package services

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"goacloud/internal/models"
)

// ProxmoxService handles all Proxmox API interactions.
type ProxmoxService struct {
	db      *sql.DB
	skipTLS bool
}

// NewProxmoxService creates a new ProxmoxService.
func NewProxmoxService(db *sql.DB, skipTLS bool) *ProxmoxService {
	return &ProxmoxService{db: db, skipTLS: skipTLS}
}

func (p *ProxmoxService) tlsConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: p.skipTLS} //nolint:gosec
}

// GetStats fetches Proxmox node statistics and optionally the guest list.
func (p *ProxmoxService) GetStats(rawURL, configuredNode, tokenID, secret string, includeGuests bool, forceRealIPs bool) (models.ProxmoxStats, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}
	slog.Debug("ProxmoxStats baseURL", "url", baseURL)

	stats := models.ProxmoxStats{VMs: []models.VM{}}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	headers := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// 0. Auto-discover node
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	headers(reqNodes)
	respNodes, err := client.Do(reqNodes)
	if err != nil {
		return stats, fmt.Errorf("Network error (Nodes): %v", err)
	}
	bodyNodes, _ := io.ReadAll(respNodes.Body)
	respNodes.Body.Close()

	targetNode := configuredNode
	var nodeList models.PveNodesList
	if jsonErr := json.Unmarshal(bodyNodes, &nodeList); jsonErr == nil && len(nodeList.Data) > 0 {
		found := false
		firstAny := ""
		firstOnline := ""
		for _, n := range nodeList.Data {
			if firstAny == "" {
				firstAny = n.Node
			}
			if n.Status == "online" && firstOnline == "" {
				firstOnline = n.Node
			}
			if n.Node == configuredNode {
				found = true
				break
			}
		}
		if !found {
			if firstOnline != "" {
				slog.Info("Proxmox: node not found, using online node", "configured", configuredNode, "using", firstOnline)
				targetNode = firstOnline
			} else {
				slog.Info("Proxmox: no online node, using first available", "node", firstAny)
				targetNode = firstAny
			}
		}
	} else {
		slog.Warn("Proxmox: cannot decode node list", "status", respNodes.StatusCode, "body", string(bodyNodes))
	}

	// 1. Node Status
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes/%s/status", baseURL, targetNode), nil)
	headers(req)
	resp, err := client.Do(req)
	if err != nil {
		return stats, fmt.Errorf("Network error: %v", err)
	}
	bodyStatus, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return stats, fmt.Errorf("API Error Node Status (%s) HTTP %d: %s", targetNode, resp.StatusCode, string(bodyStatus))
	}

	var nodeStatus models.PveNodeStatus
	if err := json.Unmarshal(bodyStatus, &nodeStatus); err == nil {
		stats.CPU = int(nodeStatus.Data.CPU * 100)
		stats.RAMTotal = float64(nodeStatus.Data.Memory.Total) / 1024 / 1024 / 1024
		stats.RAMUsed = float64(nodeStatus.Data.Memory.Used) / 1024 / 1024 / 1024
		stats.RAMUsedStr = fmt.Sprintf("%.2f GB", stats.RAMUsed)
		stats.RAMTotalStr = fmt.Sprintf("%.2f GB", stats.RAMTotal)
		if stats.RAMTotal > 0 {
			stats.RAM = int((stats.RAMUsed / stats.RAMTotal) * 100)
		}
		storageTotal := float64(nodeStatus.Data.Rootfs.Total)
		storageUsed := float64(nodeStatus.Data.Rootfs.Used)
		if storageTotal > 0 {
			stats.Storage = int((storageUsed / storageTotal) * 100)
		}
	} else {
		slog.Error("JSON Decode Error Node Status", "error", err)
	}

	if includeGuests {
		var allGuests []models.VM

		fetchAPI := func(endpoint, kind string) {
			req, _ := http.NewRequest("GET", endpoint, nil)
			headers(req)
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					var vms models.PveVMList
					if err := json.NewDecoder(resp.Body).Decode(&vms); err == nil {
						for _, vm := range vms.Data {
							allGuests = append(allGuests, models.VM{
								ID:     vm.VMID,
								Name:   vm.Name,
								Status: vm.Status,
								Uptime: fmt.Sprintf("%dh", vm.Uptime/3600),
								IP:     "-",
								Type:   kind,
							})
						}
					}
				}
			}
		}

		fetchAPI(fmt.Sprintf("%s/api2/json/nodes/%s/qemu", baseURL, targetNode), "VM")
		fetchAPI(fmt.Sprintf("%s/api2/json/nodes/%s/lxc", baseURL, targetNode), "CT")

		stats.VMs = allGuests

		if forceRealIPs {
			var wg sync.WaitGroup
			for i := range stats.VMs {
				if stats.VMs[i].Status != "running" {
					continue
				}
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					ip, err := p.getGuestIP(client, baseURL, targetNode, tokenID, secret, stats.VMs[idx].Type, stats.VMs[idx].ID)
					if err == nil && ip != "" {
						stats.VMs[idx].IP = ip
					}
				}(i)
			}
			wg.Wait()
		} else {
			rows, err := p.db.Query("SELECT vmid, ip_address FROM vm_cache")
			if err == nil {
				defer rows.Close()
				ipMap := make(map[int]string)
				for rows.Next() {
					var vmid int
					var ip string
					if err := rows.Scan(&vmid, &ip); err == nil {
						ipMap[vmid] = ip
					}
				}
				for i := range stats.VMs {
					if val, ok := ipMap[stats.VMs[i].ID]; ok {
						stats.VMs[i].IP = val
					}
				}
			}
		}

		sort.Slice(stats.VMs, func(i, j int) bool {
			return stats.VMs[i].ID < stats.VMs[j].ID
		})
	}

	return stats, nil
}

// GetGuestDetail fetches detailed information about a specific VM/CT.
func (p *ProxmoxService) GetGuestDetail(rawURL, configuredNode, tokenID, secret, pveType, vmid string) (models.GuestDetail, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}

	var detail models.GuestDetail
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}

	headers := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	targetNode := configuredNode

	// Auto-discover node
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
	headers(reqNodes)
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList models.PveNodesList
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	urlStatus := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/status/current", baseURL, targetNode, pveType, vmid)
	req, _ := http.NewRequest("GET", urlStatus, nil)
	headers(req)
	resp, err := client.Do(req)
	if err != nil {
		return detail, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return detail, fmt.Errorf("API Status Error: %s", resp.Status)
	}

	var statusResp models.PveGuestStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return detail, err
	}

	d := statusResp.Data
	detail.ID, _ = strconv.Atoi(vmid)
	detail.Name = d.Name
	detail.Status = d.Status
	detail.Uptime = fmt.Sprintf("%dh", int(d.Uptime)/3600)
	detail.CPU = float64(int(d.CPU*10000)) / 100
	detail.Cores = d.CPUs
	detail.RAMUsed = fmt.Sprintf("%.2f GB", float64(d.Mem)/1024/1024/1024)
	detail.RAMTotal = fmt.Sprintf("%.2f GB", float64(d.MaxMem)/1024/1024/1024)
	if d.MaxMem > 0 {
		detail.RAMPercent = int((float64(d.Mem) / float64(d.MaxMem)) * 100)
	}
	detail.DiskUsed = fmt.Sprintf("%.2f GB", float64(d.Disk)/1024/1024/1024)
	detail.DiskTotal = fmt.Sprintf("%.2f GB", float64(d.MaxDisk)/1024/1024/1024)
	if d.MaxDisk > 0 {
		detail.DiskPercent = int((float64(d.Disk) / float64(d.MaxDisk)) * 100)
	}
	detail.Type = pveType

	// Config
	urlConfig := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/config", baseURL, targetNode, pveType, vmid)
	reqConfig, _ := http.NewRequest("GET", urlConfig, nil)
	headers(reqConfig)
	if respConfig, err := client.Do(reqConfig); err == nil && respConfig.StatusCode == 200 {
		defer respConfig.Body.Close()
		var configResp models.PveGuestConfigResponse
		if err := json.NewDecoder(respConfig.Body).Decode(&configResp); err == nil {
			if configResp.Data.Description != "" {
				detail.Note = configResp.Data.Description
			}
			if detail.Name == "" {
				if configResp.Data.Name != "" {
					detail.Name = configResp.Data.Name
				} else {
					detail.Name = configResp.Data.Hostname
				}
			}
			if detail.Cores == 0 && configResp.Data.Cores > 0 {
				detail.Cores = configResp.Data.Cores
			}
		}
	}

	return detail, nil
}

// FetchSyslog fetches syslog entries from the Proxmox node.
func (p *ProxmoxService) FetchSyslog(proxmoxURL, node, tokenID, tokenSecret string, start, limit int) []ProxmoxSyslogEntry {
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
		Timeout:   10 * time.Second,
	}
	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/syslog?start=%d&limit=%d", proxmoxURL, node, start, limit)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Data []ProxmoxSyslogEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	return result.Data
}

// ProxmoxSyslogEntry is a single Proxmox syslog line.
type ProxmoxSyslogEntry struct {
	N int    `json:"n"`
	T string `json:"t"`
}

// getGuestIP fetches the IP address of a running VM/CT.
func (p *ProxmoxService) getGuestIP(client *http.Client, baseURL, node, tokenID, secret, kind string, id int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiURL string
	if kind == "CT" {
		apiURL = fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/interfaces", baseURL, node, id)
	} else if kind == "VM" {
		apiURL = fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", baseURL, node, id)
	} else {
		return "", nil
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil
	}

	if kind == "CT" {
		var lxcResp models.PveLxcInterfacesResponse
		if err := json.NewDecoder(resp.Body).Decode(&lxcResp); err != nil {
			return "", err
		}
		for _, iface := range lxcResp.Data {
			if iface.Name != "lo" && iface.Inet != "" && iface.Inet != "127.0.0.1" {
				parts := strings.Split(iface.Inet, "/")
				if len(parts) > 0 {
					return parts[0], nil
				}
			}
		}
	} else if kind == "VM" {
		var qemuResp models.PveQemuInterfacesResponse
		if err := json.NewDecoder(resp.Body).Decode(&qemuResp); err != nil {
			return "", err
		}
		for _, iface := range qemuResp.Data.Result {
			if iface.Name != "lo" {
				for _, ip := range iface.IPAddresses {
					if ip.IPAddressType == "ipv4" && ip.IPAddress != "127.0.0.1" {
						return ip.IPAddress, nil
					}
				}
			}
		}
	}
	return "", nil
}
