package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sandboxVMIDMin and sandboxVMIDMax bound the disposable restore-test VMID range.
// Any restore / reconfigure / destroy operation MUST target a VMID inside this
// range, enforced by isSandboxVMID below. This is the single, non-negotiable
// safety invariant of the whole restore-test engine: it makes it impossible for
// a bug to restore over, or destroy, a real production guest.
const (
	sandboxVMIDMin = 9500
	sandboxVMIDMax = 9599
)

// defaultRestoreStorage is the ONE storage literal of last resort for a
// restore-test guest, used only after the resolution order (override > pm.Storage >
// auto-detection) yielded nothing. The nominal path now passes a resolved storage
// from resolveRestoreStorage; this const is the floor, not the default.
const defaultRestoreStorage = "local-lvm"

// defaultSandboxBridge is the hard fallback bridge for sandbox interfaces. The
// isolation bridge is NEVER freely auto-detected (detectBridge returns the first
// Linux bridge, often vmbr0 = prod): the resolver uses an explicit override or
// pm.Bridge, and only falls back to this literal — chosen because the HomeLab
// isolation VLAN lives on vmbr1, preserving the pre-Jalon-2 posture.
const defaultSandboxBridge = "vmbr1"

// isSandboxVMID reports whether vmid is inside the disposable sandbox range
// [9500, 9599]. It is the guard checked before every destructive Proxmox call on
// the restore path. RestoreBackup, SetGuestNetworkVlan and DestroyGuest enforce it
// INTERNALLY (they refuse out-of-range VMIDs themselves). PowerAction is generic and
// dual-use (the dashboard power handler also calls it), so on the restore path the
// guard is carried by the engine's sandboxPowerAction wrapper, which calls this
// before forwarding. If it returns false, the caller MUST refuse to issue the
// request.
func isSandboxVMID(vmid int) bool {
	return vmid >= sandboxVMIDMin && vmid <= sandboxVMIDMax
}

// errNotSandbox builds the standard refusal error for an out-of-range VMID.
func errNotSandbox(op string, vmid int) error {
	return fmt.Errorf("refus de sûreté: %s sur VMID %d hors de la plage sandbox [%d,%d]",
		op, vmid, sandboxVMIDMin, sandboxVMIDMax)
}

// restoreClient builds an HTTP client and resolves the target node, the shared
// preamble of every destructive operation below.
func (p *ProxmoxService) restoreClient(rawURL, configuredNode, tokenID, secret string, timeout time.Duration) (*http.Client, string, string) {
	baseURL := p.hostBaseURL(rawURL)
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: p.tlsConfig()},
	}
	node := p.resolveNode(client, baseURL, configuredNode, tokenID, secret)
	return client, baseURL, node
}

// RestoreBackup restores a vzdump archive into a fresh guest at targetVMID.
//
// SAFETY: refuses immediately (no API call) if targetVMID is outside the sandbox
// range. archiveVolID is a Proxmox volid (e.g. "local:backup/vzdump-lxc-110-...").
// Returns the task UPID to poll with GetTaskStatus.
func (p *ProxmoxService) RestoreBackup(rawURL, node, tokenID, secret, pveType, archiveVolID string, targetVMID int, storage string) (string, error) {
	if !isSandboxVMID(targetVMID) {
		return "", errNotSandbox("restore", targetVMID)
	}
	if storage == "" {
		// The caller now passes a value resolved by resolveRestoreStorage; this is
		// only the floor for a programmatic empty call (defense in depth).
		storage = defaultRestoreStorage
	}

	client, baseURL, targetNode := p.restoreClient(rawURL, node, tokenID, secret, 60*time.Second)

	form := url.Values{}
	form.Set("vmid", fmt.Sprintf("%d", targetVMID))
	form.Set("storage", storage)
	// force=1 lets the restore overwrite an existing guest at targetVMID. We keep
	// it ON deliberately: the SAFETY of this overwrite does NOT rest on force, it
	// rests on two upstream invariants — (1) isSandboxVMID() guarantees targetVMID
	// is in the disposable [9500,9599] range (no production guest can ever live
	// there), and (2) pickFreeSandboxVMID() atomically reserves the VMID under a
	// global lock so no two concurrent tests can claim the same slot. force=0 would
	// be wrong here: a previous test's asynchronous destroy may not have fully
	// completed when we restore into a freshly-reserved slot, and force=0 would then
	// fail spuriously even though the slot is logically ours.
	form.Set("force", "1")

	var apiURL string
	if pveType == "lxc" {
		form.Set("ostemplate", archiveVolID)
		form.Set("restore", "1")
		apiURL = fmt.Sprintf("%s/api2/json/nodes/%s/lxc", baseURL, targetNode)
	} else {
		form.Set("archive", archiveVolID)
		apiURL = fmt.Sprintf("%s/api2/json/nodes/%s/qemu", baseURL, targetNode)
	}

	req, _ := http.NewRequest("POST", apiURL, strings.NewReader(form.Encode()))
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Data == "" {
		return "", fmt.Errorf("restore did not return an UPID: %s", string(body))
	}
	return out.Data, nil
}

// SetGuestNetworkVlan forces EVERY network interface of the sandbox guest onto an
// isolation VLAN BEFORE it is started, so a restored production guest can never
// reach the live network. It reads the current config, enumerates ALL netN keys
// (net0, net1, …) present in the restored archive, rewrites/adds the isolation tag
// on each (keeping name/bridge where possible), and PUTs them all back in a single
// config update.
//
// Forcing only net0 would be unsafe: a production archive may carry net1, net2…
// that would otherwise boot onto the live network and conflict / leak. The whole
// point of the isolation VLAN (a routed-nowhere cul-de-sac on OPNsense) only holds
// if NO interface escapes it.
//
// If the guest has no network interface at all, that is not an error — a guest
// without a NIC is isolated by definition.
//
// bridge is the DEDICATED sandbox bridge resolved by the caller (pm.SandboxBridgeName()
// — its own attribute, hard vmbr1 fallback, NEVER the creation bridge pm.Bridge). It
// is COUPLED to vlanTag: the isolation holds only if every NIC is forced onto the
// isolation VLAN AND onto a bridge that actually carries that VLAN — so the caller
// resolves the pair together and passes both here. An empty bridge floors to
// defaultSandboxBridge rather than ever emitting a bridgeless (or auto-prod-bridge)
// interface.
//
// SAFETY: refuses immediately (no API call) if vmid is outside the sandbox range.
func (p *ProxmoxService) SetGuestNetworkVlan(rawURL, node, tokenID, secret, pveType string, vmid, vlanTag int, bridge string) error {
	if !isSandboxVMID(vmid) {
		return errNotSandbox("set network vlan", vmid)
	}
	if bridge == "" {
		bridge = defaultSandboxBridge
	}

	client, baseURL, targetNode := p.restoreClient(rawURL, node, tokenID, secret, 15*time.Second)
	auth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// 1. Read current config and collect EVERY netN interface line.
	cfgURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d/config", baseURL, targetNode, pveType, vmid)
	reqGet, _ := http.NewRequest("GET", cfgURL, nil)
	auth(reqGet)
	respGet, err := client.Do(reqGet)
	currentNets := map[string]string{}
	if err == nil {
		defer respGet.Body.Close()
		if respGet.StatusCode == 200 {
			var cfgResp struct {
				Data map[string]any `json:"data"`
			}
			if json.NewDecoder(respGet.Body).Decode(&cfgResp) == nil {
				for k, v := range cfgResp.Data {
					if !isNetKey(k) {
						continue
					}
					if sv, ok := v.(string); ok {
						currentNets[k] = sv
					}
				}
			}
		}
	}

	// No interfaces found → guest is isolated of itself; nothing to neutralize.
	if len(currentNets) == 0 {
		return nil
	}

	// 2. Force the isolation tag on every interface, in a single PUT.
	form := url.Values{}
	for key, cur := range currentNets {
		form.Set(key, buildSandboxNetN(cur, pveType, vlanTag, bridge))
	}
	reqPut, _ := http.NewRequest("PUT", cfgURL, strings.NewReader(form.Encode()))
	auth(reqPut)
	reqPut.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	respPut, err := client.Do(reqPut)
	if err != nil {
		return err
	}
	defer respPut.Body.Close()
	if respPut.StatusCode < 200 || respPut.StatusCode >= 300 {
		body, _ := io.ReadAll(respPut.Body)
		return fmt.Errorf("API error %d: %s", respPut.StatusCode, string(body))
	}
	return nil
}

// isNetKey reports whether a config key is a network interface line (net0, net1,
// …). It matches "net" followed by one or more digits, and nothing else, so keys
// like "netfoo" or "net" alone are rejected.
func isNetKey(key string) bool {
	if !strings.HasPrefix(key, "net") {
		return false
	}
	suffix := key[len("net"):]
	if suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// buildSandboxNetN derives the netN string to apply to a single sandbox guest
// interface, forcing the given VLAN tag onto the given (sandbox) bridge AND cutting
// the carrier (link_down=1) whatever the guest type. It preserves the existing
// name/model fields when the current line is parseable, but always REWRITES the
// bridge to the sandbox bridge — a restored prod NIC must never keep its production
// bridge, even on the isolation VLAN. It is applied to every netN key of the guest.
// bridge is resolved by the caller (pm.SandboxBridgeName() — the dedicated sandbox
// attribute, never the creation bridge; hard vmbr1 fallback) and is COUPLED to
// vlanTag.
func buildSandboxNetN(current, pveType string, vlanTag int, bridge string) string {
	if bridge == "" {
		bridge = defaultSandboxBridge
	}
	if current == "" {
		if pveType == "lxc" {
			return fmt.Sprintf("name=eth0,bridge=%s,tag=%d,link_down=1", bridge, vlanTag)
		}
		return fmt.Sprintf("virtio,bridge=%s,tag=%d,link_down=1", bridge, vlanTag)
	}

	// net0 is a comma-separated list of key=value pairs, except QEMU's first
	// field which is the bare model (e.g. "virtio=AA:BB:..." or "virtio").
	parts := strings.Split(current, ",")
	out := make([]string, 0, len(parts)+2)
	hasBridge := false
	tagSet := false
	linkSet := false
	for _, raw := range parts {
		seg := strings.TrimSpace(raw)
		if seg == "" {
			continue
		}
		key := seg
		if i := strings.Index(seg, "="); i >= 0 {
			key = seg[:i]
		}
		switch strings.ToLower(key) {
		case "tag":
			out = append(out, fmt.Sprintf("tag=%d", vlanTag))
			tagSet = true
		case "link_down":
			// Force the carrier OFF, whatever the archive carried. link_down belongs to
			// BOTH schemas (qemu net[n] and pve-container net[n]), so LXC gets it too.
			out = append(out, "link_down=1")
			linkSet = true
		case "bridge":
			out = append(out, "bridge="+bridge)
			hasBridge = true
		default:
			out = append(out, seg)
		}
	}
	if !hasBridge {
		out = append(out, "bridge="+bridge)
	}
	if !tagSet {
		out = append(out, fmt.Sprintf("tag=%d", vlanTag))
	}
	// Defense in depth for EVERY guest type: a restored firewall/router (e.g. OPNsense)
	// tags VLANs internally and announces itself as gateway on every network; the
	// isolation VLAN alone does NOT contain it (incident 2026-06-28: restored OPNsense
	// lagged the whole infra). A restored LXC is just as dangerous in the general case:
	// it boots with the PRODUCTION network configuration of its original (static IP,
	// gateway, services) and would collide with the still-running production container
	// the moment the sandbox segment is alive. link_down=1 IS part of the pve-container
	// net[n] schema (it is not a QEMU-only option), so it applies to LXC as well, and it
	// guarantees NO frame leaves the sandbox NIC. The N3 healthcheck runs via the guest
	// agent (qm guest exec / pct exec), not the network, so it is unaffected.
	if !linkSet {
		out = append(out, "link_down=1")
	}
	return strings.Join(out, ",")
}

// DestroyGuest purges a sandbox guest (config + disks). This is the cleanup call
// that the restore-test engine defers to guarantee the disposable guest is never
// left behind to fill the disk.
//
// SAFETY: refuses absolutely (no API call) if vmid is outside the sandbox range.
// Returns the task UPID (may be empty if the API responds synchronously).
func (p *ProxmoxService) DestroyGuest(rawURL, node, tokenID, secret, pveType string, vmid int) (string, error) {
	if !isSandboxVMID(vmid) {
		return "", errNotSandbox("destroy", vmid)
	}

	gtype := "qemu"
	if pveType == "lxc" {
		gtype = "lxc"
	}

	client, baseURL, targetNode := p.restoreClient(rawURL, node, tokenID, secret, 30*time.Second)
	auth := func(req *http.Request) {
		req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	}

	// A guest cannot be destroyed while running — the DELETE returns 500
	// ("VM X is running - destroy failed"). Force-stop it first and wait until it
	// is actually stopped. Best-effort: a stop error (already stopped) is ignored.
	stopURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d/status/stop", baseURL, targetNode, gtype, vmid)
	stopReq, _ := http.NewRequest("POST", stopURL, nil)
	auth(stopReq)
	if stopResp, serr := client.Do(stopReq); serr == nil {
		stopResp.Body.Close()
	}
	statusURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d/status/current", baseURL, targetNode, gtype, vmid)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		sReq, _ := http.NewRequest("GET", statusURL, nil)
		auth(sReq)
		sResp, serr := client.Do(sReq)
		if serr != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		var st struct {
			Data struct {
				Status string `json:"status"`
			} `json:"data"`
		}
		_ = json.NewDecoder(sResp.Body).Decode(&st)
		sResp.Body.Close()
		if st.Data.Status == "stopped" {
			break
		}
		time.Sleep(2 * time.Second)
	}

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d?purge=1&destroy-unreferenced-disks=1",
		baseURL, targetNode, gtype, vmid)
	req, _ := http.NewRequest("DELETE", apiURL, nil)
	auth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Data string `json:"data"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Data, nil
}

// volIDBelongsToVMID reports whether a vzdump volid is an archive OF vmid. It is the
// pure guard of the retention pruning path: parseVMIDFromVolID reads the VMID encoded
// in the archive file name (vzdump-lxc-110-…), so a volid whose name does not carry
// the expected VMID is NEVER deletable, even if a storage listing mislabelled it.
func volIDBelongsToVMID(volID string, vmid int) bool {
	if volID == "" || vmid <= 0 {
		return false
	}
	return parseVMIDFromVolID(volID) == vmid
}

// DeleteBackupArchive deletes ONE vzdump archive from a Proxmox storage. It backs the
// per-target retention rotation (keep the N most recent archives) and lives here, with
// the other destructive Proxmox calls, because — like them — it carries its own safety
// guard: it refuses (no API call) any volid whose file name does not belong to
// expectedVMID, so a listing quirk or a future refactor can never delete the archives
// of another guest.
//
// Returns the task UPID when Proxmox answers asynchronously (may be empty).
func (p *ProxmoxService) DeleteBackupArchive(rawURL, node, tokenID, secret, storage, volID string, expectedVMID int) (string, error) {
	if !volIDBelongsToVMID(volID, expectedVMID) {
		return "", fmt.Errorf("refus de sûreté: suppression de l'archive %q qui n'appartient pas au VMID %d", volID, expectedVMID)
	}
	if storage == "" {
		return "", fmt.Errorf("suppression d'archive: storage non renseigné")
	}

	client, baseURL, targetNode := p.restoreClient(rawURL, node, tokenID, secret, 60*time.Second)

	apiURL := fmt.Sprintf("%s/api2/json/nodes/%s/storage/%s/content/%s",
		baseURL, url.PathEscape(targetNode), url.PathEscape(storage), url.PathEscape(volID))
	req, _ := http.NewRequest("DELETE", apiURL, nil)
	req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Data string `json:"data"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Data, nil
}

// waitForTask polls a Proxmox task UPID until it stops or the deadline passes.
// Returns the exit status ("OK" or an error string). It is a thin helper around
// GetTaskStatus used by the restore-test engine.
func (p *ProxmoxService) waitForTask(rawURL, node, tokenID, secret, upid string, timeout, poll time.Duration) (string, error) {
	if upid == "" {
		return "OK", nil
	}
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timeout en attente de la tâche %s", upid)
		}
		time.Sleep(poll)
		status, exit, err := p.GetTaskStatus(rawURL, node, tokenID, secret, upid)
		if err != nil {
			// transient — keep polling until the deadline
			continue
		}
		if status == "running" {
			continue
		}
		return exit, nil
	}
}
