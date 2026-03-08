package models

import (
	"sync"
	"time"
)

// ProxmoxCache holds the last fetched Proxmox stats in memory.
type ProxmoxCache struct {
	Stats     ProxmoxStats
	UpdatedAt time.Time
	Mutex     sync.RWMutex
}

// VM represents a virtual machine or container.
type VM struct {
	ID     int
	Name   string
	Status string // running, stopped
	Uptime string
	IP     string
	Type   string // "VM" or "CT"
}

// ProxmoxStats holds node statistics and VM list.
type ProxmoxStats struct {
	CPU        int // Percentage
	RAM        int // Percentage
	RAMUsed    float64
	RAMTotal   float64
	RAMUsedStr string
	RAMTotalStr string
	Storage    int // Percentage
	VMs        []VM
}

// PveNode is a Proxmox node entry.
type PveNode struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

// PveNodesList is the list of nodes returned by the Proxmox API.
type PveNodesList struct {
	Data []PveNode `json:"data"`
}

// PveNodeStatus holds node status data from the Proxmox API.
type PveNodeStatus struct {
	Data struct {
		CPU    float64 `json:"cpu"`
		Memory struct {
			Total int64 `json:"total"`
			Used  int64 `json:"used"`
		} `json:"memory"`
		Rootfs struct {
			Total int64 `json:"total"`
			Used  int64 `json:"used"`
		} `json:"rootfs"`
	} `json:"data"`
}

// PveVM represents a VM/CT entry from the Proxmox API list.
type PveVM struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Uptime int    `json:"uptime"`
}

// PveVMList is the list returned by the Proxmox nodes/{node}/qemu or lxc endpoint.
type PveVMList struct {
	Data []PveVM `json:"data"`
}

// GuestDetail holds detailed information about a single VM/CT.
type GuestDetail struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	Uptime      string  `json:"uptime"`
	CPU         float64 `json:"cpu"`
	Cores       int     `json:"cores"`
	RAMUsed     string  `json:"ram_used"`
	RAMTotal    string  `json:"ram_total"`
	RAMPercent  int     `json:"ram_percent"`
	DiskUsed    string  `json:"disk_used"`
	DiskTotal   string  `json:"disk_total"`
	DiskPercent int     `json:"disk_percent"`
	Note        string  `json:"note"`
	Type        string  `json:"type"`
}

// PveGuestStatusResponse is the response from Proxmox status/current endpoint.
type PveGuestStatusResponse struct {
	Data struct {
		Name    string  `json:"name"`
		Status  string  `json:"status"`
		Uptime  float64 `json:"uptime"`
		CPUs    int     `json:"cpus"`
		CPU     float64 `json:"cpu"`
		Mem     int64   `json:"mem"`
		MaxMem  int64   `json:"maxmem"`
		Disk    int64   `json:"disk"`
		MaxDisk int64   `json:"maxdisk"`
	} `json:"data"`
}

// PveGuestConfigResponse is the response from the Proxmox config endpoint.
type PveGuestConfigResponse struct {
	Data struct {
		Name        string `json:"name"`
		Hostname    string `json:"hostname"`
		Description string `json:"description"`
		Cores       int    `json:"cores"`
		Memory      int    `json:"memory"`
	} `json:"data"`
}

// PveNetworkInterface represents a network interface from QEMU guest agent.
type PveNetworkInterface struct {
	Name        string `json:"name"`
	IPAddresses []struct {
		IPAddress     string `json:"ip-address"`
		IPAddressType string `json:"ip-address-type"`
	} `json:"ip-addresses"`
}

// PveLxcInterfacesResponse is the response for LXC network interfaces.
type PveLxcInterfacesResponse struct {
	Data []struct {
		Name string `json:"name"`
		Inet string `json:"inet"`
	} `json:"data"`
}

// PveQemuInterfacesResponse is the response for QEMU network interfaces.
type PveQemuInterfacesResponse struct {
	Data struct {
		Result []PveNetworkInterface `json:"result"`
	} `json:"data"`
}
