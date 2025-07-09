package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cockroachdb/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf.c

var blockedIfacesName = regexp.MustCompile(`^vxlan\.calico$|^cali`)

type TsblockManager struct {
	mu                sync.RWMutex
	currentCgroup     string
	ebpfObjects       *bpfObjects
	egressLink        link.Link
	ingressLink       link.Link
	ctx               context.Context
	cancel            context.CancelFunc
	linkUpdateCh      chan netlink.LinkUpdate
	done              chan struct{}
	healthCheckTicker *time.Ticker
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memory limit: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	manager := &TsblockManager{
		ctx:               ctx,
		cancel:            cancel,
		linkUpdateCh:      make(chan netlink.LinkUpdate),
		done:              make(chan struct{}),
		healthCheckTicker: time.NewTicker(30 * time.Second),
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Initialize the manager
	if err := manager.initialize(); err != nil {
		log.Fatalf("failed to initialize tsblock manager: %v", err)
	}
	defer manager.cleanup()

	// Start background routines
	go manager.healthCheck()
	go manager.serviceMonitor()

	// Main event loop
	for {
		select {
		case <-sigCh:
			log.Println("received shutdown signal")
			return
		case <-ctx.Done():
			log.Println("context cancelled")
			return
		case u := <-manager.linkUpdateCh:
			if err := manager.handleLinkUpdate(&u); err != nil {
				log.Printf("error handling link update: %v", err)
			}
		}
	}
}

func (m *TsblockManager) initialize() error {
	tsCgroupPath, err := tailscaleCgroup()
	if err != nil {
		return errors.Wrap(err, "detect tailscaled cgroup path")
	}
	log.Printf("found cgroup for tailscale: %s\n", tsCgroupPath)

	m.mu.Lock()
	m.currentCgroup = tsCgroupPath
	m.mu.Unlock()

	return m.attachToCgroup(tsCgroupPath)
}

func (m *TsblockManager) attachToCgroup(cgroupPath string) error {
	// Load pre-compiled programs and maps into the kernel.
	m.ebpfObjects = &bpfObjects{}
	if err := loadBpfObjects(m.ebpfObjects, nil); err != nil {
		return errors.Wrap(err, "load eBPF objects")
	}
	log.Println("loaded eBPF programs and maps into the kernel")

	// Link eBPF programs to the cgroup.
	lEgress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: m.ebpfObjects.RestrictNetworkInterfacesEgress,
	})
	if err != nil {
		return errors.Wrap(err, "link restrict_network_interfaces_egress to the cgroup")
	}
	m.egressLink = lEgress

	lIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: m.ebpfObjects.RestrictNetworkInterfacesIngress,
	})
	if err != nil {
		m.egressLink.Close()
		return errors.Wrap(err, "link restrict_network_interfaces_ingress to the cgroup")
	}
	m.ingressLink = lIngress

	log.Println("attached eBPF programs to the cgroup")

	// Subscribe to link changes
	handleError := func(err error) {
		log.Printf("netlink error: %v", err)
	}
	if err := netlink.LinkSubscribeWithOptions(m.linkUpdateCh, m.done, netlink.LinkSubscribeOptions{
		ErrorCallback: handleError,
		ListExisting:  true,
	}); err != nil {
		return errors.Wrap(err, "subscribe to link changes")
	}
	log.Println("subscribed to link changes")

	return nil
}

func (m *TsblockManager) detachFromCgroup() {
	if m.egressLink != nil {
		m.egressLink.Close()
		m.egressLink = nil
	}
	if m.ingressLink != nil {
		m.ingressLink.Close()
		m.ingressLink = nil
	}
	if m.ebpfObjects != nil {
		m.ebpfObjects.Close()
		m.ebpfObjects = nil
	}
}

func (m *TsblockManager) reattachToCgroup() error {
	log.Println("reattaching to tailscaled cgroup...")

	// Detach from current cgroup
	m.detachFromCgroup()

	// Get new cgroup path
	tsCgroupPath, err := tailscaleCgroup()
	if err != nil {
		return errors.Wrap(err, "detect tailscaled cgroup path")
	}

	m.mu.Lock()
	m.currentCgroup = tsCgroupPath
	m.mu.Unlock()

	log.Printf("reattaching to new cgroup: %s\n", tsCgroupPath)
	return m.attachToCgroup(tsCgroupPath)
}

func (m *TsblockManager) cleanup() {
	log.Println("cleaning up tsblock manager...")

	if m.healthCheckTicker != nil {
		m.healthCheckTicker.Stop()
	}

	close(m.done)
	m.detachFromCgroup()

	log.Println("cleanup completed")
}

func (m *TsblockManager) healthCheck() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.healthCheckTicker.C:
			if err := m.validateCgroupHealth(); err != nil {
				log.Printf("health check failed: %v", err)
				if err := m.reattachToCgroup(); err != nil {
					log.Printf("failed to reattach to cgroup: %v", err)
				}
			}
		}
	}
}

func (m *TsblockManager) validateCgroupHealth() error {
	m.mu.RLock()
	currentCgroup := m.currentCgroup
	m.mu.RUnlock()

	// Check if current cgroup path still exists
	if _, err := os.Stat(currentCgroup); os.IsNotExist(err) {
		return errors.New("current cgroup path no longer exists")
	}

	// Check if tailscaled is still using the same cgroup
	expectedCgroup, err := tailscaleCgroup()
	if err != nil {
		return errors.Wrap(err, "failed to detect current tailscaled cgroup")
	}

	if currentCgroup != expectedCgroup {
		return errors.Newf("cgroup mismatch: current=%s, expected=%s", currentCgroup, expectedCgroup)
	}

	return nil
}

func (m *TsblockManager) serviceMonitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.checkTailscaledStatus(); err != nil {
				log.Printf("tailscaled status check failed: %v", err)
				if err := m.reattachToCgroup(); err != nil {
					log.Printf("failed to reattach after service check: %v", err)
				}
			}
		}
	}
}

func (m *TsblockManager) checkTailscaledStatus() error {
	// Check if tailscaled service is active
	if _, err := cgroupByService("tailscaled.service"); err != nil {
		return errors.Wrap(err, "tailscaled service not found or not active")
	}
	return nil
}

func (m *TsblockManager) handleLinkUpdate(u *netlink.LinkUpdate) error {
	if m.ebpfObjects == nil {
		return errors.New("eBPF objects not initialized")
	}

	return handleLinkUpdate(m.ebpfObjects.IfacesMap, u)
}

func handleLinkUpdate(ifacesMap *ebpf.Map, u *netlink.LinkUpdate) error {
	ifaceName := u.Link.Attrs().Name
	ifaceIdx := uint32(u.Index)

	switch u.Header.Type {
	case unix.RTM_NEWLINK:
		log.Printf("interface created or updated: %d (%s)\n", ifaceIdx, ifaceName)
		if blockedIfacesName.MatchString(ifaceName) {
			if err := blockInterface(ifacesMap, ifaceIdx); err != nil {
				return errors.Wrapf(err, "block interface %d (%s)", ifaceIdx, ifaceName)
			}
		} else {
			if err := unblockInterface(ifacesMap, ifaceIdx); err != nil {
				return errors.Wrapf(err, "unblock interface %d (%s)", ifaceIdx, ifaceName)
			}
		}

	case unix.RTM_DELLINK:
		log.Printf("interface removed: %d (%s)\n", ifaceIdx, ifaceName)
		if err := unblockInterface(ifacesMap, ifaceIdx); err != nil {
			return errors.Wrapf(err, "unblock interface %d (%s)", ifaceIdx, ifaceName)
		}

	default:
		return errors.Newf("received a netlink message of unknown type %x for interface %d (%s)", u.Header.Type, ifaceIdx, ifaceName)
	}

	return nil
}

func blockInterface(ifacesMap *ebpf.Map, ifaceIdx uint32) error {
	log.Printf("blocking interface: %d\n", ifaceIdx)

	if err := ifacesMap.Put(ifaceIdx, uint8(0)); err != nil {
		return errors.Wrap(err, "add an entry to ifacesMap")
	}

	return nil
}

func unblockInterface(ifacesMap *ebpf.Map, ifaceIdx uint32) error {
	log.Printf("unblocking interface: %d\n", ifaceIdx)

	if err := ifacesMap.Delete(ifaceIdx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return errors.Wrap(err, "remove an entry from ifacesMap")
	}

	return nil
}
