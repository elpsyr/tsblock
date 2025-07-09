# tsblock

[![Licensed under GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![CI](https://github.com/ciffelia/tsblock/actions/workflows/ci.yaml/badge.svg)](https://github.com/ciffelia/tsblock/actions/workflows/ci.yaml)

tsblock prevents Tailscale from using specific network interfaces.

tsblock is developed to work around [tailscale/tailscale#7594](https://github.com/tailscale/tailscale/issues/7594). Currently, interfaces whose name matches `^vxlan\.calico$|^cali` are blocked. The pattern is hard-coded in [main.go](main.go).

## Requirements

- Tailscale must be running as a systemd service.
- tsblock must run as root. It is recommended to run tsblock as a systemd service.

## How it works

tsblock utilizes eBPF to drop packets sent from `tailscaled.service` systemd unit.

## Install

```
go build
sudo ./systemd/install.sh
sudo systemctl daemon-reload
sudo systemctl enable --now tsblock.service
```

## Uninstall

```
sudo systemctl disable --now tsblock.service
sudo ./systemd/uninstall.sh
```

## Architecture

### System Architecture

```mermaid
graph TB
    subgraph "User Space"
        A[tsblock Go Application] --> B[Tailscale Detection]
        A --> C[Network Interface Monitor]
        A --> D[eBPF Program Loader]
        
        B --> E["systemctl show tailscaled.service"]
        B --> F["proc/mounts parsing"]
        
        C --> G[netlink subscription]
        C --> H[Interface Pattern Matching]
        
        D --> I[eBPF Object Loading]
        D --> J[Cgroup Attachment]
    end
    
    subgraph "Kernel Space"
        K[eBPF Program] --> L[Packet Filtering]
        K --> M[Interface Map]
        
        L --> N[DROP/PASS Decision]
        M --> O[Blocked Interface Index]
    end
    
    subgraph "System Integration"
        P[systemd] --> Q[tailscaled.service]
        P --> R[tsblock.service]
        
        Q --> S[Tailscale Process]
        R --> A
        
        S --> T[Network Traffic]
    end
    
    A --> K
    T --> K
    H --> M
    
    style A fill:#e1f5fe
    style K fill:#f3e5f5
    style P fill:#e8f5e8
```

### Component Interaction

```mermaid
sequenceDiagram
    participant Main as tsblock main()
    participant CG as Cgroup Detection
    participant eBPF as eBPF Loader
    participant NL as Netlink Monitor
    participant Kernel as eBPF in Kernel
    participant TS as Tailscale Process
    
    Main->>CG: tailscaleCgroup()
    CG->>CG: cgroupMountPoint()
    CG->>CG: cgroupByService("tailscaled.service")
    CG-->>Main: return cgroup path
    
    Main->>eBPF: loadBpfObjects()
    eBPF->>Kernel: Load eBPF programs
    Kernel-->>eBPF: Programs loaded
    eBPF-->>Main: Objects ready
    
    Main->>eBPF: AttachCgroup(egress)
    eBPF->>Kernel: Attach to cgroup egress
    Kernel-->>eBPF: Attached
    
    Main->>eBPF: AttachCgroup(ingress)
    eBPF->>Kernel: Attach to cgroup ingress
    Kernel-->>eBPF: Attached
    
    Main->>NL: LinkSubscribe()
    NL->>NL: Subscribe to interface changes
    
    loop Interface Monitoring
        NL->>NL: Receive LinkUpdate
        NL->>NL: Check interface name pattern
        
        alt Interface matches ^cilium_|^lxc
            NL->>Kernel: blockInterface() - Add to map
            Kernel-->>NL: Interface blocked
        else Interface doesn't match
            NL->>Kernel: unblockInterface() - Remove from map
            Kernel-->>NL: Interface unblocked
        end
    end
    
    TS->>Kernel: Send network packet
    Kernel->>Kernel: Check interface in blocked map
    
    alt Interface blocked
        Kernel->>Kernel: DROP packet
    else Interface not blocked
        Kernel->>Kernel: PASS packet
        Kernel->>TS: Forward packet
    end
```
