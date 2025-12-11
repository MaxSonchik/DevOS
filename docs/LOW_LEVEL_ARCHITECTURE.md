# DevOS — Низкоуровневая Архитектура

**Версия:** 1.0.0 | **Дата:** Декабрь 2025 | **Статус:** Low-Level Design Phase

---

## Оглавление

1. [Введение](#введение)
2. [Kernel Modifications](#kernel-modifications)
3. [System Boot & Initialization](#system-boot--initialization)
4. [DevOS Core Services Architecture](#devos-core-services-architecture)
5. [IPC & Socket Infrastructure](#ipc--socket-infrastructure)
6. [Filesystem Optimization](#filesystem-optimization)
7. [Process Scheduler](#process-scheduler)
8. [Security Enforcement Layer](#security-enforcement-layer)
9. [Device Management](#device-management)
10. [Performance Tuning](#performance-tuning)
11. [Monitoring & Observability](#monitoring--observability)
12. [Backward Compatibility](#backward-compatibility)

---

## Введение

### Проблема: "Просто настроенный Arch Linux"

**Текущее восприятие:**
```
Arch Linux + Calamares + d-env + d-guard + ... = DevOS
```

**Проблема:** Это может быть воспринято как простой spin-off, а не отдельная ОС.

### Решение: Уникальные Низкоуровневые Компоненты

DevOS должен отличаться **ниже уровня приложений**:

```
DevOS = Arch Linux (совместимость) + Уникальные Kernel & System Services
```

**Ключевые отличия:**

| Уровень | Arch Linux | DevOS |
|---------|-----------|-------|
| **Kernel** | Vanilla | Модифицированный (CONFIG_DEVOS, patches) |
| **Init** | systemd (стандартный) | systemd + devos-core.target |
| **Core Services** | Базовые | Специальные DevOS демоны |
| **IPC** | Standard D-Bus | Extended D-Bus + devos-socket |
| **FS** | ext4/btrfs | ext4 + devos-fs-cache |
| **Scheduler** | BORE/CFS | Оптимизированный для dev workload |
| **Security** | SELinux/AppArmor | SELinux + DevOS MAC policies |

---

## Kernel Modifications

### 1. Kernel Patching Strategy

**Подход:** Минимальные патчи поверх LTS ядра (не fork!)

```
Linux LTS Kernel (vanilla)
    ↓
DevOS Patches (добавляют функционал, не меняют ядро)
    ↓
DevOS Kernel (скомпилирован с DevOS CONFIG)
```

**Гарантия совместимости:**
- Все патчи имеют DEVOS_* префикс
- Патчи можно отключить через CONFIG_DEVOS=n
- Без патчей DevOS ядро = Arch Linux ядро

### 2. Kernel Configuration (CONFIG_DEVOS)

**Файл:** `core/kernel/devos.config`

```bash
# DevOS Kernel Build Configuration
# This extends standard Arch Linux kernel config

# ============================================
# DevOS Core Features
# ============================================
CONFIG_DEVOS=y                           # Enable DevOS subsystem

# DevOS monitoring & observability
CONFIG_DEVOS_MONITORING=y                # Enable devos-core monitoring
CONFIG_DEVOS_METRICS=y                   # Enable kernel metrics export
CONFIG_DEVOS_TRACE=y                     # Enable kernel tracing

# DevOS security features
CONFIG_DEVOS_MAC=y                       # DevOS MAC (Mandatory Access Control)
CONFIG_DEVOS_AUDIT_EXTENDED=y            # Extended audit capabilities
CONFIG_DEVOS_INTEGRITY=y                 # File integrity monitoring

# ============================================
# Performance Optimizations for Development
# ============================================

# Scheduler optimizations
CONFIG_SCHED_BORE=y                      # Boost on-demand scheduler
CONFIG_SCHED_AUTOGROUP=y                 # Auto task grouping for better latency
CONFIG_SCHED_TUNE=y                      # Scheduler tuning

# IO Optimization
CONFIG_BFQ_IO_IOSCHED=y                  # Budget Fair Queueing I/O scheduler
CONFIG_IOSCHED_BFQ_DEFAULT=y             # Use BFQ as default
CONFIG_BFQ_GROUP_IOSCHED=y               # BFQ cgroups support

# Memory optimization
CONFIG_SLAB_MERGE_DEFAULT=y              # Merge similar slab caches
CONFIG_SLUB_CPU_PARTIAL=y                # CPU-local partial slabs
CONFIG_LRU_GEN=y                         # Multi-generation LRU
CONFIG_HAVE_MEMORYLESS_NODES=y           # Support memoryless nodes

# ============================================
# Development-Oriented Features
# ============================================

# Container support
CONFIG_CGROUPS=y                         # Control groups v2
CONFIG_CGROUP_CPUACCT=y                  # CPU accounting
CONFIG_CGROUP_MEMORY=y                   # Memory cgroups
CONFIG_MEMCG_SWAP=y                      # Memory swap accounting
CONFIG_CPUSETS=y                         # CPU affinity

# Namespace support
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_PID_NS=y
CONFIG_IPC_NS=y
CONFIG_UTS_NS=y
CONFIG_USER_NS=y

# Tracing & debugging
CONFIG_FTRACE=y                          # Function tracing
CONFIG_KPROBES=y                         # Dynamic probes
CONFIG_UPROBES=y                         # User-space probes
CONFIG_TRACE_SYSCALLS=y                  # Syscall tracing

# ============================================
# Security Hardening
# ============================================

# Memory protection
CONFIG_SMACK=y                           # Simplified Mandatory Access Control
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_HARDENED_USERCOPY_FALLBACK=y

# Execution protection
CONFIG_DEF_MLOCK_LIMIT=65536             # Default mlock limit
CONFIG_HAVE_ARCH_HARDENED_USERCOPY=y
CONFIG_DEBUG_STRICT_USER_COPY_CHECKS=y

# Network security
CONFIG_NETFILTER=y
CONFIG_IP_NF_FILTER=y
CONFIG_NF_NAT=y

# ============================================
# Development Tools Support
# ============================================

# Debugging
CONFIG_DEBUG_INFO_DWARF4=y               # DWARF4 debug info
CONFIG_GDB_SCRIPTS=y                     # GDB scripts support
CONFIG_DEBUG_KERNEL=y                    # Kernel debugging

# Profiling
CONFIG_PERF_EVENTS=y
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_FRAME_POINTER=y                   # Frame pointers for profiling

# ============================================
# Standard Arch Linux Optimizations
# ============================================
CONFIG_MARCH=znver2                      # Modern CPU optimization
CONFIG_MTUNE=znver2
CONFIG_GENERIC_CPU=n

# Disable unnecessary features
CONFIG_ACPI_DEBUG=n
CONFIG_SELINUX_DEBUG=n
CONFIG_DEBUG_RODATA_TEST=n
```

### 3. DevOS Kernel Patches

**Директория:** `core/kernel/patches/`

```
patches/
├── 0001-devos-subsystem-core.patch
├── 0002-devos-monitoring-interface.patch
├── 0003-devos-mac-policies.patch
├── 0004-devos-scheduler-optimization.patch
├── 0005-devos-io-scheduler-tuning.patch
├── 0006-devos-audit-extension.patch
└── 0007-devos-secureboot-signing.patch
```

**Пример patch:** `0001-devos-subsystem-core.patch`

```patch
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -60,6 +60,7 @@ obj-y += kernel/
 obj-y += certs/
 obj-$(CONFIG_SECURITY) += security/
 obj-$(CONFIG_CRYPTO) += crypto/
+obj-$(CONFIG_DEVOS) += devos/

--- /dev/null
+++ b/kernel/devos/Kconfig
@@ -0,0 +1,15 @@
+config DEVOS
+	bool "DevOS subsystem support"
+	depends on EXPERT
+	help
+	  Enable DevOS kernel extensions for development-focused
+	  operating system functionality.
+	
+	  This includes enhanced monitoring, MAC policies, and
+	  performance optimizations specifically for developers.
```

**Применение патчей при сборке:**

```bash
# build-kernel.sh
cd linux-6.6

# Apply DevOS patches
for patch in ../patches/*.patch; do
    echo "Applying $patch..."
    patch -p1 < "$patch"
done

# Copy DevOS kernel config
cp ../devos.config .config

# Build kernel
make menuconfig
make -j$(nproc)
make modules_install
make install
```

### 4. Kernel Boot Parameters

**Файл:** `/boot/loader/entries/devos.conf` (для systemd-boot)

```ini
title   DevOS
linux   /vmlinuz-devos
initrd  /devos-microcode.img
initrd  /initramfs-devos.img
options root=/dev/mapper/devos-root rw
        rootflags=relatime,journal_checksum
        devos.features=core,monitoring,security
        devos.loglevel=notice
        devos.max_cpus=0
        devos.enable_cgroup_v2=1
```

**Параметры DevOS:**

| Параметр | Значение | Описание |
|----------|----------|---------|
| `devos.features` | core,monitoring,security | Какие DevOS фичи включить |
| `devos.loglevel` | debug/info/notice/warn/error | Уровень логирования DevOS |
| `devos.sysctl_tuning` | 0/1 | Применять оптимизации sysctl |
| `devos.enable_cgroup_v2` | 0/1 | Использовать cgroups v2 |
| `devos.io_scheduler` | bfq/cfg/deadline | I/O scheduler |

---

## System Boot & Initialization

### 1. Boot Sequence

```
┌──────────────────────────────────────────────────────┐
│ Firmware (BIOS/UEFI)                                 │
└──────────────┬───────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────┐
│ Bootloader (GRUB2 / systemd-boot)                   │
│ Load: kernel + initramfs + microcode                │
└──────────────┬───────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────┐
│ Kernel Initialization                               │
│ - Load DevOS patches                                │
│ - Initialize cgroups v2                             │
│ - Setup SELinux contexts                            │
│ - Mount filesystems                                 │
└──────────────┬───────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────┐
│ systemd (PID 1)                                      │
│ Load: devos-core.target                             │
└──────────────┬───────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────┐
│ DevOS Core Services Initialization                  │
│ - devos-monitord                                    │
│ - devos-secured                                     │
│ - devos-socketd                                     │
│ - devos-indexd                                      │
└──────────────┬───────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────┐
│ Standard systemd services                           │
│ - networkd, resolved, journald, udev                │
└──────────────┬───────────────────────────────────────┘
               ↓
┌──────────────────────────────────────────────────────┐
│ User Session (Desktop/TTY)                          │
│ - D-Bus session                                     │
│ - Desktop Environment (KDE/GNOME)                   │
└──────────────────────────────────────────────────────┘
```

### 2. Initramfs customization

**Файл:** `core/initramfs/hooks/devos.hook`

```bash
#!/bin/bash
# Custom initramfs hook for DevOS

build() {
    msg "Adding DevOS initialization..."
    
    # Add DevOS kernel modules
    add_module devos_core
    add_module devos_monitoring
    add_module devos_security
    
    # Add DevOS binaries for early boot
    add_binary /usr/lib/devos/early-init
    
    # Add DevOS configuration
    add_dir /etc/devos
    add_file /etc/devos/initramfs.conf
    
    # Custom init script
    add_file "$_d/devos-init" "/init-devos"
}

help() {
    cat <<HELPEOF
This hook loads DevOS kernel modules and initialization code
during early boot, before systemd takes over.
HELPEOF
}

build "$@"
```

**Init скрипт:** `core/initramfs/init-devos`

```bash
#!/bin/sh
# DevOS Early Boot Initialization

set -e

msg() {
    echo ">>> [DevOS] $*"
}

msg "Initializing DevOS subsystems..."

# 1. Load DevOS kernel parameters
if [ -f /etc/devos/initramfs.conf ]; then
    . /etc/devos/initramfs.conf
fi

# 2. Initialize early monitoring
msg "Starting kernel monitoring..."
echo 1 > /proc/sys/kernel/sched_schedstats

# 3. Setup cgroups v2 early
msg "Mounting cgroups v2..."
if [ ! -d /sys/fs/cgroup ]; then
    mkdir -p /sys/fs/cgroup
fi
mount -t cgroup2 none /sys/fs/cgroup

# 4. Apply security policies early
msg "Loading DevOS MAC policies..."
/usr/lib/devos/early-init security

# 5. Initialize device monitoring
msg "Setting up device monitoring..."
/usr/lib/devos/early-init devices

# 6. Continue with standard boot
msg "Passing control to systemd..."
exec /lib/systemd/systemd-stub
```

---

## DevOS Core Services Architecture

### 1. Core Services Overview

**4 основных демона, работающих ниже приложений:**

```
┌─────────────────────────────────────────────────┐
│ Applications & Development Tools                │
└──────────────┬──────────────────────────────────┘
               │
        ┌──────┴──────┬─────────┬──────────────┐
        ↓             ↓         ↓              ↓
┌──────────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐
│devos-monitord│ │devos-sec│ │devos-sock│ │devos-idx │
│(Monitoring)  │ │(Security)││(IPC)     │ │(Indexing)│
└──────────────┘ └─────────┘ └──────────┘ └──────────┘
        │             │         │              │
        └──────────────┴─────────┴──────────────┘
                      ↓
            ┌─────────────────────┐
            │  Linux Kernel       │
            │  (with DevOS mods)  │
            └─────────────────────┘
```

### 2. devos-monitord (Monitoring Daemon)

**Назначение:** Real-time kernel metrics collection и exposure

**Тип:** systemd service (Type=notify)

**Файл:** `core/services/devos-monitord.service`

```ini
[Unit]
Description=DevOS Kernel Monitoring Daemon
Documentation=man:devos-monitord(8)
After=systemd-modules-load.service
Before=devos-core.target

[Service]
Type=notify
ExecStartPre=/usr/lib/devos/devos-monitord --check-kernel
ExecStart=/usr/lib/devos/devos-monitord --daemon
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=5s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=devos-monitord

# Security settings
PrivateNetwork=no
PrivateDevices=no
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=256M
CPUQuota=20%

[Install]
WantedBy=devos-core.target
```

**Реализация:** `tools/devos-monitord/main.go`

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/devos/pkg/kernel"
	"github.com/devos/pkg/metrics"
)

func main() {
	// devos-monitord — kernel metrics aggregator
	// Exported via:
	// 1. /proc/devos/metrics (procfs interface)
	// 2. /run/devos/metrics.sock (Unix socket)
	// 3. Prometheus-compatible endpoint (localhost:9100/metrics/devos)

	ctx := context.Background()

	// 1. Check kernel version and DevOS support
	if !kernel.IsDevOSKernel() {
		fmt.Fprintf(os.Stderr, "ERROR: Kernel does not support DevOS\n")
		os.Exit(1)
	}

	// 2. Initialize metrics collectors
	collectors := []metrics.Collector{
		metrics.NewSchedulerMetrics(),       // CPU scheduler stats
		metrics.NewIOMetrics(),              // I/O performance
		metrics.NewMemoryMetrics(),          // Memory usage patterns
		metrics.NewSecurityMetrics(),        // MAC policy enforcement
		metrics.NewDevelopmentMetrics(),     // Dev-specific metrics
	}

	// 3. Start metrics collection
	aggregator := metrics.NewAggregator(collectors)
	if err := aggregator.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to start aggregator: %v\n", err)
		os.Exit(1)
	}

	// 4. Export via multiple interfaces
	go exportProcFS(aggregator)  // /proc/devos/metrics
	go exportSocket(aggregator)  // /run/devos/metrics.sock
	go exportPrometheus(aggregator) // :9100/metrics/devos

	// 5. Keep running
	select {}
}

// Metrics available:
// - devos_scheduler_latency_us (scheduler latency)
// - devos_io_throughput_bytes (I/O performance)
// - devos_memory_cache_hit_rate (cache efficiency)
// - devos_security_policy_violations (security events)
// - devos_dev_build_time_seconds (development metrics)
```

### 3. devos-secured (Security Daemon)

**Назначение:** Runtime enforcement of DevOS security policies

**Тип:** systemd service

**Файл:** `core/services/devos-secured.service`

```ini
[Unit]
Description=DevOS Security Policy Enforcement
Documentation=man:devos-secured(8)
After=systemd-modules-load.service
Before=devos-core.target

[Service]
Type=notify
ExecStartPre=/usr/lib/devos/devos-secured --validate-policies
ExecStart=/usr/lib/devos/devos-secured --daemon
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=5s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=devos-secured

# Must run as root for security enforcement
User=root
ProtectSystem=no
ProtectHome=no
PrivateNetwork=no

# Resource limits
MemoryMax=512M
CPUQuota=25%

[Install]
WantedBy=devos-core.target
```

**Реализация:** `tools/devos-secured/main.go`

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/devos/pkg/policies"
	"github.com/devos/pkg/selinux"
)

func main() {
	// devos-secured — SELinux/AppArmor policy enforcer
	// Manages:
	// 1. SELinux context enforcement
	// 2. File integrity monitoring (FIM)
	// 3. Process capability enforcement
	// 4. Audit rule management

	// 1. Load DevOS security policies
	policies.LoadDefaultPolicies("/etc/devos/security/policies")

	// 2. Initialize SELinux
	selinux.Initialize()

	// 3. Setup file integrity monitoring
	fim := policies.NewFileIntegrityMonitor()
	fim.Watch([]string{
		"/usr/bin",
		"/usr/lib",
		"/etc/devos",
		"/root/.ssh",
	})

	// 4. Start audit monitoring
	auditMonitor := policies.NewAuditMonitor()
	auditMonitor.Start()

	// 5. Watch for policy changes
	watchForPolicyUpdates()

	select {}
}
```

### 4. devos-socketd (Socket Daemon)

**Назначение:** Unified socket interface для IPC между DevOS компонентами

**Тип:** systemd socket-activated service

**Файл:** `core/services/devos.socket`

```ini
[Unit]
Description=DevOS Socket Interface
Documentation=man:devos-socketd(8)
Before=devos-core.target

[Socket]
ListenStream=/run/devos/devos.sock
ListenDatagram=/run/devos/devos.sock
SocketMode=0660
SocketUser=root
SocketGroup=devos

Accept=no

[Install]
WantedBy=sockets.target
```

**Сервис:** `core/services/devos-socketd.service`

```ini
[Unit]
Description=DevOS Socket Daemon
Documentation=man:devos-socketd(8)
Requires=devos.socket

[Service]
Type=notify
ExecStart=/usr/lib/devos/devos-socketd
StandardOutput=journal
StandardError=journal

Restart=on-failure
RestartSec=5s

MemoryMax=256M
CPUQuota=15%

[Install]
WantedBy=devos-core.target
```

**Реализация:** `tools/devos-socketd/main.go`

```go
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/devos/pkg/ipc"
)

func main() {
	// devos-socketd — IPC hub for all DevOS services
	// Protocol: JSON-RPC 2.0 over Unix sockets

	listener, err := net.Listen("unix", "/run/devos/devos.sock")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	// Register RPC handlers
	rpc := ipc.NewRPCServer()

	// Methods exposed via socket:
	rpc.Register("devos.metrics.get", handleMetrics)
	rpc.Register("devos.security.check", handleSecurityCheck)
	rpc.Register("devos.process.info", handleProcessInfo)
	rpc.Register("devos.system.status", handleSystemStatus)
	rpc.Register("devos.index.query", handleIndexQuery)

	// Start accepting connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go rpc.Handle(conn)
	}
}
```

**Socket API:**

```bash
# Example: Get system metrics via devos-socketd
$ nc -U /run/devos/devos.sock <<< '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "devos.metrics.get",
  "params": {"metric": "scheduler_latency"}
}'

# Response:
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "scheduler_latency_us": 42.5,
    "io_throughput_mbps": 850.3,
    "memory_cache_hit_rate": 0.94
  }
}
```

### 5. devos-indexd (Indexing Daemon)

**Назначение:** Fast filesystem indexing для dev tools (как locate, но оптимизировано)

**Тип:** systemd timer service

**Файл:** `core/services/devos-indexd.service`

```ini
[Unit]
Description=DevOS Filesystem Indexer
Documentation=man:devos-indexd(8)
After=devos-core.target

[Service]
Type=simple
ExecStart=/usr/lib/devos/devos-indexd --daemon
StandardOutput=journal
StandardError=journal

Restart=on-failure
RestartSec=10s

MemoryMax=512M
CPUQuota=10%
Nice=19

[Install]
WantedBy=devos-core.target
```

**Timer:** `core/services/devos-indexd.timer`

```ini
[Unit]
Description=DevOS Filesystem Index Update
Documentation=man:devos-indexd(8)

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Unit=devos-indexd.service

[Install]
WantedBy=timers.target
```

---

## IPC & Socket Infrastructure

### 1. D-Bus Extensions

**Дополнительный systemd D-Bus интерфейс:**

**Файл:** `core/services/org.devos.Manager1.conf`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
  "http://dbus.freedesktop.org/static/busconfig.dtd">

<busconfig>
  <policy context="default">
    <allow send_destination="org.devos.Manager1"/>
    <allow receive_sender="org.devos.Manager1"/>
  </policy>

  <!-- DevOS system policy -->
  <policy user="root">
    <allow send_destination="org.devos.Manager1"
           send_interface="org.devos.Manager1"
           send_member="*"/>
    <allow receive_sender="org.devos.Manager1"
           receive_interface="org.devos.Manager1"
           receive_member="*"/>
  </policy>
</busconfig>
```

**D-Bus interface:** `org.devos.Manager1`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
  "http://dbus.freedesktop.org/static/introspection.dtd">

<node name="/org/devos/Manager1">
  <interface name="org.devos.Manager1">
    <method name="GetMetrics">
      <arg name="metric" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
      <annotation name="org.freedesktop.DBus.Method.NoReply" value="false"/>
    </method>

    <method name="CheckSecurityPolicy">
      <arg name="process_id" type="u" direction="in"/>
      <arg name="result" type="b" direction="out"/>
    </method>

    <method name="GetProcessInfo">
      <arg name="process_id" type="u" direction="in"/>
      <arg name="info" type="a{sv}" direction="out"/>
    </method>

    <method name="QueryIndex">
      <arg name="query" type="s" direction="in"/>
      <arg name="results" type="as" direction="out"/>
    </method>

    <signal name="MetricsUpdated">
      <arg name="timestamp" type="t"/>
      <arg name="metrics" type="a{sv}"/>
    </signal>

    <signal name="SecurityEvent">
      <arg name="event_type" type="s"/>
      <arg name="process_id" type="u"/>
      <arg name="details" type="a{sv}"/>
    </signal>

    <property name="Version" type="s" access="read"/>
    <property name="Features" type="as" access="read"/>
  </interface>
</node>
```

### 2. DevOS Socket Protocol

**Unified protocol для всех сокетов:**

```
Connection: /run/devos/devos.sock
Protocol: JSON-RPC 2.0
Format: UTF-8 JSON lines

Authentication:
- PID/UID-based (kernel credentials)
- SELinux context validation
- D-Bus integration

Message format:
{
  "jsonrpc": "2.0",
  "id": <number or string>,
  "method": "<namespace>.<service>.<method>",
  "params": {<key>: <value>, ...}
}

Response format:
{
  "jsonrpc": "2.0",
  "id": <same as request>,
  "result": <value> or "error": {
    "code": <number>,
    "message": "<error message>"
  }
}
```

**Авторизация в сокете:**

```c
// kernel/devos/ipc.c
static bool devos_socket_authorize(struct socket *sock, const char *method) {
	// 1. Get process credentials
	struct sock_common *sk = sock->sk;
	struct cred *cred = sk->sk_peer_cred;

	// 2. Check SELinux context
	if (!devos_selinux_check(cred, method)) {
		return false;
	}

	// 3. Check D-Bus policy
	if (!devos_dbus_policy_check(cred, method)) {
		return false;
	}

	// 4. Rate limiting
	if (!devos_rate_limit_check(cred->uid, method)) {
		return false;
	}

	return true;
}
```

---

## Filesystem Optimization

### 1. ext4 Optimizations for DevOS

**Дополнительные флаги при форматировании:**

```bash
#!/bin/bash
# format-devos-filesystem.sh

DEVICE="/dev/vda1"
MOUNT_POINT="/"

# 1. Format ext4 с DevOS оптимизациями
mkfs.ext4 -F \
    -E resize=536870912,stride=32,stripe-width=32 \
    -O extent,filetype,sparse_super2,encrypt,metadata_csum,inline_data,large_file,dir_index,journal \
    "$DEVICE"

# 2. Tune параметры
tune2fs -c 0 -i 0 "$DEVICE"
tune2fs -O sparse_super2 "$DEVICE"

# 3. Mount с оптимальными опциями
mount -o relatime,journal_ioprio=3,nobarrier,inline_data,delalloc,max_batch_time=2000 "$MOUNT_POINT"
```

**Файл `/etc/fstab` с DevOS опциями:**

```
# Root filesystem
/dev/mapper/devos-root / ext4 relatime,journal_checksum,data=ordered,errors=remount-ro,nobarrier 0 1

# Home directory (separate volume)
/dev/mapper/devos-home /home ext4 relatime,journal_checksum,data=ordered,nobarrier 0 2

# Cache directory (tmpfs для ускорения)
tmpfs /var/cache tmpfs size=512M,mode=1777,nosuid,nodev,noexec 0 0

# Build directory (tmpfs для dev workload)
tmpfs /tmp tmpfs size=2G,mode=1777,nosuid,nodev 0 0
```

### 2. devos-fs-cache (Filesystem Cache Daemon)

**Назначение:** Интеллектуальное кэширование на основе dev workload patterns

**Реализация:** `tools/devos-fs-cache/main.go`

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/devos/pkg/workload"
)

func main() {
	// devos-fs-cache — intelligent filesystem caching
	// Preloads common dev files into page cache

	cache := NewDevelopmentCache()

	// 1. Learn workload patterns
	learner := workload.NewPatternLearner()
	patterns := learner.Learn("/home", 24*time.Hour)

	// 2. Pre-populate cache with predicted files
	for _, pattern := range patterns {
		files, _ := filepath.Glob(pattern.Path)
		for _, file := range files {
			preloadToCache(file)
		}
	}

	// 3. Monitor for workload changes
	watchWorkloadChanges(cache)
}

func preloadToCache(filePath string) {
	// Open file and read into page cache
	file, _ := os.Open(filePath)
	defer file.Close()

	// Use readahead syscall to preload
	syscall.SyscallN(unix.SYS_READAHEAD, uintptr(file.Fd()), 0, 1024*1024*100)
}
```

### 3. Filesystem Encryption (LUKS2)

**Automated LUKS2 setup для /home:**

```bash
#!/bin/bash
# setup-home-encryption.sh

DEVICE="/dev/vda2"
MAPPER_NAME="devos-home"

# 1. Format LUKS2
cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha256 \
    --iter-time 5000 \
    "$DEVICE"

# 2. Open encrypted volume
cryptsetup luksOpen "$DEVICE" "$MAPPER_NAME"

# 3. Format ext4
mkfs.ext4 "/dev/mapper/$MAPPER_NAME"

# 4. Create crypttab entry for automatic unlock
echo "$MAPPER_NAME UUID=$(blkid -s UUID -o value /dev/mapper/$MAPPER_NAME) none luks,x-systemd.device-timeout=0" >> /etc/crypttab
```

---

## Process Scheduler

### 1. BORE Scheduler Integration

**Kernel config:**

```
CONFIG_SCHED_BORE=y
CONFIG_SCHED_AUTOGROUP=y
CONFIG_SCHED_TUNE=y
```

**sysctl tuning:** `/etc/sysctl.d/99-devos-scheduler.conf`

```bash
# ============================================
# DevOS Scheduler Tuning
# ============================================

# BORE scheduler tuning
kernel.sched_bore=1                  # Enable BORE
kernel.sched_burst=100               # Burst boost level
kernel.sched_bore_latency_ratio=1500 # Latency target

# Autogroup tuning
kernel.sched_autogroup_enabled=1     # Enable auto grouping

# CFS tuning (fallback)
kernel.sched_migration_cost_ns=500000    # Task migration cost
kernel.sched_latency_ns=24000000         # Scheduling latency
kernel.sched_min_granularity_ns=3000000  # Minimal granularity
kernel.sched_wakeup_granularity_ns=4000000

# CPU affinity for development workload
kernel.sched_cpufreq_default=3       # schedutil governor

# Task scheduler features
kernel.sched_child_runs_first=1      # Child process scheduling
kernel.sched_compat_yield=0          # Disable compat mode
```

### 2. CGroup v2 Setup

**Автоматическая конфигурация cgroups v2:**

```bash
#!/bin/bash
# setup-cgroups-v2.sh

CGROUP_ROOT="/sys/fs/cgroup"

# 1. Mount cgroup v2
if ! grep -q cgroup2 /proc/mounts; then
	mount -t cgroup2 none "$CGROUP_ROOT"
fi

# 2. Create DevOS cgroup hierarchy
mkdir -p "$CGROUP_ROOT/devos"
mkdir -p "$CGROUP_ROOT/devos/dev-workload"
mkdir -p "$CGROUP_ROOT/devos/background-tasks"

# 3. Set resource limits
# Development workload: 80% of resources
echo "400:500" > "$CGROUP_ROOT/devos/dev-workload/cpu.max"
echo "2G" > "$CGROUP_ROOT/devos/dev-workload/memory.max"

# Background tasks: 20% of resources
echo "100:500" > "$CGROUP_ROOT/devos/background-tasks/cpu.max"
echo "512M" > "$CGROUP_ROOT/devos/background-tasks/memory.max"

# 4. Enable unified hierarchy
echo "+cpuset +cpu +cpuacct +memory +io +pids" > "$CGROUP_ROOT/cgroup.subtree_control"
```

### 3. Process Priority Management

**Файл:** `core/services/devos-scheduler.service`

```ini
[Unit]
Description=DevOS Process Scheduler Optimizer
After=devos-core.target

[Service]
Type=simple
ExecStart=/usr/lib/devos/devos-scheduler-daemon
Restart=on-failure

[Install]
WantedBy=devos-core.target
```

**Реализация:** `tools/devos-scheduler/main.go`

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	// devos-scheduler — dynamic process priority optimizer
	// Monitors dev workload and adjusts nice/ionice

	monitor := NewWorkloadMonitor()

	for workload := range monitor.Watch() {
		switch workload.Type {
		case "compilation":
			// Compilation: high priority (nice -10)
			setPriority(workload.PID, -10)
			setIOPriority(workload.PID, "realtime", 0)

		case "testing":
			// Testing: normal priority (nice 0)
			setPriority(workload.PID, 0)
			setIOPriority(workload.PID, "be", 4)

		case "build":
			// Build: high priority
			setPriority(workload.PID, -5)
			setIOPriority(workload.PID, "realtime", 1)

		default:
			// Other: background (nice 10)
			setPriority(workload.PID, 10)
			setIOPriority(workload.PID, "idle", 0)
		}
	}
}

func setPriority(pid int, nice int) {
	syscall.Setpriority(syscall.PRIO_PROCESS, pid, nice)
}
```

---

## Security Enforcement Layer

### 1. DevOS SELinux Policies

**Policy source:** `security/selinux/devos.te`

```selinux
# DevOS SELinux Policies

# Type definitions
type devos_t;
type devos_monitord_t;
type devos_secured_t;
type devos_socketd_t;
type devos_indexd_t;
type devos_tool_t;
type devos_cache_t;

# Attributes
attribute devos_domain;
attribute devos_file_type;

typeattribute devos_monitord_t devos_domain;
typeattribute devos_secured_t devos_domain;
typeattribute devos_socketd_t devos_domain;
typeattribute devos_indexd_t devos_domain;

# File contexts
type devos_runtime_t;
typeattribute devos_runtime_t devos_file_type;

type devos_config_t;
typeattribute devos_config_t devos_file_type;

# Rules: devos-monitord can read metrics
allow devos_monitord_t kernel_t:system { ptrace };
allow devos_monitord_t devos_runtime_t:file { read write open };

# Rules: devos-secured can enforce policies
allow devos_secured_t kernel_t:system { module_load };
allow devos_secured_t self:capability { dac_override };

# Rules: devos-socketd can communicate via sockets
allow devos_socketd_t devos_runtime_t:sock_file { read write };

# Tools can access their own runtime
allow devos_tool_t devos_runtime_t:file { read };

# Deny by default
dontaudit devos_domain kernel_t:system all_system_perms;
```

**File contexts:** `security/selinux/devos.fc`

```
/usr/lib/devos/.*                    -- system_u:object_r:devos_tool_t:s0
/etc/devos(/.*)?                        system_u:object_r:devos_config_t:s0
/run/devos(/.*)?                        system_u:object_r:devos_runtime_t:s0
/var/lib/devos(/.*)?                    system_u:object_r:devos_cache_t:s0
```

### 2. File Integrity Monitoring (FIM)

**Файл:** `core/services/devos-fim.service`

```ini
[Unit]
Description=DevOS File Integrity Monitor
After=devos-core.target

[Service]
Type=simple
ExecStart=/usr/lib/devos/devos-fim --daemon
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=10s

MemoryMax=256M

[Install]
WantedBy=devos-core.target
```

**Файл конфигурации:** `/etc/devos/fim.conf`

```yaml
# File Integrity Monitoring configuration

# System directories to watch
system_watch:
  - /usr/bin
  - /usr/lib
  - /etc/devos
  - /etc/security

# Home directory watch (selective)
home_watch:
  - ~/.ssh
  - ~/.gnupg
  - ~/.config/devos

# Development directories (less strict)
dev_watch:
  - /home/*/.local/share/dev
  - /opt/devos

# Monitoring parameters
check_interval: 3600  # Check every hour
hash_algorithm: sha256
alert_on_change: true
```

**Реализация:** `tools/devos-fim/main.go`

```go
package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type FileIntegrityMonitor struct {
	database map[string]string // path -> hash
	watchers []string
}

func (fim *FileIntegrityMonitor) Check() error {
	for _, watchPath := range fim.watchers {
		filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Calculate current hash
			content, _ := ioutil.ReadFile(path)
			currentHash := fmt.Sprintf("%x", sha256.Sum256(content))

			// Compare with stored hash
			if storedHash, exists := fim.database[path]; exists {
				if storedHash != currentHash {
					// File integrity violation!
					log.Printf("ALERT: File modified: %s", path)
					auditEvent("file_integrity_violation", path)
				}
			} else {
				// New file discovered
				fim.database[path] = currentHash
			}

			return nil
		})
	}

	return nil
}
```

---

## Device Management

### 1. Custom udev Rules

**Файл:** `core/udev/99-devos.rules`

```bash
# DevOS Custom udev Rules

# Label USB devices for dev use
SUBSYSTEMS=="usb", ATTRS{idVendor}=="1234", TAG+="devos-usb-dev"

# Enable high-speed I/O for SSDs
SUBSYSTEM=="block", ATTRS{queue/rotational}=="0", \
  RUN{program}+="/usr/lib/devos/optimize-ssd-io $devnode"

# Setup GPU devices for development
SUBSYSTEM=="drm", ATTRS{vendor}=="0x10de", ENV{DEVOS_GPU}="1"

# Monitor for security events
SUBSYSTEM=="hidraw", RUN+="/usr/lib/devos/audit-usb $devpath"

# Auto-mount development devices
SUBSYSTEM=="block", TAG+="devos-mount"
```

### 2. Device Monitoring Service

**Сервис:** `core/services/devos-devices.service`

```ini
[Unit]
Description=DevOS Device Monitor
After=devos-core.target

[Service]
Type=simple
ExecStart=/usr/lib/devos/devos-devices --daemon
Restart=on-failure

[Install]
WantedBy=devos-core.target
```

---

## Performance Tuning

### 1. swappiness & Memory Tuning

**Файл:** `/etc/sysctl.d/99-devos-memory.conf`

```bash
# ============================================
# DevOS Memory Tuning
# ============================================

# Reduce swap usage (dev workload needs fast memory)
vm.swappiness=10                         # Swap only if <10% free RAM

# Page cache tuning
vm.page-cluster=1                        # Reduce page clustering
vm.readahead_kb=256                      # Smaller readahead

# Memory overcommit (for containers)
vm.overcommit_memory=1                   # Allow overcommit for flexibility
vm.overcommit_ratio=50                   # Max 50% overcommit

# Page reclaim optimization
vm.extfrag_threshold=500                 # Fragmentation threshold
vm.zone_reclaim_mode=0                   # No zone reclaim (better locality)

# Drop caches for clean builds
vm.drop_caches=0                         # Keep caches by default
# Use: echo 3 > /proc/sys/vm/drop_caches for clean builds

# Dirty page tuning
vm.dirty_ratio=20                        # Flush at 20% dirty
vm.dirty_background_ratio=5              # BG flush at 5%
vm.dirty_expire_centisecs=3000           # Expire after 30s
vm.dirty_writeback_centisecs=500         # Writeback every 5s
```

### 2. IO Tuning

**Файл:** `/etc/sysctl.d/99-devos-io.conf`

```bash
# ============================================
# DevOS I/O Tuning
# ============================================

# BFQ I/O Scheduler parameters
# (if CONFIG_BFQ_IO_IOSCHED is enabled)

# File descriptor limits
fs.file-max=2097152                      # Max file descriptors
fs.inotify.max_user_watches=524288       # For file monitoring

# Network buffer tuning
net.core.rmem_default=262144
net.core.rmem_max=134217728
net.core.wmem_default=262144
net.core.wmem_max=134217728

# TCP tuning for dev environments
net.ipv4.tcp_tw_reuse=1                  # Reuse TIME_WAIT sockets
net.ipv4.tcp_fin_timeout=30
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=4096
```

### 3. CPU Power Management

**Файл:** `/etc/sysctl.d/99-devos-cpu.conf`

```bash
# ============================================
# DevOS CPU Power Management
# ============================================

# Use schedutil governor for dynamic frequency
kernel.cpufreq.default_governor=schedutil

# Allow CPU frequency scaling
kernel.cpu_freq.max_boost=100            # Allow CPU boost
kernel.cpu_freq.min_perf_pct=50          # Min 50% perf

# Power consumption balancing
kernel.power.energy_perf_bias=performance

# Disable CPU throttling for dev workload
kernel.nmi_watchdog=0                    # Disable watchdog interrupt
```

---

## Monitoring & Observability

### 1. Kernel Tracing (kprobes/uprobes)

**Динамические probe definition:**

```bash
#!/bin/bash
# core/services/devos-tracing-setup.sh

# Enable kernel tracing
echo 1 > /sys/kernel/debug/tracing/tracing_on

# Trace syscalls from d-env
echo 'p:devos_d_env_start /usr/bin/d-env' > /sys/kernel/debug/kprobes/new_event
echo 'r:devos_d_env_exit /usr/bin/d-env' >> /sys/kernel/debug/kprobes/new_event

# Trace filesystem operations
echo 'p:devos_fs_write vfs_write' > /sys/kernel/debug/tracing/kprobe_events
echo 'p:devos_fs_read vfs_read' >> /sys/kernel/debug/tracing/kprobe_events

# Enable trace events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable
```

### 2. SystemD Journal Integration

**Enhanced journaling:** `/etc/systemd/journald.conf`

```ini
[Journal]
# DevOS enhanced journaling

Storage=persistent
Compress=yes
Seal=yes

# Size limits
SystemMaxUse=4G
RuntimeMaxUse=1G

# Forward to syslog
ForwardToSyslog=yes

# Custom field filtering
# (store DevOS-specific metrics)
FilterExtraFields=DEVOS_METRIC DEVOS_WORKLOAD
```

---

## Backward Compatibility

### 1. Compatibility Matrix

| Компонент | Arch Linux | DevOS | Совместимость |
|-----------|-----------|-------|--------------|
| pacman | ✅ | ✅ | 100% |
| systemd | ✅ | ✅ + расширения | ✅ (backward compat) |
| Linux kernel | LTS vanilla | LTS + DevOS patches | ✅ (patches можно отключить) |
| Приложения | ✅ | ✅ | 100% |
| Services | базовые | + devos-* | ✅ (опциональные) |

### 2. Boot Without DevOS

**Если отключить DevOS на уровне kernel:**

```bash
# In GRUB or systemd-boot
kernel_devos_disable=1

# Or:
systemctl mask devos-core.target
systemctl mask devos-*.service

# System становится обычным Arch Linux
```

### 3. Миграция между версиями

**Upgrade path:**

```bash
# 1. Update kernel
pacman -S linux-devos-lts

# 2. Update services
pacman -S devos-core devos-services

# 3. Rebuild initramfs
mkinitcpio -P

# 4. Reboot
reboot
```

**Downgrade path:**

```bash
# 1. Remove DevOS packages
pacman -R devos-core devos-services

# 2. Install vanilla Arch kernel
pacman -S linux-lts

# 3. Rebuild initramfs
mkinitcpio -P

# 4. Reboot
reboot
```

---

## Implementation Roadmap

### Phase 1: Kernel & Boot (Weeks 1-4)

- [ ] Kernel patch preparation
- [ ] initramfs customization
- [ ] Boot sequence optimization
- [ ] Testing on VM

### Phase 2: Core Services (Weeks 5-8)

- [ ] devos-monitord implementation
- [ ] devos-secured implementation
- [ ] devos-socketd implementation
- [ ] Service integration tests

### Phase 3: Filesystem & Scheduler (Weeks 9-12)

- [ ] ext4 optimization
- [ ] devos-fs-cache implementation
- [ ] BORE scheduler integration
- [ ] cgroups v2 setup

### Phase 4: Security & Monitoring (Weeks 13-16)

- [ ] SELinux policy development
- [ ] FIM implementation
- [ ] Kernel tracing setup
- [ ] Security audit

### Phase 5: Testing & Documentation (Weeks 17-20)

- [ ] Performance benchmarks
- [ ] Compatibility testing
- [ ] Documentation completion
- [ ] Release preparation

---

## Conclusion

DevOS Low-Level Architecture transforms a stock Arch Linux system into a **uniquely optimized development OS** through:

1. **Kernel Modifications** — Performance-oriented configurations
2. **Core Services** — 4 specialized daemons for monitoring, security, IPC, and indexing
3. **Filesystem Optimization** — Intelligent caching and encryption
4. **Scheduler Tuning** — BORE scheduler + cgroups v2 for dev workload
5. **Security Layer** — SELinux policies + FIM + audit
6. **Complete Backward Compatibility** — Works with all Arch Linux packages

This approach answers the question: "Why is DevOS a separate distribution?"

**Answer:** Because DevOS includes kernel-level optimizations, specialized system daemons, and performance tuning that simply cannot be achieved with post-install configuration. It's a fundamentally different system architecture.

---

**Version:** 1.0.0  
**Status:** Architecture Phase  
**Last Updated:** December 2025
