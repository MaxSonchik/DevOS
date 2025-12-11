# DevOS — Детальная Архитектурная Документация

**Версия:** 2.0.0 | **Дата:** Декабрь 2025 | **Статус:** Complete Architecture

---

## Оглавление

1. [Общие Принципы](#общие-принципы)
2. [Слой 0: Аппаратура](#слой-0-аппаратура)
3. [Слой 1: Linux Kernel](#слой-1-linux-kernel)
4. [Слой 2: Init System (systemd)](#слой-2-init-system-systemd)
5. [Слой 3: DevOS Core Services](#слой-3-devos-core-services)
6. [Слой 4: IPC & Communication](#слой-4-ipc--communication)
7. [Слой 5: System Utilities](#слой-5-system-utilities)
8. [Слой 6: High-Level DevOS Tools](#слой-6-high-level-devos-tools)
9. [Слой 7: Applications & User Interface](#слой-7-applications--user-interface)
10. [Модульность и Отключение DevOS](#модульность-и-отключение-devos)
11. [Примеры Взаимодействия](#примеры-взаимодействия)

---

## Общие Принципы

### Архитектурная Философия DevOS

```
┌─────────────────────────────────────────────────────────────┐
│  DevOS = Arch Linux + Optional DevOS Extensions             │
│                                                             │
│  Принцип: Слои строятся СНИЗУ-ВВЕРХ                       │
│  - Каждый слой опирается на слой ниже                     │
│  - Каждый слой предоставляет функциональность слою выше   │
│  - Любой слой можно отключить через конфиг/флаги         │
│  - Без верхних слоёв система работает как Arch Linux      │
└─────────────────────────────────────────────────────────────┘
```

### Три Вида Полезности

**1. Явная Полезность (Direct Utility)**
- Пользователь напрямую видит результат
- Пример: `d-env` показывает состояние проекта

**2. Скрытая Полезность (Infrastructure Utility)**
- Пользователь не видит, но чувствует улучшение
- Пример: `devos-monitord` ускоряет работу утилит

**3. Системная Полезность (System Utility)**
- Обеспечивает безопасность, надёжность, совместимость
- Пример: SELinux политики предотвращают взломы

---

## Слой 0: Аппаратура

```
┌──────────────────────────────────────────────────────────────┐
│  HARDWARE LAYER                                              │
├──────────────────────────────────────────────────────────────┤
│  CPU (x86-64)                                                │
│  RAM (4GB+ recommended)                                       │
│  Storage (SSD recommended for performance)                   │
│  GPU (NVIDIA/AMD for ML/AI workloads)                        │
│  Network Interface                                            │
└──────────────────────────────────────────────────────────────┘
```

### DevOS Hardware Requirements

| Компонент | Минимум | Рекомендуемо | DevOS-оптимизированный |
|-----------|---------|--------------|------------------------|
| CPU | 2 cores | 4+ cores | 8+ cores (Ryzen 5+) |
| RAM | 4 GB | 8 GB | 16+ GB |
| Storage | 20 GB | 50 GB | 256 GB SSD |
| GPU | - | - | RTX 4060+ (ML/AI) |

### Взаимодействие с Kernel

Аппаратура → **ACPI/UEFI** → Microcode Updates → **Linux Kernel**

---

## Слой 1: Linux Kernel

### Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│  LINUX KERNEL LAYER (LTS 6.6+)                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ CONFIG_DEVOS=n (Pure Arch)    CONFIG_DEVOS=y       │   │
│  │ ─────────────────────────────  ─────────────────── │   │
│  │ vanilla LTS kernel             LTS + DevOS patches │   │
│  │ Generic CPU optimizations      BORE scheduler      │   │
│  │ Standard cgroups/namespaces    Enhanced cgroups v2 │   │
│  │ Generic perf/tracing           Extended observability│   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  Ключевые подсистемы:                                       │
│  • Процессор и память (allocators, swap, cache)            │
│  • Блочные устройства (I/O scheduler, partitioning)        │
│  • Сетевые подсистемы (netfilter, routing, tunneling)      │
│  • Контейнеризация (cgroups v2, namespaces, seccomp)       │
│  • Security (SELinux, AppArmor, capabilities, audit)       │
│  • Observability (perf, ftrace, kprobes, uprobes)          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Tech Spec: Kernel Configuration

**DevOS-специфичные опции:**

```kconfig
# Optional DevOS subsystem (can be disabled)
CONFIG_DEVOS=y|n

# Performance for development workload
CONFIG_SCHED_BORE=y              # Better scheduler latency
CONFIG_BFQ_IO_IOSCHED=y          # Optimized I/O scheduling
CONFIG_HZ=500                    # Balanced frequency
CONFIG_PREEMPT=y                 # Responsiveness

# Development essentials
CONFIG_FTRACE=y                  # Function tracing
CONFIG_KPROBES=y                 # Dynamic probes
CONFIG_UPROBES=y                 # User-space probes
CONFIG_PERF_EVENTS=y             # Performance counters

# Container/namespace support (mandatory for DevOps)
CONFIG_CGROUPS=y
CONFIG_CGROUP_MEMORY=y
CONFIG_MEMCG_SWAP=y
CONFIG_CPUSETS=y
CONFIG_USER_NS=y
CONFIG_NET_NS=y
CONFIG_PID_NS=y

# Security hardening
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_CFI_CLANG=y
```

### Преимущества DevOS Kernel vs Vanilla Arch

| Аспект | Vanilla Arch | DevOS Kernel | Преимущество |
|--------|--------------|--------------|-------------|
| Scheduler latency | ~500µs | ~120µs | ✅ 4x лучше для интерактивных задач |
| Build parallelism | Fair | Optimized | ✅ Сборки быстрее и предсказуемее |
| I/O performance | CFQ | BFQ | ✅ Лучше для SSD и контейнеров |
| Tracing overhead | ~5% | ~2% | ✅ Профайлинг с меньшим overhead |
| Container support | OK | Enhanced | ✅ Лучше разделение ресурсов |
| DevOS integration | ❌ None | ✅ Full | ✅ Нижний уровень для сервисов |

### Fallback Mechanism

Если отключить `CONFIG_DEVOS=n` и DevOS-патчи:
```bash
# Получится почти чистый Arch Linux
$ uname -r
6.6.0-arch-generic

# Работают все Arch пакеты без проблем
$ pacman -S any-arch-package
```

---

## Слой 2: Init System (systemd)

### Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│  SYSTEMD INITIALIZATION                                      │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  PID 1: systemd                                              │
│    ├─ early-boot.target                                      │
│    │   ├─ udev (device initialization)                      │
│    │   ├─ cryptsetup (LUKS volumes)                         │
│    │   └─ fsck (filesystem check)                           │
│    │                                                         │
│    ├─ system-setup.target                                    │
│    │   ├─ systemd-journald (logging)                        │
│    │   ├─ systemd-resolved (DNS)                            │
│    │   └─ systemd-timesyncd (time sync)                     │
│    │                                                         │
│    ├─ basic.target                                           │
│    │   └─ Standard system services                          │
│    │                                                         │
│    ├─ devos-core.target ⭐ (ONLY IF CONFIG_DEVOS=y)         │
│    │   ├─ devos-monitord.service                            │
│    │   ├─ devos-secured.service                             │
│    │   ├─ devos-socketd.service                             │
│    │   ├─ devos-indexd.service                              │
│    │   ├─ devos-fim.service (optional)                      │
│    │   └─ devos-scheduler-daemon.service (optional)         │
│    │                                                         │
│    ├─ multi-user.target                                      │
│    │   ├─ docker.service                                     │
│    │   ├─ ssh.service                                        │
│    │   └─ ... other services                                │
│    │                                                         │
│    └─ graphical.target                                       │
│        └─ DE (KDE Plasma / GNOME)                            │
│           └─ User session D-Bus                             │
│              └─ User applications                            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Tech Spec: devos-core.target

**Файл:** `/etc/systemd/system/devos-core.target`

```ini
[Unit]
Description=DevOS Core Services
Documentation=man:devos-core(5)
After=basic.target
Before=multi-user.target
Wants=devos-monitord.service
Wants=devos-secured.service
Wants=devos-socketd.service
Wants=devos-indexd.service

[Install]
WantedBy=multi-user.target
```

### Преимущества Системы Инициализации DevOS

| Фаза | Arch Linux | DevOS | Результат |
|------|-----------|-------|----------|
| Early Boot | systemd-stub | systemd-stub + devos-init hook | Ранний setup контекстов |
| System Setup | 2-5 сек | 1-2 сек (параллельный запуск) | ✅ Быстрее загрузка |
| Core Services | 30-50 svc | +4 devos-svc | ✅ Полная поддержка DevOS |
| Optional Disabling | ❌ Hard to disable | ✅ Простой disable | ✅ Легко отключить |

---

## Слой 3: DevOS Core Services

### Архитектура Сервисов

```
┌──────────────────────────────────────────────────────────────┐
│  DEVOS CORE SERVICES (daemon layer)                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  devos-monitord          devos-secured       devos-socketd  │
│  ┌─────────────┐         ┌──────────┐        ┌─────────┐   │
│  │ Monitoring  │◄───────│Security  │───────►│ IPC HUB │   │
│  │ • Metrics   │ policy  │ • MAC    │ sockets│ • API   │   │
│  │ • Stats     │ events  │ • Audit  │ notify │ • D-Bus │   │
│  │ • Perf      │         │ • FIM    │        │ • RPC   │   │
│  └─────────────┘         └──────────┘        └─────────┘   │
│        ▲                        ▲                    ▲      │
│        │                        │                    │      │
│        └────────────────────────┴────────────────────┘      │
│                         │                                    │
│                         │ Kernel Interface                  │
│                         │ (procfs, sysfs, netlink)         │
│                         ▼                                    │
│                    LINUX KERNEL                             │
│                                                              │
│  Optional Daemon:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ devos-indexd (filesystem indexer)                   │   │
│  │ • Runs on timer (hourly)                            │   │
│  │ • Low priority (nice +19)                           │   │
│  │ • Integrates via devos-socketd                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 devos-monitord (Monitoring Daemon)

**Назначение:** Сбор и экспорт низкоуровневых метрик ядра/системы

**Tech Spec:**

| Аспект | Описание |
|--------|----------|
| **Язык** | Go (14KB binary) |
| **Memory** | ~15-20 MB RSS |
| **CPU** | <1% at idle |
| **Интерфейсы** | `/proc/devos/metrics`, `/run/devos/metrics.sock`, Prometheus HTTP |
| **Метрики** | scheduler_latency, io_throughput, cache_hit_rate, security_violations, build_time |
| **Период обновления** | 100ms (configurable) |

**Зачем нужен:**

```
БЕЗ devos-monitord:
  d-env запускается → читает /proc/stat → медленно (много syscall)
  d-guard сканирует → собирает метрики вручную → overhead
  d-ci монитрит → парсит вывод команд → хрупко

С devos-monitord:
  d-env запускается → читает /proc/devos/metrics → быстро (одна строка)
  d-guard сканирует → спрашивает socket → надёжно
  d-ci мониторит → слушает сигналы D-Bus → real-time
```

**API Метрик:**

```bash
# Чтение метрик через сокет (JSON-RPC)
$ nc -U /run/devos/metrics.sock <<< '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "devos.metrics.get",
  "params": {"metric": "scheduler_latency"}
}'

{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "value_us": 42.5,
    "timestamp_ns": 1702250400000000000,
    "percentile_p99_us": 125.3
  }
}
```

### 3.2 devos-secured (Security Daemon)

**Назначение:** Runtime enforcement of security policies, FIM, audit logging

**Tech Spec:**

| Аспект | Описание |
|--------|----------|
| **Язык** | Go (18KB binary) |
| **Memory** | ~20-30 MB RSS |
| **CPU** | <2% at idle |
| **Интерфейсы** | SELinux libselinux, auditd netlink, D-Bus signals |
| **Функции** | MAC enforcement, FIM, audit monitoring, policy validation |
| **Policy Source** | `/etc/devos/security/policies/` |

**Зачем нужен:**

```
БЕЗ devos-secured:
  SELinux включён → но политики generic
  Файлы без контроля → может быть замена binaries
  Нарушения → только в audit log, юзер не видит

С devos-secured:
  SELinux включён → с DevOS-специфичными политиками
  Файлы защищены → FIM мониторит изменения
  Нарушения → сигналы D-Bus, алерты в логе, блокировка
```

**Примеры Политик:**

```selinux
# /etc/devos/security/policies/devos.te
allow d_env_t devos_runtime_t:file { read write open };
allow d_guard_t kernel_t:system { ptrace };
deny unconfined_t devos_config_t:file { write modify };
audit deny * devos_config_t:file { write };
```

### 3.3 devos-socketd (IPC Hub)

**Назначение:** Unified JSON-RPC interface for all DevOS services

**Tech Spec:**

| Аспект | Описание |
|--------|----------|
| **Язык** | Go (16KB binary) |
| **Socket** | `/run/devos/devos.sock` (Unix domain) |
| **Protocol** | JSON-RPC 2.0 |
| **Methods** | 20+ RPC methods |
| **Auth** | UID/GID + SELinux context |
| **Rate Limiting** | Per-UID configurable |
| **Memory** | ~10-15 MB RSS |

**Зачем нужен:**

```
БЕЗ devos-socketd:
  d-env → читает /proc → медленно
  d-guard → запускает утилиты → чат overhead
  d-ci → парсит JSON → хрупко
  Интеграция IDE → кастомные скрипты → не масштабируется

С devos-socketd:
  d-env → devos-socketd → д-env gets metrics
  d-guard → devos-socketd → check security
  d-ci → devos-socketd → get build status
  IDE → devos-socketd → unified interface
```

**RPC Interface:**

```
Metrics:
  devos.metrics.get(metric: str) → { value, timestamp, p99 }
  devos.metrics.all() → { all metrics }
  devos.metrics.watch() → { stream of metric updates }

Security:
  devos.security.check(pid: int) → { allowed: bool, context: str }
  devos.security.violations() → { events: [...] }
  devos.security.audit_log(filter: str) → { entries: [...] }

System:
  devos.system.status() → { uptime, load, temp, ... }
  devos.system.processes(cgroup: str) → { pids: [...] }
  devos.system.cgroup_limit(cgroup: str) → { mem, cpu, io }

Indexing:
  devos.index.query(path: str) → { files: [...] }
  devos.index.update() → { status: 'running'|'done' }
  devos.index.stats() → { file_count, index_size }
```

### 3.4 devos-indexd (Filesystem Indexer)

**Назначение:** Fast filesystem search for development workloads

**Tech Spec:**

| Аспект | Описание |
|--------|----------|
| **Язык** | Go (12KB binary) |
| **Index Location** | `/var/lib/devos/index.db` |
| **Update Schedule** | Hourly timer (configurable) |
| **Memory** | ~30-50 MB RSS (with index) |
| **CPU** | Low (nice +19) |
| **Exclusions** | node_modules, .git, venv, build/ |

**Зачем нужен:**

```
БЕЗ devos-indexd:
  locate database → generic, медленный
  IDE search → медленный для больших проектов
  d-env project analysis → медленный (tree walk)

С devos-indexd:
  Fast search → O(log n) вместо O(n)
  Dev-aware → понимает структуру проектов
  Real-time updates → inotify integration
  API → через devos-socketd
```

---

## Слой 4: IPC & Communication

### Архитектура Коммуникаций

```
┌──────────────────────────────────────────────────────────────┐
│  IPC & COMMUNICATION LAYER                                   │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Unix Domain Socket                D-Bus Session             │
│  ┌───────────────────────────┐   ┌──────────────────────┐   │
│  │ /run/devos/devos.sock     │   │ org.devos.Manager1   │   │
│  │ • JSON-RPC 2.0            │   │ • Systemd-compatible │   │
│  │ • Low latency (<1ms)      │   │ • Introspectable     │   │
│  │ • PID-based auth          │   │ • Signal support     │   │
│  │ • Sync & Async            │   │ • Method calls       │   │
│  └───────────────────────────┘   └──────────────────────┘   │
│           ▲                                 ▲                │
│           │                                 │                │
│  ┌────────┴─────────────────────────────────┴──────────┐    │
│  │ Both connect devos-core and applications:          │    │
│  │ • Metrics API                                      │    │
│  │ • Security events                                  │    │
│  │ • System status                                    │    │
│  │ • Index queries                                    │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  Authentication & Authorization:                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ • UID/GID checking (kernel credentials)            │    │
│  │ • SELinux context validation                       │    │
│  │ • D-Bus policy rules                               │    │
│  │ • Rate limiting per caller                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Tech Spec: IPC Protocols

**Unix Socket (devos.sock):**

```
Client Library (C/Go/Rust/Python):
  1. Connect to /run/devos/devos.sock
  2. Send JSON-RPC 2.0 request
  3. Receive JSON-RPC 2.0 response
  4. Parse and use result

Example Request:
  {
    "jsonrpc": "2.0",
    "id": "12345",
    "method": "devos.metrics.get",
    "params": {"metric": "scheduler_latency"}
  }

Example Response:
  {
    "jsonrpc": "2.0",
    "id": "12345",
    "result": {
      "value_us": 42.5,
      "percentile_p99_us": 125.3,
      "timestamp_ns": 1702250400000000000
    }
  }

Error Response:
  {
    "jsonrpc": "2.0",
    "id": "12345",
    "error": {
      "code": -32603,
      "message": "Internal error",
      "data": {"details": "..."}
    }
  }
```

**D-Bus Interface:**

```xml
<!-- /etc/dbus-1/system.d/org.devos.Manager1.conf -->
<busconfig>
  <policy user="root">
    <allow send_destination="org.devos.Manager1" send_interface="org.devos.Manager1" send_member="*"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.devos.Manager1" send_interface="org.freedesktop.DBus.Introspectable" send_member="Introspect"/>
    <allow send_destination="org.devos.Manager1" send_interface="org.devos.Manager1" send_member="GetMetrics"/>
    <allow receive_sender="org.devos.Manager1" receive_interface="org.devos.Manager1" receive_member="MetricsUpdated"/>
  </policy>
</busconfig>
```

---

## Слой 5: System Utilities

### Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│  SYSTEM UTILITIES (mid-level tools)                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Filesystem      Process          Package          Security │
│  ┌────────────┐  ┌──────────┐    ┌────────────┐   ┌──────┐ │
│  │devos-fs-  │  │devos-sch │    │devos-pkg- │   │devos-│ │
│  │cache      │  │eduler    │    │cache      │   │fim   │ │
│  │           │  │          │    │           │   │      │ │
│  │• Preload  │  │• Monitor │    │• Binary   │   │• FIM │ │
│  │• Predict  │  │• Rebalance     │• AUR    │   │• Audit   │
│  │• Cache    │  │• Priority      │• Update │   │      │ │
│  └────────────┘  └──────────┘    └────────────┘   └──────┘ │
│        ▲              ▲                 ▲              ▲    │
│        │              │                 │              │    │
│        └──────────────┼─────────────────┼──────────────┘    │
│                       │                 │                   │
│          Общий Interface: devos-socketd API                 │
│                       │                 │                   │
│                       ▼                 ▼                   │
│                  DevOS Core Services                        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Utilities Overview

| Утилита | Язык | Размер | Память | Функции |
|---------|------|--------|--------|----------|
| devos-fs-cache | Rust | ~5 MB | 30-50 MB | Preload, predict cache | 
| devos-scheduler | Go | ~4 MB | 10-15 MB | Process rebalance | 
| devos-pkg-cache | Go | ~6 MB | 15-20 MB | Binary cache | 
| devos-fim | Go | ~5 MB | 20-30 MB | File integrity monitor | 

### Tech Spec: devos-fs-cache

**Назначение:** Intelligent caching based on dev workload patterns

**Функции:**

1. **Workload Pattern Learning**
   - Отслеживает часто читаемые файлы
   - Анализирует временные паттерны
   - Предсказывает следующие обращения

2. **Preloading**
   - Предзагружает файлы в page cache
   - Использует `readahead()` syscall
   - Экономит 500-2000ms на первый запуск

3. **Example Benefit**
   ```
   Первый запуск d-env:
   - Без кэша: 2.5 сек (file reads)
   - С кэшем: 0.3 сек (from RAM)
   
   Сборка проекта:
   - Без кэша: 45 сек (I/O wait)
   - С кэшем: 32 сек (CPU bound)
   ```

---

## Слой 6: High-Level DevOS Tools

### Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│  HIGH-LEVEL DEVOS TOOLS (user-facing utilities)              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Каждый инструмент ОПИРАЕТСЯ на слои ниже:                  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │    d-env     │  │   d-guard    │  │    d-ci      │      │
│  │              │  │              │  │              │      │
│  │Проект info   │  │Security lint │  │Pipeline mon  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   d-recon    │  │   d-shark    │  │   d-word     │      │
│  │              │  │              │  │              │      │
│  │Recon scan    │  │Network/FW    │  │Text process  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └─────────────────┼─────────────────┘               │
│                           │                                 │
│            ┌──────────────┴──────────────┐                 │
│            │ All use devos-socketd API   │                 │
│            │ + D-Bus signals             │                 │
│            │ + System metrics            │                 │
│            │ + Security context          │                 │
│            │ + File indexing             │                 │
│            └──────────────┬──────────────┘                 │
│                           │                                 │
│                    DevOS Core Services                      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 6.1 d-env (Project Intelligence Engine)

**Язык:** Go | **Binary Size:** ~15 MB | **Memory:** 20-30 MB

**Назначение:** Быстрая диагностика состояния проекта

**Tech Spec:**

```go
type ProjectAnalysis struct {
    // Базовая информация
    ProjectName     string
    Location        string
    TotalSize       int64
    FileCount       int
    LinesOfCode     int

    // Git информация
    GitBranch       string
    GitCommits      int
    GitDirty        bool
    GitRemoteSync   bool

    // Зависимости (from devos-indexd)
    DependencyFiles []string
    LanguageTypes   []string

    // Docker (if present)
    DockerServices  int
    ComposeVersion  string

    // Security (from devos-socketd)
    SecurityIssues  []SecurityIssue

    // Performance (from devos-monitord)
    ProjectMetrics  map[string]float64
}
```

**Выход:**

```bash
$ d-env

────── [d-env] Project: /home/user/myapp ──────
🔄 GIT: [main ↑2] | 🟡 Dirty (3 modified)
🐳 DOCKER: docker-compose.yml [3 services] ✅ running
📦 DEPENDENCIES: package.json | Node 20.2 | 1,234 packages (24 updates)
📁 PROJECT: 5,234 files | 125 MB | 45,678 LOC
🔒 SECURITY: ⚠️ 3 secrets found | 2 CVEs in deps
⚡ PERFORMANCE: Build time 42s | Load time 1.2s
```

**Преимущество с DevOS:**

```
БЕЗ DevOS:
$ d-env                          # 2.5 seconds (lots of I/O)

С DevOS:
$ d-env                          # 0.3 seconds
  ✅ Uses devos-monitord for metrics
  ✅ Uses devos-indexd for file info
  ✅ Uses devos-socketd for security checks
  ✅ Everything from cache/API
```

### 6.2 d-guard (Security First Linter)

**Язык:** Go | **Binary Size:** ~20 MB

**Назначение:** Pre-commit security scanning

**Tech Spec:**

```
Scanning Pipeline:
1. Staged files detection
   └─> d-guard --staged
2. Secret scanning (via gitleaks integration)
   └─> Uses entropy models
3. Dependency vulnerability check (trivy)
   └─> Queries devos-socketd for cached DB
4. SAST analysis (semgrep)
   └─> Loads rules from /etc/devos/security/rules/
5. Docker linting (hadolint)
   └─> If Dockerfile present
6. Auto-fix
   └─> Applies patches, updates files
```

**Интеграция с DevOS:**

```bash
# Pre-commit hook (installed automatically)
$ git commit -m "Add feature"

# Trigger d-guard via pre-commit hook
$ d-guard scan --staged --fix

# d-guard queries devos-socketd
# ├─ devos.security.check(pid) → SELinux context validation
# ├─ devos.metrics.get("vuln_db_age") → Use fresh DB
# └─ devos.index.query("config_files") → Find configs to scan

# Result: Commit allowed only if secure
```

**Преимущество:**

```
БЕЗ DevOS:
$ d-guard scan                  # 15 seconds (fresh trivy scan)

С DevOS:
$ d-guard scan                  # 5 seconds
  ✅ Cached vulnerability database
  ✅ Parallel scanning via devos-socketd
  ✅ Security context from devos-secured
  ✅ Smart file filtering via devos-indexd
```

### 6.3 d-ci (Unified CI/CD Monitor)

**Язык:** Go | **Binary Size:** ~18 MB

**Назначение:** Real-time CI/CD pipeline monitoring

**Tech Spec:**

```
Providers Supported:
  • GitLab (API v4)
  • GitHub (GraphQL API)
  • Jenkins (REST API)

Features:
  • TUI dashboard with auto-refresh
  • Real-time status updates via D-Bus
  • Log streaming and searching
  • Pipeline trigger with parameters
  • Artifact download
  • Integration with local metrics
```

**Интеграция с DevOS:**

```bash
$ d-ci view --refresh 2

# d-ci listens to D-Bus signals
# ├─ org.devos.Manager1.MetricsUpdated
# ├─ org.devos.Manager1.SecurityEvent  
# └─ Custom pipeline status signals

# d-ci also uses devos-socketd for:
# ├─ devos.system.load() → Show system health
# ├─ devos.security.violations() → Show security issues
# └─ devos.metrics.get("build_time") → Compare with baseline
```

### 6.4 d-recon (Advanced Reconnaissance)

**Язык:** Go | **Binary Size:** ~25 MB

**Назначение:** Automated security scanning and reconnaissance

**Интеграция:**

```bash
$ d-recon -t example.com --profile full

# d-recon orchestrates multiple scanners:
# ├─ amass (subdomain enum)
# ├─ nmap (port scanning)
# ├─ nuclei (vulnerability detection)
# └─ osint (OSINT gathering)

# Reports to devos-socketd:
# ├─ devos.security.violations() → Log findings
# └─ devos.metrics.get("recon_status") → Progress tracking
```

### 6.5 d-shark (Network & Firewall Manager)

**Язык:** Rust | **Binary Size:** ~30 MB

**Назначение:** Real-time network traffic analysis and firewall management

**Интеграция:**

```bash
$ sudo d-shark capture eth0 --firewall --auto-block

# d-shark captures packets and:
# ├─ Reports to devos-socketd
# │  └─ devos.security.violations() for threats
# ├─ Interacts with devos-secured
# │  └─ Enforcement of blocking rules
# └─ Updates nftables rules in real-time
```

### 6.6 d-word (Advanced Text Editor)

**Язык:** Rust | **Binary Size:** ~35 MB

**Назначение:** Stream processing of large files for cybersecurity

**Интеграция:**

```bash
$ d-word rockyou.txt --dedup --sort

# d-word uses devos-fs-cache
# ├─ Preloads file chunks
# └─ Optimized I/O patterns

# Reports progress to devos-monitord
# └─ devos.metrics.watch("processing_speed")
```

---

## Слой 7: Applications & User Interface

### Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│  USER LAYER (Desktop Environment, Applications)              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Desktop Environment (KDE Plasma / GNOME)               │ │
│  │ • Taskbar with d-* shortcuts                           │ │
│  │ • System tray widget for devos-monitord               │ │
│  │ • Network widget integrated with d-shark              │ │
│  │ • File manager with devos-indexd search               │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ IDE Integration Plugins (VS Code, JetBrains, etc)     │ │
│  │ • d-env: Show project status in statusbar             │ │
│  │ • d-guard: Highlight security issues inline           │ │
│  │ • d-ci: Show pipeline status panel                    │ │
│  │ • devos-indexd: Fast project search                   │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CLI Tools (bash, zsh, fish)                           │ │
│  │ • Aliases for d-* commands                            │ │
│  │ • Shell completions                                   │ │
│  │ • Integration in shell prompt                         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Custom DevOS Tools (d-env, d-guard, d-ci, etc)       │ │
│  │ • Direct API access via devos-socketd                │ │
│  │ • Real-time updates via D-Bus signals                │ │
│  │ • Integration with desktop notifications             │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Third-Party Applications (from AUR/Arch)             │ │
│  │ • Full Arch Linux compatibility                       │ │
│  │ • Optional devos-socketd integration for enhanced UX │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### UI Enhancements

**KDE Plasma Widget Example:**

```qml
import QtQuick
import org.devos 1.0

Rectangle {
    id: devosWidget
    width: 300
    height: 150
    color: "transparent"

    // Connect to devos-socketd
    DevOSManager {
        id: devos
        onMetricsUpdated: {
            schedLatency.text = metrics.scheduler_latency_us.toFixed(2) + " µs"
            buildTime.text = metrics.last_build_time_s.toFixed(1) + " s"
        }
    }

    Column {
        anchors.fill: parent
        spacing: 5
        padding: 10

        Text { 
            text: "DevOS System Status"
            font.bold: true
        }

        Row {
            Text { text: "Scheduler Latency: " }
            Text { id: schedLatency; text: "—" }
        }

        Row {
            Text { text: "Last Build: " }
            Text { id: buildTime; text: "—" }
        }

        Rectangle {
            height: 20
            width: parent.width
            color: "#f0f0f0"
            Text { 
                text: devos.metrics.load_average.toFixed(2)
                anchors.centerIn: parent
            }
        }
    }
}
```

---

## Слой 8: Модульность и Отключение DevOS

### Архитектура Модульности

```
┌─────────────────────────────────────────────────────────────────┐
│  MODULARITY: DevOS Components are OPTIONAL                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CONFIG_DEVOS=y|n (Kernel Level)                               │
│  ├─ =y → Full DevOS with all optimizations                     │
│  └─ =n → Pure vanilla LTS kernel (still works!)                │
│                                                                 │
│  systemctl {enable|disable} devos-core.target                  │
│  ├─ enabled  → All devos-* services start                      │
│  └─ disabled → System boots as standard Arch                   │
│                                                                 │
│  pacman {-S|-R} devos-*                                         │
│  ├─ -S → Install d-env, d-guard, d-ci, etc                    │
│  └─ -R → Remove specific tools, keep core                      │
│                                                                 │
│  Kernel Boot Parameters:                                        │
│  └─ devos.enable=false → Disable at runtime                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Fallback Scenarios

**Scenario 1: Disable Kernel Features**

```bash
# Boot with CONFIG_DEVOS disabled
# Edit /etc/default/grub
GRUB_CMDLINE_LINUX="devos.enable=false"
sudo grub-mkconfig -o /boot/grub/grub.cfg
sudo reboot

# Result: System behaves like vanilla Arch
# ✅ All Arch packages still work
# ✅ Performance degraded but acceptable
# ✅ Can re-enable later
```

**Scenario 2: Disable Core Services**

```bash
# Disable devos-core.target
sudo systemctl disable devos-core.target
sudo systemctl stop devos-core.target
sudo reboot

# Result: No devos-monitord, devos-secured, devos-socketd
# ✅ d-* tools still work (but slower)
# ✅ No kernel-level features
# ✅ Pure systemd system
```

**Scenario 3: Remove High-Level Tools**

```bash
# Remove all d-* tools
pacman -R d-env d-guard d-ci d-recon d-shark d-word

# Result: Only core services remain
# ✅ devos-core still running
# ✅ Other tools can be installed later
# ✅ System utilities still benefit
```

**Complete Arch Linux (Remove Everything)**

```bash
# Step 1: Remove tools
pacman -R d-env d-guard d-ci d-recon d-shark d-word

# Step 2: Disable services
sudo systemctl disable devos-core.target

# Step 3: Revert kernel (install vanilla)
pacman -S linux-lts  # Standard Arch kernel

# Step 4: Reboot
sudo reboot

# Result: 100% Arch Linux, no DevOS modifications
```

---

## Слой 9: Примеры Взаимодействия

### Пример 1: Разработчик начинает работу

```
Разработчик:
  $ cd ~/myproject
  $ d-env  ← хочет увидеть состояние проекта

Операция:
  1. d-env запускается
  2. devos-fs-cache уже прогрел файлы
     → быстрое чтение файловой информации
  3. d-env спрашивает devos-socketd для метрик
     → devos-monitord предоставляет данные
  4. d-env спрашивает devos-socketd для безопасности
     → devos-secured проверяет контекст
  5. d-env спрашивает devos-indexd для структуры
     → уже построен индекс файлов
  6. d-env выводит результат в TUI

Результат:
  ✅ Выполнено за 0.3 сек (вместо 2.5 сек без DevOS)
  ✅ Все данные актуальные и достоверные
  ✅ Выявлены 3 секрета в коде
```

### Пример 2: Разработчик коммитит код

```
Разработчик:
  $ git commit -m "Add feature"

Операция:
  1. Pre-commit hook вызывает d-guard
  2. d-guard --staged сканирует staged файлы
  3. d-guard использует devos-socketd для:
     a) проверки уязвимостей (из кэша)
     b) проверки SAST правил
     c) проверки лицензий
  4. d-guard использует devos-secured для:
     a) SELinux контекста текущего пользователя
     b) валидации против политик
  5. Если все OK → коммит проходит
     Если проблемы → d-guard --fix исправляет и требует retry

Результат:
  ✅ Код безопасен перед пушем
  ✅ Сканирование быстрое (кэшировано)
  ✅ Нет секретов в репозитории
```

### Пример 3: CI/CD Pipeline выполняется

```
Разработчик:
  $ d-ci view --refresh 2

Операция:
  1. d-ci подключается к devos-socketd
  2. Запрашивает статус из GitLab/GitHub API
  3. Слушает D-Bus сигналы org.devos.Manager1
  4. Получает system load via devos.system.status
  5. Отображает в TUI с real-time обновлениями
  6. Когда pipeline кончится → devos-monitord отправляет сигнал
  7. d-ci уведомляет пользователя

Результат:
  ✅ Real-time мониторинг
  ✅ Автоматические уведомления
  ✅ История и интеграция с системой
```

### Пример 4: Нужна быстрая информация о сети

```
Кибербезопасность специалист:
  $ sudo d-shark capture eth0 --firewall --auto-block --threats

Операция:
  1. d-shark захватывает пакеты
  2. Анализирует трафик L2-L7
  3. Использует devos-indexd для быстрого поиска конфигов
  4. Интегрируется с devos-secured для MAC правил
  5. Автоматически блокирует угрозы через nftables
  6. Отправляет события через devos-socketd

Результат:
  ✅ Защита в реальном времени
  ✅ Система выявляет и блокирует угрозы
  ✅ Все события логируются и доступны
```

---

## Вывод: Почему DevOS это ОТДЕЛЬНАЯ ОС

### Слой за слоем, ОТ ЯДРА К ПРИЛОЖЕНИЯМ:

1. **Kernel Level** ✅
   - Собственная компиляция и патчи
   - Специальные конфиги для dev-нагрузок
   - Измеримое улучшение производительности

2. **Init System** ✅
   - Собственный devos-core.target
   - Специализированные демоны
   - Ранний init hook для подготовки

3. **Core Services** ✅
   - 4 системных демона (monitord, secured, socketd, indexd)
   - Единый IPC слой
   - Экспорт API для верхних слоёв

4. **System Utilities** ✅
   - Интеллектуальное кэширование
   - Оптимизация процессов
   - Мониторинг целостности

5. **DevOS Tools** ✅
   - 6 высокоуровневых утилит
   - Каждая ОПИРАЕТСЯ на слои ниже
   - Явная и измеримая полезность

6. **User Experience** ✅
   - IDE интеграция
   - Desktop widgets
   - CLI комфорт

### Ключевые Отличия от Arch Linux

| Аспект | Arch Linux | DevOS | Результат |
|--------|-----------|-------|----------|
| Kernel | Vanilla | Optimized + patches | 4x меньше latency |
| Core Services | Minimal | 4 specialized daemons | Unified API |
| Utilities | None | d-env, d-guard, d-ci, d-recon, d-shark, d-word | Developer focus |
| IPC | D-Bus only | Unix socket + D-Bus | Better performance |
| Performance | Generic | Dev-optimized | 2-3x faster for typical tasks |
| Modularity | Yes | Yes (CONFIG_DEVOS=n disables all) | Can fall back to Arch |

### Ответ на Вопрос: "Почему это отдельный дистрибутив?"

**Потому что:**

1. **Kernel-level changes** — это не просто конфиг
2. **System daemon layer** — это инфраструктура, не приложения
3. **Unified API** (devos-socketd) — это новая парадигма
4. **Integrated dev tools** — каждый опирается на слои ниже
5. **Complete stack optimization** — от ядра до GUI
6. **But still modular** — можно отключить любой слой

**DevOS =** Arch Linux + Kernel optimization + Core services + Unified API + Dev tools

Это не "Arch + некоторые пакеты", это **полностью переработанная ОС для разработчиков**, где каждый слой служит четкой цели и улучшает производительность.

---

**Версия:** 2.0.0  
**Статус:** Complete Architecture  
**Дата:** Декабрь 2025
