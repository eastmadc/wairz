# RTOS Binary Fingerprinting — Research Brief

**Date:** 2026-04-06
**Sources:** 3 parallel research scouts (253 web searches, 447+ tool uses)

## Key Findings Beyond Seed

### VxWorks Symbol Table (confirmed from Ghidra + vxhunter)

5 entry sizes confirmed: 0x0E (v5.0), 0x10 (v5.3/5.5), 0x14 (v5.4/6.4/6.8), 0x18 (v6.1), 0x1C (unknown).
Each has: symHashNode(4) + symNameOff(4) + symLocOff(4) + varying fields + symType(1) + padding(1).
Valid types — v5.x: `[0x03-0x09, 0x12, 0x13, 0x40, 0x41, 0x80, 0x81]`; v6.x: `[0x03-0x05, 0x08-0x11, 0x20, 0x21, 0x40, 0x41]`.
Detection: search for known strings (`\x00bzero\x00`, `\x00usrInit\x00`), scan backward, validate 100 entries.
OWOW MemFS: 32-byte `"OWOWOWOW..."` header, then uint32 version (1=compressed, 2=plain), uint32 file_count.
Boot line: `\w+\(\d+,\d+\)\S+:\S+\s+[ehbgufst]\w*=` (e.g., `enp(0,0)host:/path/vxWorks e=90.0.0.2 h=100.0.0.4`).

### QNX IFS (confirmed from OpenQNX headers)

Startup header: `0x00ff7eeb` at offset 0, 256 bytes total. flags1 bit 0x02 = big-endian. Machine field at 0x0A = ELF machine type.
Image header: `"imagefs"` (7 bytes), `"sfegami"` for reversed endian. flags bit 0x01 = big-endian.
QNX6 filesystem is DIFFERENT — superblock magic `0x68191122` at offset `0x2000`.
QNX EFS magic: `"QSSL_F3S"` (8 bytes).
QNX ELF OSABI: `e_ident[EI_OSABI]` = 3 (reliable for individual QNX binaries).
`.QNX_info` and `.QNX_usage` removed by `strip` but preserved by `mkifs` for bootstrap components.

### Zephyr (confirmed from MCUboot + bindesc sources)

MCUboot header: 32 bytes at offset 0. Magic `0x96f3b83d`. Version at offsets 0x14-0x1B (major.minor.revision.build_num).
Binary descriptor: 8-byte magic `0xb9863e5a7ea46046`, followed by TLV entries. Tag 0x1900 = kernel version string.
Boot banner: `"*** Booting Zephyr OS build <git-describe> ***"` — enabled by default via CONFIG_BOOT_BANNER.
ELF sections: `k_timer_area`, `k_mem_slab_area`, `k_heap_area`, `k_mutex_area`, `k_sem_area`, `k_msgq_area`, `k_pipe_area`, `k_event_area`, `k_queue_area`, `k_condvar_area`, `device_area`, `init_PRE_KERNEL_1`, `init_PRE_KERNEL_2`.

### FreeRTOS vs SafeRTOS (confirmed from source + RE talks)

SafeRTOS has NO dynamic memory — `pvPortMalloc`/`vPortFree` absent is definitive.
SafeRTOS unique: `xTaskInitializeScheduler` (CONFIRMED).
"Wittenstein" string: NOT in compiled binaries (only source comments). UNRELIABLE.
Default task names: `"IDLE"` (configIDLE_TASK_NAME), `"Tmr Svc"` (configTIMER_SERVICE_TASK_NAME) — VERY reliable.
Heap discrimination: `vPortDefineHeapRegions` → heap_5; `xPortGetMinimumEverFreeHeapSize` → heap_4; no `xPortGetFreeHeapSize` → heap_3.

### ThreadX (confirmed from Eclipse ThreadX repo)

`_tx_version_id` global string ALWAYS present. Pattern across all eras:
- Express Logic: `"Copyright.*Express Logic.*ThreadX <arch>/<compiler> Version G<ver>"`
- Azure RTOS: `"Copyright.*Microsoft.*ThreadX <arch>/<compiler> Version <ver>"`
- Eclipse: `"Eclipse ThreadX.*ThreadX <arch>/<compiler> Version <ver>"`
Companion version strings: `_nx_version_id` (NetX), `_fx_version_id` (FileX), `_gx_version_id` (GUIX), `_ux_version_id` (USBX).

### uC/OS (confirmed from weston-embedded repos)

Task name strings are DEFINITIVE:
- uC/OS-II: `"uC/OS-II Idle"`, `"uC/OS-II Stat"` (hardcoded in os_core.c)
- uC/OS-III: `"uC/OS-III Idle Task"`, `"uC/OS-III Stat Task"`, `"uC/OS-III Timer Task"`
"Micrium"/"Jean J. Labrosse": NOT in compiled binaries. UNRELIABLE.
uC/OS-III unique APIs: `OSTaskQPend`, `OSTaskSemPend` (task-level message queue and semaphore).

### Companion Component Version Strings

| Component | Version Pattern | Key Symbols |
|-----------|----------------|-------------|
| lwIP | `\d+\.\d+\.\d+(d\|rc\d+)?` near `pbuf_alloc`; HTTP UA `"lwIP/%d.%d.%d"` | pbuf_alloc, tcp_write, netif_add |
| wolfSSL | LIBWOLFSSL_VERSION_STRING `"X.Y.Z"` | wolfSSL_Init, wolfSSL_lib_version |
| Mbed TLS | `"Mbed TLS X.Y.Z"` (full), `"X.Y.Z"` (short); older: `"PolarSSL X.Y.Z"` | mbedtls_ssl_init, mbedtls_version_get_string |
| tinycrypt | **NO version string** (project EOL) | tc_sha256_init, tc_aes128_set_encrypt_key |
| BearSSL | **NO version string** (v0.6, 2018) | br_ssl_client_init_full, br_sha256_init |
| LittleFS | On-disk magic `"littlefs"` at superblock offset 8 | lfs_mount, lfs_file_open |
| FatFS | `"FatFs"`, `"ChaN"`, revision `"R0.XX"` | f_mount, f_open |
| SPIFFS | Magic `0x20140529 ^ page_size` | SPIFFS_mount, SPIFFS_open |
| FreeRTOS+TCP | `"VX.Y.Z"` in ipFR_TCP_VERSION_NUMBER | FreeRTOS_socket, FreeRTOS_sendto |
| NetX Duo | `_nx_version_id` contains `"NetX Duo"` | nx_ip_create, nx_tcp_socket_create |

### CPE Identifiers (confirmed from NVD)

| Component | CPE | Notes |
|-----------|-----|-------|
| FreeRTOS | `cpe:2.3:o:amazon:freertos:{ver}` | 145 NVD records |
| Zephyr | `cpe:2.3:o:zephyrproject-rtos:zephyr:{ver}` | |
| VxWorks | `cpe:2.3:o:windriver:vxworks:{ver}` | |
| ThreadX | `cpe:2.3:o:microsoft:azure_rtos_threadx:{ver}` | Messy: also azure_rtos, azure_real_time_operating_system |
| QNX | `cpe:2.3:o:blackberry:qnx_neutrino_rtos:{ver}` | |
| lwIP | `cpe:2.3:a:lwip_project:lwip:{ver}` | |
| wolfSSL | `cpe:2.3:a:wolfssl:wolfssl:{ver}` | 129 NVD records |
| Mbed TLS | `cpe:2.3:a:arm:mbed_tls:{ver}` | Also mbed:mbedtls (newer) |

### Existing Tool Gaps

- **binwalk**: Only VxWorks (WIND version, VxWorks\x00, OWOW MemFS). No FreeRTOS/Zephyr/ThreadX.
- **FACT**: No RTOS detection plugin.
- **cpu_rec**: ISA only, not RTOS.
- **EMBA**: Claims RTOS support but patterns not in database.
- **ONEKEY**: Most advanced (compiled reference library + function signatures) — commercial, not available.

Our engine will be the most comprehensive open-source RTOS detection tool.
