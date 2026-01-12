# NetSnoop - Multi-threaded Network Packet Sniffer

NetSnoop is a high-performance network packet sniffer written in C, capable of capturing and logging ICMP, TCP, and UDP packets across all network interfaces. It supports multi-threading with a producer-consumer queue to efficiently handle large volumes of network traffic.

---

## Features

* Capture ICMP, TCP, and UDP packets.
* Multi-threaded design for high performance.
* Thread-safe logging to separate protocol-specific log files.
* Hexdump of payloads with ASCII representation.
* Graceful shutdown on `Ctrl+C`.
* Automatic selection of the first non-loopback interface if none specified.

---

## Requirements

* Linux OS (requires raw socket privileges).
* GCC compiler.
* Root privileges to capture raw packets.

---

## Compilation

```bash
make all
```

---

## Usage

**Important:** The network interface **must be UP** before performing any operations.

```bash
sudo ./netsnoop [OPTIONS]
```

### Options

| Option                    | Description                                                                    |
| ------------------------- | ------------------------------------------------------------------------------ |
| `-i, --interface <iface>` | Specify the network interface to sniff (default: first non-loopback interface) |      
| `-p, --protocal <tcp,udp,icmp>`| Filter packets by protocol |

### Example

```bash
sudo ./netsnoop -i eth0 -p tcp
```

Captures TCP packets on `eth0`.

```bash
sudo ./netsnoop
```

Captures all packets on the first non-loopback interface.

---

## Logs

NetSnoop writes logs into the following files:

* `icmp_log.txt` - ICMP packets
* `tcp_log.txt` - TCP packets
* `udp_log.txt` - UDP packets

Each log includes timestamped packet headers, source/destination IPs, ports (where applicable), and payload hexdumps.

---

## Notes

* Requires root privileges due to raw socket usage.
* Use `Ctrl+C` to stop sniffing gracefully.
* Avoid virtual or container interfaces (veth, docker, br-) as they are skipped automatically.

---


