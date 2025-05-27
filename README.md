# Network Monitoring Tool

This repository hosts a (not-so) simple Network Monitoring Tool in C++ and Python for network traffic analysis.

## The Npcap C++ Wrapper
Windows, in its infinite wisdom, guards access to the layer 2. While I initially did entertain the idea of crafting my own packet capture library from scratch, the thought of working with NDIS filter driver callbacks, quickly turned me to the **Npcap** library.

This C++ wrapper, bridged to Python with pybind11, includes:
*   Listing and Selecting Network Interfaces
*   Sniffing raw packets
*   Applying BPF filters for targetted captures
*   Running Asynchronous capture loops

## Supported Protocols
The current suite of parsers:
*   **Layer 2**: Ethernet, ARP, TPID (VLAN)
*   **Layer 3**: IPv4, IPv6, ICMP, ICMPv6
*   **Layer 4**: TCP, UDP
*   And, DNS

Other protocols bravely venture into the "Unknown Protocol" category

### Some additional cool features:
*   *Top Talkers* Identifies the most active source/destination by bytes
*   *Protocol Distribution* Breakdown of the traffic
*   *GeoIP Lookups* Public IPs are mapped to approximate location and ISP/Organization
*   *Reverse DNS*

In the future, I do wish to incorporate a web UI (Flask and React) to better visualize this data.
Deployability is a future goal, though Npcap's driver dependency makes direct deployment on typical PaaS challenging.

**A Note on Dependencies (If you're brave enough to try this before it's "web-scale"):**
*   **Npcap:** Must be installed on Windows for the core capture.
*   **Python Packages:** See `requirements.txt` (when finalized) for `pybind11` (build-time), `geoip2`, etc.
*   **GeoLite2 Databases:** For GeoIP features, you'll need databases from MaxMind.
