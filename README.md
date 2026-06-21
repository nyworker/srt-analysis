# srt-analysis

Tools for analyzing SRT (Secure Reliable Transport) streams from PCAP captures.

## Overview

`analyze_srt.py` decodes SRT/UDT packets from a PCAP file and surfaces common stream health issues:

- Receiver buffer drain rate and time-to-full estimate
- Retransmission rate and NAK events
- DROPREQ (too-late packet drops)
- ACK progression / stalls
- RTT statistics
- Link capacity vs. send rate headroom
- Data sequence gaps

## Requirements

```
pip install dpkt
```

## Usage

Edit the `PCAP_FILE` path at the top of `analyze_srt.py`, then:

```bash
python3 analyze_srt.py
```

Supports standard Ethernet (link type 1) and Linux cooked capture v2 / SLL2 (link type 276).

## Example Finding

```
[BUFFER AVAILABILITY TREND]
  Start: 336 slots free
  End:   321 slots free
  Rate:  5.0 slots/sec filling up
  *** ESTIMATED TIME UNTIL BUFFER FULL: 64s ***

[LINK CAPACITY vs SEND RATE]
  pkt_rate: 5.4 pps avg
  link_cap: 5.0 pps avg
  Headroom for retransmit: -8%  (NONE - at capacity)
```

**Root cause (port4015.choking.pcap):** The encoder was producing a black video frame, resulting in near-zero visual entropy and an extremely low encoded bitrate (~52.5 kbps, 5 pps). The depressed bandwidth caused the receiver's estimated link capacity to floor at 5 pps — exactly matching the send rate — leaving no headroom for retransmissions. The low bitrate also meant each ACK cycle advanced the receiver buffer by only one slot, making the `buf_avail` drain appear alarming when it was actually a consequence of the encoding issue rather than a receiver-side stall.

## SRT Packet Fields Decoded

| ACK field | Meaning |
|---|---|
| `acked_seq` | Last acknowledged data sequence number |
| `RTT` | Round-trip time (µs, from receiver's perspective) |
| `buf_avail` | Free slots in receiver buffer (packets) — decreasing = app not reading |
| `pkt_rate` | Receiver-measured packet arrival rate (pps) |
| `link_cap` | Receiver's estimated link capacity (pps) |
| `bw` | Receiver-measured bandwidth (bytes/sec) |
