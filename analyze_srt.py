#!/usr/bin/env python3
"""SRT PCAP analyzer - decodes SRT/UDT packets and highlights anomalies."""

import dpkt
import struct
import sys
from collections import defaultdict

PCAP_FILE = "/home/wsl/claude/srt-ana/port4015.choking.pcap"

# SRT control packet types
CTRL_TYPES = {
    0x0000: "HANDSHAKE",
    0x0001: "KEEPALIVE",
    0x0002: "ACK",
    0x0003: "NAK",
    0x0004: "CONGESTION_WARNING",
    0x0005: "SHUTDOWN",
    0x0006: "ACKACK",
    0x0007: "DROPREQ",
    0x0008: "PEERERROR",
    0x7FFF: "SRT_EXT",
}

# SRT extension subtypes (for 0x7FFF)
SRT_EXT_TYPES = {
    0x0000: "SRT_CMD_NONE",
    0x0001: "SRT_CMD_HSREQ",
    0x0002: "SRT_CMD_HSRSP",
    0x0003: "SRT_CMD_KMREQ",
    0x0004: "SRT_CMD_KMRSP",
    0x0005: "SRT_CMD_SID",
    0x0006: "SRT_CMD_CONGESTION",
    0x0007: "SRT_CMD_FILTER",
    0x0008: "SRT_CMD_GROUP",
}

class SRTStats:
    def __init__(self):
        self.data_pkts = 0
        self.retrans_pkts = 0
        self.ctrl_counts = defaultdict(int)
        self.nak_ranges = []
        self.ack_seq_nums = []
        self.data_seq_nums = []
        self.timestamps = []
        self.ackack_seq_nums = []
        self.dropped_msg_ids = []
        self.congestion_warnings = 0
        self.ack_seqno_history = []  # (ts, ack_seqno) for tracking
        self.last_ack_seqno = None
        self.nak_details = []
        self.dropreq_details = []


def parse_srt_packet(data, ts, src, dst, stats, verbose=False):
    if len(data) < 16:
        return

    word0 = struct.unpack(">I", data[0:4])[0]
    is_control = (word0 >> 31) & 1
    timestamp = struct.unpack(">I", data[8:12])[0]
    dst_socket_id = struct.unpack(">I", data[12:16])[0]

    stats.timestamps.append(ts)

    if not is_control:
        # Data packet
        seq_no = word0 & 0x7FFFFFFF
        word1 = struct.unpack(">I", data[4:8])[0]
        pp = (word1 >> 30) & 0x3    # position: 10=first, 00=middle, 01=last, 11=solo
        order_flag = (word1 >> 29) & 1
        kk = (word1 >> 27) & 0x3   # encryption
        retransmit = (word1 >> 26) & 1  # R bit (SRT)
        msg_no = word1 & 0x03FFFFFF

        stats.data_pkts += 1
        stats.data_seq_nums.append((ts, seq_no))
        if retransmit:
            stats.retrans_pkts += 1

        if verbose:
            r_flag = " [RETRANS]" if retransmit else ""
            print(f"  {ts:.6f} DATA seq={seq_no} msg={msg_no} pp={pp} kk={kk}{r_flag}  {src}->{dst}")

    else:
        # Control packet
        ctrl_type = (word0 >> 16) & 0x7FFF
        subtype = word0 & 0xFFFF
        add_info = struct.unpack(">I", data[4:8])[0]
        type_name = CTRL_TYPES.get(ctrl_type, f"UNKNOWN({ctrl_type:#06x})")
        stats.ctrl_counts[type_name] += 1

        if ctrl_type == 0x0003:  # NAK
            nak_pairs = []
            payload = data[16:]
            i = 0
            while i + 4 <= len(payload):
                val = struct.unpack(">I", payload[i:i+4])[0]
                if (val >> 31) & 1:
                    # Range start
                    start = val & 0x7FFFFFFF
                    if i + 8 <= len(payload):
                        end_val = struct.unpack(">I", payload[i+4:i+8])[0]
                        end = end_val & 0x7FFFFFFF
                        nak_pairs.append((start, end, end - start + 1))
                        i += 8
                    else:
                        nak_pairs.append((start, start, 1))
                        i += 4
                else:
                    nak_pairs.append((val, val, 1))
                    i += 4
            total_lost = sum(c for _, _, c in nak_pairs)
            stats.nak_details.append((ts, nak_pairs, total_lost))
            stats.nak_ranges.append(total_lost)
            if verbose:
                print(f"  {ts:.6f} NAK  lost={total_lost} ranges={nak_pairs}  {src}->{dst}")

        elif ctrl_type == 0x0002:  # ACK
            ack_seqno = add_info  # acknowledged up to this sequence number
            rtt = None
            if len(data) >= 20:
                ack_num = struct.unpack(">I", data[16:20])[0]  # ACK number (for ACKACK)
            if len(data) >= 28:
                rtt = struct.unpack(">I", data[20:24])[0]  # RTT in microseconds
                rtt_var = struct.unpack(">I", data[24:28])[0]
            buf_avail = None
            if len(data) >= 32:
                buf_avail = struct.unpack(">I", data[28:32])[0]  # available rcv buffer
            pkt_recv_rate = None
            link_capacity = None
            if len(data) >= 36:
                pkt_recv_rate = struct.unpack(">I", data[32:36])[0]
            if len(data) >= 40:
                link_capacity = struct.unpack(">I", data[36:40])[0]

            stats.ack_seq_nums.append((ts, ack_seqno, rtt))
            stats.ack_seqno_history.append((ts, ack_seqno))
            if verbose:
                rtt_ms = f"{rtt/1000:.2f}ms" if rtt else "?"
                buf_str = f" buf={buf_avail}" if buf_avail is not None else ""
                pkt_str = f" pkt_rate={pkt_recv_rate}" if pkt_recv_rate else ""
                cap_str = f" link_cap={link_capacity}" if link_capacity else ""
                print(f"  {ts:.6f} ACK  acked_seq={ack_seqno} rtt={rtt_ms}{buf_str}{pkt_str}{cap_str}  {src}->{dst}")

        elif ctrl_type == 0x0006:  # ACKACK
            ack_num = add_info
            stats.ackack_seq_nums.append((ts, ack_num))
            if verbose:
                print(f"  {ts:.6f} ACKACK ack_num={ack_num}  {src}->{dst}")

        elif ctrl_type == 0x0007:  # DROPREQ
            if len(data) >= 20:
                first_seq = struct.unpack(">I", data[16:20])[0] & 0x7FFFFFFF
                last_seq = struct.unpack(">I", data[20:24])[0] & 0x7FFFFFFF if len(data) >= 24 else first_seq
                count = last_seq - first_seq + 1
                stats.dropped_msg_ids.append((ts, add_info, first_seq, last_seq, count))
                stats.dropreq_details.append((ts, add_info, first_seq, last_seq))
            if verbose:
                print(f"  {ts:.6f} DROPREQ msg_id={add_info}  {src}->{dst}")

        elif ctrl_type == 0x0004:  # CONGESTION WARNING
            stats.congestion_warnings += 1
            if verbose:
                print(f"  {ts:.6f} CONGESTION_WARNING  {src}->{dst}")

        elif ctrl_type == 0x0000:  # HANDSHAKE
            if len(data) >= 48:
                version = struct.unpack(">I", data[16:20])[0]
                enc_field = struct.unpack(">H", data[20:22])[0]
                ext_field = struct.unpack(">H", data[22:24])[0]
                isn = struct.unpack(">I", data[24:28])[0]
                mss = struct.unpack(">I", data[28:32])[0]
                max_flow = struct.unpack(">I", data[32:36])[0]
                hs_type = struct.unpack(">I", data[36:40])[0]  # -1=induction, 1=conclusion
                sock_id = struct.unpack(">I", data[40:44])[0]
                if verbose:
                    hs_name = {0xFFFFFFFF: "INDUCTION", 1: "CONCLUSION", 0: "WAVEHAND"}.get(hs_type, f"{hs_type}")
                    print(f"  {ts:.6f} HANDSHAKE type={hs_name} ver={version} isn={isn} mss={mss}  {src}->{dst}")
        else:
            if verbose:
                print(f"  {ts:.6f} {type_name} sub={subtype:#06x} add={add_info}  {src}->{dst}")


def fmt_seq_gap(seqs):
    """Find sequence number gaps."""
    if len(seqs) < 2:
        return []
    sorted_seqs = sorted(seqs)
    gaps = []
    for i in range(1, len(sorted_seqs)):
        diff = sorted_seqs[i] - sorted_seqs[i-1]
        if diff > 1:
            gaps.append((sorted_seqs[i-1], sorted_seqs[i], diff - 1))
    return gaps


def analyze():
    stats = SRTStats()
    pkt_count = 0
    src_map = defaultdict(lambda: defaultdict(int))

    print("=" * 70)
    print(f"SRT PCAP Analysis: {PCAP_FILE}")
    print("=" * 70)

    with open(PCAP_FILE, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        linktype = pcap.datalink()
        # 1=Ethernet, 276=Linux SLL2 (cooked v2, 20-byte header)
        ip_offset = 20 if linktype == 276 else 14

        for ts, buf in pcap:
            pkt_count += 1
            try:
                raw_ip = buf[ip_offset:]
                ip = dpkt.ip.IP(raw_ip)
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                src = f"{dpkt.utils.inet_to_str(ip.src)}:{udp.sport}"
                dst = f"{dpkt.utils.inet_to_str(ip.dst)}:{udp.dport}"
                payload = bytes(udp.data)
                if len(payload) < 16:
                    continue
                parse_srt_packet(payload, ts, src, dst, stats, verbose=False)
                src_map[src][dst] += 1
            except Exception as e:
                pass

    duration = stats.timestamps[-1] - stats.timestamps[0] if len(stats.timestamps) > 1 else 0

    print(f"\n[OVERVIEW]")
    print(f"  Total packets : {pkt_count}")
    print(f"  Duration      : {duration:.3f}s  ({stats.timestamps[0]:.3f} - {stats.timestamps[-1]:.3f})")
    print(f"  Data packets  : {stats.data_pkts}")
    print(f"  Retransmits   : {stats.retrans_pkts}  ({100*stats.retrans_pkts/max(stats.data_pkts,1):.1f}%)")

    print(f"\n[CONTROL PACKETS]")
    for k, v in sorted(stats.ctrl_counts.items(), key=lambda x: -x[1]):
        print(f"  {k:25s}: {v}")

    print(f"\n[FLOWS]")
    for src, dsts in src_map.items():
        for dst, cnt in dsts.items():
            print(f"  {src} -> {dst}  ({cnt} pkts)")

    # NAK analysis
    if stats.nak_details:
        total_nak_events = len(stats.nak_details)
        total_lost = sum(r for _, _, r in stats.nak_details)
        nak_rate = total_nak_events / duration if duration > 0 else 0
        print(f"\n[NAK / LOSS]")
        print(f"  NAK events    : {total_nak_events}  ({nak_rate:.2f}/s)")
        print(f"  Total pkts in NAK: {total_lost}")
        print(f"  NAK events detail:")
        for ts, pairs, lost in stats.nak_details:
            rel = ts - stats.timestamps[0]
            print(f"    t+{rel:.3f}s  lost={lost}  ranges={pairs}")
    else:
        print(f"\n[NAK / LOSS]  None")

    # DROPREQ analysis
    if stats.dropreq_details:
        print(f"\n[DROPREQ - TOO-LATE DROPS]")
        print(f"  *** CRITICAL: Sender is dropping packets because they're too late to deliver ***")
        for ts, msg_id, first_seq, last_seq, in stats.dropreq_details:
            rel = ts - stats.timestamps[0]
            count = last_seq - first_seq + 1
            print(f"    t+{rel:.3f}s  msg_id={msg_id}  seq {first_seq}..{last_seq}  ({count} pkts)")
    else:
        print(f"\n[DROPREQ]  None")

    if stats.congestion_warnings:
        print(f"\n[CONGESTION WARNING]")
        print(f"  *** Congestion warnings: {stats.congestion_warnings} ***")

    # ACK progression / stalls
    if stats.ack_seqno_history:
        print(f"\n[ACK PROGRESSION]")
        ack_seqs = [s for _, s in stats.ack_seqno_history]
        rtt_vals = [r for _, _, r in stats.ack_seq_nums if r and r > 0]
        if rtt_vals:
            print(f"  RTT min/avg/max: {min(rtt_vals)/1000:.1f}ms / {sum(rtt_vals)/len(rtt_vals)/1000:.1f}ms / {max(rtt_vals)/1000:.1f}ms")

        # Detect ACK stalls (same seq reported multiple times in a row)
        stalls = []
        i = 0
        while i < len(stats.ack_seqno_history):
            j = i
            seq = stats.ack_seqno_history[i][1]
            while j < len(stats.ack_seqno_history) and stats.ack_seqno_history[j][1] == seq:
                j += 1
            if j - i > 2:
                stalls.append((stats.ack_seqno_history[i][0], stats.ack_seqno_history[j-1][0], seq, j - i))
            i = j

        if stalls:
            print(f"  *** ACK STALLS (same seq repeated): ***")
            for start_ts, end_ts, seq, count in stalls:
                rel = start_ts - stats.timestamps[0]
                dur = end_ts - start_ts
                print(f"    t+{rel:.3f}s  seq={seq} stalled for {dur:.3f}s ({count} identical ACKs)")
        else:
            print(f"  ACK progression looks normal (no stalls detected)")

        # Look for ACK going backwards (wrap or disorder)
        backwards = []
        for i in range(1, len(stats.ack_seqno_history)):
            prev_ts, prev_seq = stats.ack_seqno_history[i-1]
            cur_ts, cur_seq = stats.ack_seqno_history[i]
            # Allow for wraparound at 2^31
            delta = (cur_seq - prev_seq) & 0x7FFFFFFF
            if delta > 0x3FFFFFFF:  # went backwards by more than 25% of space
                backwards.append((cur_ts, prev_seq, cur_seq))
        if backwards:
            print(f"  *** ACK BACKWARDS jumps: ***")
            for ts, prev, cur in backwards:
                rel = ts - stats.timestamps[0]
                print(f"    t+{rel:.3f}s  {prev} -> {cur}")

    # Data sequence gap analysis
    if stats.data_seq_nums:
        seqs_only = [s for _, s in stats.data_seq_nums]
        gaps = fmt_seq_gap(seqs_only)
        if gaps:
            print(f"\n[DATA SEQUENCE GAPS (missing seqs)]")
            for lo, hi, missing in gaps[:20]:
                print(f"  seq {lo}..{hi}  missing={missing}")
            if len(gaps) > 20:
                print(f"  ... and {len(gaps)-20} more gaps")
        else:
            print(f"\n[DATA SEQUENCE GAPS]  None")

    # Inter-packet timing (look for bursts or pauses)
    if len(stats.timestamps) > 10:
        iats = [stats.timestamps[i+1] - stats.timestamps[i] for i in range(len(stats.timestamps)-1)]
        big_gaps = [(stats.timestamps[i], iats[i]) for i in range(len(iats)) if iats[i] > 0.5]
        if big_gaps:
            print(f"\n[TIMING GAPS > 500ms]")
            for t, gap in big_gaps:
                rel = t - stats.timestamps[0]
                print(f"    t+{rel:.3f}s  gap={gap*1000:.0f}ms")

    print(f"\n[DIAGNOSIS]")
    issues = []

    retrans_pct = 100 * stats.retrans_pkts / max(stats.data_pkts, 1)
    if retrans_pct > 5:
        issues.append(f"HIGH retransmission rate: {retrans_pct:.1f}% (>{5}% threshold)")
    elif retrans_pct > 1:
        issues.append(f"Elevated retransmissions: {retrans_pct:.1f}%")

    if stats.nak_details:
        issues.append(f"NAK events: {len(stats.nak_details)} - receiver is reporting lost packets")

    if stats.dropreq_details:
        issues.append(f"DROPREQ: {len(stats.dropreq_details)} messages dropped as too-late - latency budget exceeded")

    if stats.congestion_warnings:
        issues.append(f"Congestion warnings: {stats.congestion_warnings}")

    if not issues:
        issues.append("No obvious issues found in this capture")

    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")


if __name__ == "__main__":
    analyze()
