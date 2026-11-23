#!/usr/bin/env python3
"""Extract 5-tuple-independent, per-direction IP-pair/window metadata from classic Ethernet PCAP.

Stdlib only. Intended for bounded offline SCADA lab captures, not live packet capture.
Does not inspect/store packet payloads. IPv4 TCP/UDP/ICMP only; other IP
protocols are counted; non-IPv4 frames are excluded.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import struct
import sys
from urllib import request, error

PCAP_MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6),
    b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9),
    b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}
FEATURE_VERSION = 1
FEATURE_COLUMNS = [
    'packet_count', 'byte_count', 'packets_per_second', 'bytes_per_second',
    'mean_packet_bytes', 'std_packet_bytes', 'mean_interarrival_ms',
    'unique_dst_ports', 'unique_src_ports',
    'tcp_packets', 'udp_packets', 'icmp_packets', 'other_ip_packets',
    'tcp_syn_packets', 'tcp_syn_no_ack_packets', 'tcp_rst_packets',
    'icmp_echo_requests', 'icmp_echo_replies',
]
CSV_COLUMNS = [
    '@timestamp', 'window_seconds', 'feature_version', 'experiment_id',
    'scenario', 'scada_ip', 'src_ip', 'dest_ip', *FEATURE_COLUMNS,
]
MAX_GROUPS = 200_000


def packet_records(path):
    """Yield (timestamp, original frame length, frame data), validating classic PCAP."""
    with path.open('rb') as file:
        head = file.read(24)
        if len(head) != 24 or head[:4] not in PCAP_MAGIC:
            raise ValueError('Expected complete classic PCAP global header')
        endian, scale = PCAP_MAGIC[head[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + 'HHIIII', head[4:])
        if (major, minor) != (2, 4) or not 1 <= snaplen <= 16 * 1024 * 1024:
            raise ValueError('Unsupported PCAP version or snaplen')
        if (linktype & 0xffff) != 1:
            raise ValueError('Only Ethernet PCAP (LINKTYPE_ETHERNET=1) is supported')
        while True:
            h = file.read(16)
            if not h:
                break
            if len(h) != 16:
                raise ValueError('Truncated PCAP record header')
            ts_sec, ts_frac, incl, orig = struct.unpack(endian + 'IIII', h)
            if incl > snaplen or orig < incl:
                raise ValueError('Invalid PCAP record length')
            payload = file.read(incl)
            if len(payload) != incl:
                raise ValueError('Truncated PCAP packet data')
            yield ts_sec + ts_frac * scale, orig, payload


def ipv4_details(frame):
    """Return header-only attributes; skip non-IPv4 or malformed packets."""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from('!H', frame, 12)[0]
    offset = 14
    # A single or double VLAN tag is common in OT environments.
    for _ in range(2):
        if ether_type not in (0x8100, 0x88a8, 0x9100):
            break
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    vihl = frame[offset]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0f) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        return None
    iplen = struct.unpack_from('!H', frame, offset + 2)[0]
    if iplen < ihl:
        return None
    proto = frame[offset + 9]
    src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
    dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
    frag = struct.unpack_from('!H', frame, offset + 6)[0]
    transport = offset + ihl
    result = {'src_ip': src, 'dest_ip': dst, 'protocol': proto,
              'src_port': None, 'dest_port': None, 'syn': False,
              'syn_no_ack': False, 'rst': False, 'icmp_type': None}
    # Non-first fragments cannot be decoded as a new transport header.
    if frag & 0x1fff:
        return result
    if proto in (6, 17) and iplen >= ihl + 4 and len(frame) >= transport + 4:
        result['src_port'], result['dest_port'] = struct.unpack_from('!HH', frame, transport)
        if proto == 6 and iplen >= ihl + 14 and len(frame) >= transport + 14:
            flags = frame[transport + 13]
            result['syn'] = bool(flags & 0x02)
            result['syn_no_ack'] = bool(flags & 0x02) and not bool(flags & 0x10)
            result['rst'] = bool(flags & 0x04)
    if proto == 1 and iplen >= ihl + 1 and len(frame) >= transport + 1:
        result['icmp_type'] = frame[transport]
    return result


def make_group():
    return {
        'packet_count': 0, 'byte_count': 0, 'squared_bytes': 0,
        'last_seen': None, 'sum_interarrival': 0, 'num_interarrival': 0,
        'dst_ports': set(), 'src_ports': set(),
        'tcp_packets': 0, 'udp_packets': 0, 'icmp_packets': 0,
        'other_ip_packets': 0, 'tcp_syn_packets': 0,
        'tcp_syn_no_ack_packets': 0, 'tcp_rst_packets': 0,
        'icmp_echo_requests': 0, 'icmp_echo_replies': 0,
    }


def iso_utc(epoch_seconds):
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def extract(pcap_path, *, window_seconds, experiment_id, scenario, scada_ip):
    groups = {}
    total_frames = 0
    skipped = 0
    for when, frame_bytes, frame in packet_records(pcap_path):
        total_frames += 1
        pkt = ipv4_details(frame)
        if pkt is None:
            skipped += 1
            continue
        if scada_ip and scada_ip not in (pkt['src_ip'], pkt['dest_ip']):
            # Defense in depth: validate PCAP content against requested SCADA IP.
            skipped += 1
            continue
        slot = math.floor(when / window_seconds) * window_seconds
        key = (slot, pkt['src_ip'], pkt['dest_ip'])
        if key not in groups:
            if len(groups) >= MAX_GROUPS:
                raise ValueError(f'Too many groups (>={MAX_GROUPS}); shorten capture')
            groups[key] = make_group()
        g = groups[key]
        g['packet_count'] += 1
        g['byte_count'] += frame_bytes
        g['squared_bytes'] += frame_bytes ** 2
        if g['last_seen'] is not None:
            # Out-of-order capture timestamps should not yield negative intervals.
            gap = when - g['last_seen']
            if gap >= 0:
                g['sum_interarrival'] += gap
                g['num_interarrival'] += 1
        g['last_seen'] = when
        if pkt['src_port'] is not None:
            g['src_ports'].add(pkt['src_port'])
        if pkt['dest_port'] is not None:
            g['dst_ports'].add(pkt['dest_port'])
        proto = pkt['protocol']
        if proto == 6:
            g['tcp_packets'] += 1
            g['tcp_syn_packets'] += int(pkt['syn'])
            g['tcp_syn_no_ack_packets'] += int(pkt['syn_no_ack'])
            g['tcp_rst_packets'] += int(pkt['rst'])
        elif proto == 17:
            g['udp_packets'] += 1
        elif proto == 1:
            g['icmp_packets'] += 1
            g['icmp_echo_requests'] += int(pkt['icmp_type'] == 8)
            g['icmp_echo_replies'] += int(pkt['icmp_type'] == 0)
        else:
            g['other_ip_packets'] += 1
    result = []
    for (slot, src, dest), g in sorted(groups.items()):
        count = g['packet_count']
        mean = g['byte_count'] / count
        variance = max(g['squared_bytes'] / count - mean ** 2, 0.0)
        row = {
            '@timestamp': iso_utc(slot), 'window_seconds': window_seconds,
            'feature_version': FEATURE_VERSION, 'experiment_id': experiment_id,
            'scenario': scenario, 'scada_ip': scada_ip,
            'src_ip': src, 'dest_ip': dest,
            'packet_count': count, 'byte_count': g['byte_count'],
            'packets_per_second': count / window_seconds,
            'bytes_per_second': g['byte_count'] / window_seconds,
            'mean_packet_bytes': round(mean, 4),
            'std_packet_bytes': round(math.sqrt(variance), 4),
            'mean_interarrival_ms': round(1000 * g['sum_interarrival'] / g['num_interarrival'], 4)
                                    if g['num_interarrival'] else 0.0,
            'unique_dst_ports': len(g['dst_ports']),
            'unique_src_ports': len(g['src_ports']),
        }
        for field in FEATURE_COLUMNS[9:]:
            row[field] = g[field]
        result.append(row)
    return result, {'total_frames': total_frames, 'skipped_frames': skipped,
                    'analyzed_ipv4_frames': total_frames - skipped,
                    'feature_rows': len(result)}


def write_csv(rows, path):
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def es_bulk(url, index, rows):
    """Explicit opt-in ES 7-compatible bulk indexing; deterministic doc IDs."""
    base = url.rstrip('/')
    if not base.startswith(('http://', 'https://')):
        raise ValueError('--es-url requires http:// or https://')
    ok = 0
    for start in range(0, len(rows), 250):
        lines = []
        for row in rows[start:start + 250]:
            identity = '|'.join(str(row[k]) for k in ('experiment_id', '@timestamp', 'src_ip', 'dest_ip'))
            doc_id = hashlib.sha256(identity.encode('utf-8')).hexdigest()
            lines.append(json.dumps({'index': {'_index': index, '_id': doc_id}}))
            lines.append(json.dumps(row))
        body = ('\n'.join(lines) + '\n').encode('utf-8')
        req = request.Request(base + '/_bulk', data=body,
                              headers={'Content-Type': 'application/x-ndjson'}, method='POST')
        try:
            with request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
        except error.HTTPError as exc:
            raise RuntimeError(f'Elasticsearch HTTP {exc.code}: {exc.read(400)!r}') from exc
        if data.get('errors'):
            failures = [item for item in data.get('items', [])
                        if next(iter(item.values())).get('error')]
            raise RuntimeError(f'Elasticsearch bulk indexing errors: {failures[:2]}')
        ok += len(rows[start:start + 250])
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New features CSV filename')
    parser.add_argument('--window', type=int, default=5, help='Window length in seconds (1..60)')
    parser.add_argument('--es-url', default=None, help='Optional: explicitly upload to Elasticsearch')
    parser.add_argument('--index', default='scada-net-features-v1')
    args = parser.parse_args()
    if not 1 <= args.window <= 60:
        parser.error('--window must be 1..60')
    if not args.pcap.is_file():
        parser.error('PCAP file not found')
    if args.output.exists():
        parser.error('Output already exists; do not overwrite previous experiments')
    info_file = args.pcap.parent / 'capture.json'
    if not info_file.exists():
        parser.error('capture.json not found beside PCAP')
    meta = json.loads(info_file.read_text(encoding='utf-8'))
    scada_ip = str(ipaddress.IPv4Address(meta['scada_ip']))
    scenario = str(meta.get('label', 'unknown'))
    if scenario not in ('normal', 'ping_flood', 'port_scan', 'low_rate', 'modbus', 'other'):
        parser.error('Unexpected capture.json scenario label')
    experiment_id = args.pcap.parent.name
    rows, summary = extract(args.pcap, window_seconds=args.window,
                            experiment_id=experiment_id, scenario=scenario, scada_ip=scada_ip)
    if not rows:
        parser.error('No suitable IPv4 traffic found in capture')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_csv(rows, args.output)
    print(f'Saved {len(rows)} feature rows: {args.output}')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.es_url:
        indexed = es_bulk(args.es_url, args.index, rows)
        print(f'Indexed {indexed} feature rows in {args.index}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f'[ERROR] {exc}', file=sys.stderr)
        raise SystemExit(1)
