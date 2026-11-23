#!/usr/bin/env python3
"""Continuous SCADA PCAP capture + asynchronous network-ML/Elasticsearch processing.

Runs as the normal 'scada' user. Only tcpdump uses cached sudo.
Sudo credentials are often tied to controlling TTY, so the child does not
start a new session (which would invalidate the cached credentials).
One tcpdump process streams classic-PCAP records without capture gaps between
ML batches. Complete, bounded segments are atomically published and consumed
by a separate worker. No model training, Snort, PLC or ES configuration changes.

First test: sudo -v && PYTHONIOENCODING=utf-8 python3 network_ml_stream.py --segments 2
This test does NOT install a boot service or permanent sudo permission.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
import uuid

PCAP_MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def log(msg):
    print(f'[{datetime.now().astimezone().isoformat(timespec="seconds")}] {msg}', flush=True)


def ipv4_of(interface):
    p = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'dev', interface],
                       capture_output=True, text=True, timeout=10, check=True)
    matches = re.findall(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+', p.stdout)
    if len(matches) != 1:
        raise RuntimeError(f'{interface}의 IPv4 주소가 정확히 1개여야 합니다: {matches}')
    return str(ipaddress.IPv4Address(matches[0]))


class PCAPRecords:
    """Incrementally parse tcpdump stdout without splitting packet records."""

    def __init__(self):
        self.buffer = bytearray()
        self.header = None
        self.endian = None
        self.snaplen = None
        self.ts_scale = None
        self.expected = None

    def feed(self, chunk, on_packet):
        self.buffer.extend(chunk)
        while True:
            if self.header is None:
                if len(self.buffer) < 24:
                    return
                header = bytes(self.buffer[:24])
                if header[:4] not in PCAP_MAGIC:
                    raise RuntimeError('tcpdump stdout is not classic PCAP')
                self.endian, self.ts_scale = PCAP_MAGIC[header[:4]]
                major, minor, _, _, snaplen, linktype = struct.unpack(self.endian + 'HHIIII', header[4:])
                if (major, minor) != (2, 4) or not (1 <= snaplen <= 16_777_216):
                    raise RuntimeError('Unsupported PCAP version or snaplen')
                if linktype & 0xffff != 1:
                    raise RuntimeError('Expected Ethernet PCAP (LINKTYPE_ETHERNET=1)')
                self.header = header
                self.snaplen = snaplen
                del self.buffer[:24]
            if self.expected is None:
                if len(self.buffer) < 16:
                    return
                ts_sec, ts_frac, incl, orig = struct.unpack_from(self.endian + 'IIII', self.buffer)
                if incl > self.snaplen or orig < incl or ts_frac >= self.ts_scale:
                    raise RuntimeError('Invalid PCAP record header')
                self.expected = 16 + incl
            if len(self.buffer) < self.expected:
                return
            record = bytes(self.buffer[:self.expected])
            del self.buffer[:self.expected]
            self.expected = None
            on_packet(record)

    def ensure_complete(self):
        if self.header is None or self.expected is not None or self.buffer:
            raise RuntimeError('PCAP stream ended with an incomplete header/packet')


class SegmentWriter:
    def __init__(self, base, header, interface, ip, max_mb):
        dirname = datetime.now(timezone.utc).strftime('seg_%Y%m%dT%H%M%S_%fZ_') + uuid.uuid4().hex[:8]
        self.dir = base / dirname
        self.dir.mkdir(mode=0o700)
        self.partial = self.dir / 'traffic.pcap.partial'
        self.file = self.partial.open('xb')
        self.file.write(header)
        self.bytes = len(header)
        self.packets = 0
        self.interface = interface
        self.ip = ip
        self.max_bytes = max_mb * 1_000_000
        self.started = utc_now()

    def can_fit(self, n):
        return self.bytes + n <= self.max_bytes

    def write(self, packet):
        if not self.can_fit(len(packet)):
            raise RuntimeError('Packet exceeds maximum PCAP segment size')
        self.file.write(packet)
        self.bytes += len(packet)
        self.packets += 1

    def close(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()
        if self.packets == 0:
            self.partial.unlink()
            self.dir.rmdir()
            return None
        self.partial.rename(self.dir / 'traffic.pcap')
        meta = {
            'schema': 2, 'interface': self.interface, 'scada_ip': self.ip,
            'filter': f'ip and host {self.ip}', 'label': 'other',
            'capture_mode': 'continuous_stream', 'started_at': self.started,
            'ended_at': utc_now(), 'saved_packets': self.packets,
            'pcap_bytes': self.bytes, 'success': True,
        }
        part = self.dir / 'capture.json.partial'
        part.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        part.replace(self.dir / 'capture.json')
        return self.dir


def run_step(cmd, *, cwd, timeout=180):
    log('[STEP] ' + ' '.join(str(c) for c in cmd))
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    outcome = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env,
                             capture_output=True, text=True, encoding='utf-8',
                             errors='replace', timeout=timeout)
    if outcome.stdout:
        log(outcome.stdout.strip()[-2500:])
    if outcome.stderr:
        log('STDERR: ' + outcome.stderr.strip()[-1600:])
    if outcome.returncode:
        raise RuntimeError(f'exit={outcome.returncode}: {cmd[1] if len(cmd) > 1 else cmd[0]}')


def analyze_segment(directory, *, base, model, es, index):
    features = directory / 'features_5s.csv'
    detection = directory / 'detection.csv'
    # Keep existing successful stages for retrying an interrupted ES upload.
    if not features.exists():
        run_step([sys.executable, base / 'pcap_to_features.py', '--pcap', directory / 'traffic.pcap',
                  '--output', features, '--window', 5], cwd=base)
    if not detection.exists():
        run_step([sys.executable, base / 'ano-snort-threshold-v2.py', '--job', 'detect',
                  '--input', features, '--model', model, '--output', detection], cwd=base)
    run_step([sys.executable, base / 'import_network_ml.py', '--es', es,
              '--index', index, detection], cwd=base)
    (directory / 'indexed.ok').write_text(utc_now() + '\n', encoding='utf-8')
    (directory / 'failed.txt').unlink(missing_ok=True)


def worker_main(workq, *, base, model, es, index, stats):
    while True:
        directory = workq.get()
        if directory is None:
            workq.task_done()
            return
        try:
            if not (directory / 'indexed.ok').exists():
                log(f'[ML] 분석 시작: {directory.name}')
                analyze_segment(directory, base=base, model=model, es=es, index=index)
                stats['success'] += 1
                log(f'[ML] 분석·ES 저장 완료: {directory.name}')
        except Exception as exc:
            stats['errors'] += 1
            log(f'[ML ERROR] {directory.name}: {exc} (데이터 유지; 다음 실행에서 재시도)')
            (directory / 'failed.txt').write_text(f'{utc_now()}\n{exc}\n', encoding='utf-8')
        finally:
            workq.task_done()


def pending_segments(workdir):
    # Only consume this program's completed segments, not legacy batch experiments.
    for path in sorted(workdir.glob('stream_*/seg_*')):
        if ((path / 'traffic.pcap').is_file() and (path / 'capture.json').is_file()
                and not (path / 'indexed.ok').exists()):
            yield path


def main():
    p = argparse.ArgumentParser(description='Continuous tcpdump capture + independent network-ML worker')
    p.add_argument('--interface', default='enp0s3')
    p.add_argument('--seconds', type=int, default=30, help='분할 주기(초), 5..3600')
    p.add_argument('--max-mb', type=int, default=30, help='PCAP 파일당 크기 상한, MB')
    p.add_argument('--segments', type=int, default=0, help='0: 지속 실행; 2: 검증용 2개 구간')
    p.add_argument('--min-free-mb', type=int, default=500)
    p.add_argument('--queue-size', type=int, default=8)
    p.add_argument('--workdir', default='network_ml_stream_runs')
    p.add_argument('--model', default='detector-net-v1.joblib')
    p.add_argument('--es', default='http://localhost:9200')
    p.add_argument('--index', default='network-ml-anomaly')
    p.add_argument('--tcpdump', default='/usr/bin/tcpdump')
    p.add_argument('--capture-mode', choices=['sudo', 'direct'], default='sudo',
                   help='sudo: cached sudo -v required in current TTY; direct: privileged tcpdump capability')
    args = p.parse_args()
    if os.geteuid() == 0:
        p.error('Do not run this entire program as root')
    if not (5 <= args.seconds <= 3600 and 1 <= args.max_mb <= 1000 and
            0 <= args.segments and 0 <= args.min_free_mb and 1 <= args.queue_size <= 100):
        p.error('Invalid numeric arguments')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+', args.interface):
        p.error('Invalid interface name')
    if not args.es.startswith(('http://', 'https://')):
        p.error('Invalid Elasticsearch URL')
    base = Path(__file__).resolve().parent
    for name in ('pcap_to_features.py', 'ano-snort-threshold-v2.py', 'import_network_ml.py'):
        if not (base / name).is_file():
            p.error(f'Missing {base / name}')
    model = (base / args.model).resolve()
    if not model.is_file():
        p.error(f'Model not found: {model}')
    workdir = (base / args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    lockfile = workdir / '.stream.lock'
    with lockfile.open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log('[ERROR] Another continuous network ML collector is running in this workdir')
            return 2
        return run_locked(args, base, workdir, model)


def run_locked(args, base, workdir, model):
    ip = ipv4_of(args.interface)
    if shutil.disk_usage(workdir).free < args.min_free_mb * 1_000_000:
        raise RuntimeError('Not enough free disk space before capture')
    session = workdir / (datetime.now(timezone.utc).strftime('stream_%Y%m%dT%H%M%S_%fZ_')
                         + uuid.uuid4().hex[:8])
    session.mkdir(mode=0o700)
    workq = queue.Queue(maxsize=args.queue_size)
    stats = {'success': 0, 'errors': 0}
    thread = threading.Thread(target=worker_main, args=(workq,),
                              kwargs={'base': base, 'model': model, 'es': args.es,
                                      'index': args.index, 'stats': stats}, daemon=False)
    thread.start()

    try:
        existing = list(pending_segments(workdir))
        for path in existing:
            log(f'[RECOVER] unfinished ES delivery: {path.name}')
            workq.put(path, timeout=3)
    except Exception:
        workq.put(None)
        thread.join()
        raise

    cmd = ([] if args.capture_mode == 'direct' else ['sudo', '-n']) + [
        args.tcpdump, '-i', args.interface, '-nn', '-s', '0', '-U', '-w', '-',
        f'ip and host {ip}',
    ]
    log(f'[START] interface={args.interface}, scada_ip={ip}, rotation={args.seconds}s, '
        f'per-PCAP={args.max_mb}MB, max_segments={args.segments or "infinite"}')
    log('[NOTE] tcpdump continuously captures while ML runs on an independent worker thread')
    log('[NOTE] No automatic deletion; low disk space or backlog stops capture; PCAPs are preserved')
    log('[NOTE] Scenario label is other, NOT a ground-truth attack classification')
    log('[TCPDUMP] ' + ' '.join(cmd))
    parser = PCAPRecords()
    stop = threading.Event()
    completed = 0
    empty_intervals = 0
    current = None
    last_tick = time.monotonic()
    stderr_log = (session / 'tcpdump.log').open('w', encoding='utf-8')
    proc = None
    process_exit_unexpected = False
    previous_handlers = {}
    last_ip_check = time.monotonic()

    def request_stop(signum, _frame):
        log(f'[SIGNAL] {signum} -> graceful stop requested')
        stop.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, request_stop)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_log,
                                start_new_session=False, bufsize=0)
        os.set_blocking(proc.stdout.fileno(), False)
        if proc.poll() is not None:
            raise RuntimeError('tcpdump terminated immediately; check sudo credentials or tcpdump log')

        def complete_segment():
            nonlocal current, completed, empty_intervals
            if current is None:
                empty_intervals += 1
                log("[CAPTURE] no matching packets during this interval; no ES document generated")
            if current is not None:
                path = current.close()
                current = None
                if path is not None:
                    log(f'[CAPTURE] closed {path.name}; queued for inference')
                    try:
                        workq.put(path, timeout=2)
                    except queue.Full:
                        raise RuntimeError('ML worker backlog full; capture stops without dropping stored PCAP')
            completed += 1
            log(f'[ROTATE] {completed} complete interval(s)')

        def append_record(record):
            nonlocal current
            if current is None:
                current = SegmentWriter(session, parser.header, args.interface, ip, args.max_mb)
            if not current.can_fit(len(record)):
                # Hard per-file cap: rotate on a packet boundary, never truncate.
                path = current.close()
                current = SegmentWriter(session, parser.header, args.interface, ip, args.max_mb)
                if path is not None:
                    try:
                        workq.put(path, timeout=2)
                    except queue.Full:
                        raise RuntimeError('ML worker backlog full after size rotation')
                log('[ROTATE] hard PCAP size limit reached')
            current.write(record)

        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while not stop.is_set():
                if proc.poll() is not None:
                    process_exit_unexpected = True
                    break
                if shutil.disk_usage(workdir).free < args.min_free_mb * 1_000_000:
                    raise RuntimeError('Low disk space: stopping capture safely')
                if workq.full():
                    raise RuntimeError('ML backlog reached queue limit: stopping capture safely')
                if time.monotonic() - last_ip_check >= 5:
                    if ipv4_of(args.interface) != ip:
                        raise RuntimeError(f'{args.interface} IPv4 changed: stop/restart needed (was {ip})')
                    last_ip_check = time.monotonic()
                for key, _ in selector.select(timeout=0.2):
                    while True:
                        try:
                            chunk = os.read(key.fd, 65536)
                        except BlockingIOError:
                            break
                        if not chunk:
                            process_exit_unexpected = True
                            break
                        parser.feed(chunk, append_record)
                        if len(chunk) < 65536:
                            break
                if process_exit_unexpected:
                    break
                if time.monotonic() - last_tick >= args.seconds:
                    complete_segment()
                    last_tick = time.monotonic()
                    if args.segments and completed >= args.segments:
                        stop.set()
    finally:
        # Stop tcpdump without terminating the unprivileged ML worker.
        if proc is not None and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=8)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
        if proc is not None and proc.stdout is not None:
            # After the producer stops, consume any buffered final records.
            os.set_blocking(proc.stdout.fileno(), True)
            remaining = proc.stdout.read()
            if remaining:
                parser.feed(remaining, append_record)
            proc.stdout.close()
        stderr_log.close()
        if current is not None:
            path = current.close()
            if path is not None:
                try:
                    workq.put(path, timeout=2)
                    log(f'[CAPTURE] final segment queued: {path.name}')
                except queue.Full:
                    log(f'[WARNING] {path.name} retained on disk for next run; queue is full')
        log('[STOP] waiting for ML worker to finish queued segments')
        workq.put(None)
        thread.join()
        for sig, old in previous_handlers.items():
            signal.signal(sig, old)

    if process_exit_unexpected:
        raise RuntimeError(f'tcpdump exited unexpectedly (code={proc.returncode}); see {session / "tcpdump.log"}')
    log(f'[SUMMARY] rotation_intervals={completed}, empty_intervals={empty_intervals}, ML_success={stats["success"]}, ML_errors={stats["errors"]}; saved session={session}')
    if stats['errors']:
        raise RuntimeError('One or more completed PCAP segments failed ML/ES delivery; inspect failed.txt and retry on the next launch')
    log('[SUCCESS] capture and queued ML processing stopped cleanly')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as e:
        log(f'[ERROR] {e}')
        raise SystemExit(1)
