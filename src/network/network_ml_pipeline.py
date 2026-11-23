#!/usr/bin/env python3
"""SCADA network ML: one bounded capture -> features -> inference -> ES.

Run as the ordinary scada user after `sudo -v`. Only the existing capture
program runs with sudo; inference and indexing remain unprivileged.
The first version intentionally runs ONE capture, not a background daemon.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


def run(cmd, *, timeout, env=None):
    print('[RUN]', ' '.join(map(str, cmd)), flush=True)
    result = subprocess.run(
        list(map(str, cmd)), capture_output=True, text=True,
        encoding='utf-8', errors='replace', timeout=timeout, env=env,
    )
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr, flush=True)
    if result.returncode:
        raise RuntimeError(f'명령 실행 실패 (exit={result.returncode}): {cmd[0]} {cmd[1]}')


def local_ipv4(interface):
    result = subprocess.run(
        ['ip', '-4', '-o', 'addr', 'show', 'dev', interface],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        check=True, timeout=10,
    )
    addresses = []
    for line in result.stdout.splitlines():
        match = re.search(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+', line)
        if match:
            addresses.append(str(ipaddress.IPv4Address(match.group(1))))
    if len(addresses) != 1:
        raise RuntimeError(
            f'{interface}에서 IPv4 주소가 정확히 1개여야 합니다. 확인된 주소: {addresses}. '
            '인터페이스/IP 설정을 확인하세요.'
        )
    return addresses[0]


def main():
    parser = argparse.ArgumentParser(description='SCADA 네트워크 ML 1회 수집·분석·ES 저장')
    parser.add_argument('--interface', default='enp0s3', help='패킷 수집 인터페이스')
    parser.add_argument('--seconds', type=int, default=30, help='수집 시간 (1..3600초)')
    parser.add_argument('--max-mb', type=int, default=30, help='1회 PCAP 최대 크기 (1..1000MB)')
    parser.add_argument('--model', default='detector-net-v1.joblib', help='기존 학습 모델')
    parser.add_argument('--es', default='http://localhost:9200', help='Elasticsearch URL')
    parser.add_argument('--index', default='network-ml-anomaly', help='기존 Kibana 데이터 인덱스')
    parser.add_argument('--workdir', default='network_ml_runs', help='수집 및 분석 결과 저장 디렉터리')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('전체 프로그램을 root로 실행하지 마세요. scada 사용자로 실행하세요.')
    if not 1 <= args.seconds <= 3600 or not 1 <= args.max_mb <= 1000:
        parser.error('--seconds는 1..3600, --max-mb는 1..1000이어야 합니다.')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+', args.interface):
        parser.error('인터페이스 이름이 올바르지 않습니다.')
    if not args.es.startswith(('http://', 'https://')):
        parser.error('--es는 http:// 또는 https://로 시작해야 합니다.')
    if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', args.index):
        parser.error('인덱스 이름은 소문자, 숫자, 밑줄, 점, 하이픈만 사용할 수 있습니다.')

    base = Path(__file__).resolve().parent
    for filename in ('capture_scada_pcap.py', 'pcap_to_features.py',
                     'ano-snort-updated.py', 'import_network_ml.py'):
        if not (base / filename).is_file():
            raise FileNotFoundError(f'필요한 파일 없음: {base / filename}')
    model = Path(args.model).expanduser().resolve()
    if not model.is_file():
        raise FileNotFoundError(f'학습 모델 없음: {model}')
    scada_ip = local_ipv4(args.interface)
    workdir = Path(args.workdir).expanduser().resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    run_id = dt.datetime.now(dt.timezone.utc).strftime('netml_%Y%m%dT%H%M%S_%fZ_') + uuid.uuid4().hex[:8]
    run_dir = workdir / run_id
    feature_csv = run_dir / 'features_5s.csv'
    result_csv = run_dir / 'detection.csv'
    print(f'[START] SCADA={scada_ip} interface={args.interface}, duration={args.seconds}s', flush=True)
    print(f'[OUTPUT] {run_dir}', flush=True)
    print('[NOTE] label=other: 실시간 수집 데이터에 공격/정상 정답 레이블을 붙이지 않습니다.', flush=True)

    # sudo -n fails fast when a cached credential / sudo policy is unavailable.
    run([
        'sudo', '-n', sys.executable, base / 'capture_scada_pcap.py',
        '--interface', args.interface, '--host', scada_ip,
        '--seconds', args.seconds, '--max-mb', args.max_mb,
        '--output', run_dir, '--label', 'other',
    ], timeout=args.seconds + 45)
    metadata = json.loads((run_dir / 'capture.json').read_text(encoding='utf-8'))
    if not metadata.get('success') or metadata.get('saved_packets', 0) < 1:
        raise RuntimeError('PCAP 수집 실패 또는 수집된 패킷 없음')
    run([
        sys.executable, base / 'pcap_to_features.py',
        '--pcap', run_dir / 'traffic.pcap', '--output', feature_csv,
        '--window', '5',
    ], timeout=180)
    run([
        sys.executable, base / 'ano-snort-updated.py',
        '--job', 'detect', '--input', feature_csv,
        '--model', model, '--output', result_csv,
    ], timeout=180)
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    run([
        sys.executable, base / 'import_network_ml.py',
        '--es', args.es, '--index', args.index, result_csv,
    ], timeout=180, env=env)
    print(f'[SUCCESS] 1회 수집·ML 분석·Elasticsearch 저장 완료: {run_dir}', flush=True)
    print('[INFO] Kibana 조회 기간을 현재 시각으로 설정하고 새로고침하세요.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
            subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f'[ERROR] {exc}', file=sys.stderr, flush=True)
        raise SystemExit(1)
