#!/usr/bin/env python3
"""Frozen v6c/v6e final *scenario-family* Modbus ML evaluation.

Only --run calls the EXISTING lab-only write generator for the ISOLATED OpenPLC
simulator. The evaluator itself never writes to PLC and never changes a model,
Elasticsearch index or start-demo.sh. --plan, --logs-dir and --report are read-only.

IMPORTANT: experimenter-supplied 'authorized'/'attack' labels do not occur in
Modbus packets, and this experiment cannot establish ability to infer intent.
"""
import argparse
import hashlib
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parent
MODELS_DIR = ROOT.parent.parent / 'models' / 'modbus'
ES = os.environ.get('ES_URL', 'http://127.0.0.1:9200')
INDEX = 'anomaly-modbus-v5'
SHADOW = 'anomaly-modbus-v6e-shadow'
GENERATOR = ROOT / 'run-modbus-eval-v6c.py'
PLC_IP = os.environ.get('PLC_IP', '').strip()
BASIC = ['request_count', 'fc01_count', 'fc02_count', 'fc03_count',
         'write_count', 'fc05_count', 'fc06_count',
         'fc05_30s_count', 'fc06_30s_count']
SEQ = ['same_fc_run_30s', 'fc_switches_30s']
# Freeze before looking at results. Alternating benign timing is new. Both
# authorized and attack repeated-FC pairs have IDENTICAL nominal timing/FCs.
SCENARIOS = [
    ('benign-alternate-7p9', 'benign', 7.9, 8, 'normal_alternating'),
    ('authorized-fc05-9p2', 'repeat-fc05', 9.2, 4, 'normal_authorized_repeat'),
    ('attack-fc05-9p2', 'repeat-fc05', 9.2, 4, 'attack_repeat'),
    ('attack-fc06-11p7', 'repeat-fc06', 11.7, 4, 'attack_repeat'),
    ('authorized-fc06-11p7', 'repeat-fc06', 11.7, 4, 'normal_authorized_repeat'),
    ('benign-alternate-9p6', 'benign', 9.6, 8, 'normal_alternating'),
]
EVENT = re.compile(r'^EVENT scenario=(\S+) number=(\d+) fc=(\d+) value=(\S+) time=(\S+)\s*$', re.M)
START = re.compile(r'^SESSION_START scenario=(\S+) time=(\S+)\s*$', re.M)
END = re.compile(r'^SESSION_END scenario=(\S+) time=(\S+)\s*$', re.M)


def parse_time(raw):
    dt = datetime.fromisoformat(str(raw).replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise RuntimeError('timestamp에 타임존이 없습니다: ' + str(raw))
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec='microseconds')


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def es_api(index, path, data=None, timeout=25):
    req = urllib.request.Request(
        f'{ES}/{index}/{path.lstrip("/")}',
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type': 'application/json'},
        method='POST' if data is not None else 'GET',
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return json.load(res)
    except (ValueError, urllib.error.URLError) as exc:
        raise RuntimeError('Elasticsearch 조회 실패: ' + str(exc)) from exc


def frozen_models():
    result = {}
    for version, file, names in [
        ('v6c', 'detector-modbus-v6c-candidate.joblib', BASIC),
        ('v6e', 'detector-modbus-v6e-candidate.joblib', BASIC + SEQ),
    ]:
        path = MODELS_DIR / file
        if not path.is_file():
            raise RuntimeError('모델 파일 없음: ' + str(path))
        pack = joblib.load(path)
        if list(pack.get('features', [])) != names:
            raise RuntimeError(version + '의 특징 목록/순서가 다릅니다.')
        if int(pack.get('window_seconds', -1)) != 5:
            raise RuntimeError(version + ': 5초 집계 모델이 아닙니다.')
        if version == 'v6e' and int(pack.get('history_lookback_seconds', -1)) != 30:
            raise RuntimeError('v6e: 30초 이력 모델이 아닙니다.')
        if not ('model' in pack and 'decision_threshold' in pack):
            raise RuntimeError(version + '의 모델 또는 임계값 누락')
        result[version] = {'model': pack, 'file': file, 'sha256': sha(path)}
    return result


def check_model_hashes(models):
    for x in models.values():
        if sha(MODELS_DIR / x['file']) != x['sha256']:
            raise RuntimeError('실험 중 학습 모델이 변경됐습니다: ' + x['file'])


def verify_environment():
    if os.geteuid() == 0:
        raise RuntimeError('root로 실행하지 마세요. scada 사용자로 실행해야 합니다.')
    if not GENERATOR.is_file():
        raise RuntimeError('기존 시나리오 발생기가 없습니다: ' + str(GENERATOR))
    if not PLC_IP:
        raise RuntimeError("PLC_IP 환경 변수가 필요합니다.")

    if os.environ.get("ALLOW_MODBUS_WRITES") != "YES":
        raise RuntimeError(
            "Modbus 쓰기 평가 차단: 격리된 실습 환경을 확인한 뒤 "
            "ALLOW_MODBUS_WRITES=YES를 명시적으로 설정하세요."
        )

    generator_source = GENERATOR.read_text(
        encoding="utf-8", errors="replace"
    )
    if (
        'PLC_IP' not in generator_source
        or 'ALLOW_MODBUS_WRITES' not in generator_source
    ):
        raise RuntimeError("시나리오 발생기의 안전 설정을 확인하세요.")

    try:
        with socket.create_connection((PLC_IP, 502), timeout=4):
            pass
    except OSError as exc:
        raise RuntimeError(
            f"실습 PLC {PLC_IP}:502 연결 실패: {exc}"
        ) from exc

    p = subprocess.run(['pgrep', '-af', '[l]ive-modbus-es-v5.py'],
                       capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise RuntimeError('기존 v5 수집 프로세스가 보이지 않습니다. start-demo.sh 중복 실행 금지.')
    # Ensure recent source data before generating any writes.
    latest = es_api(INDEX, '_search', {
        'size': 1, 'sort': [{'@timestamp': {'order': 'desc'}}], 'query': {'match_all': {}}
    })['hits']['hits']
    if not latest:
        raise RuntimeError('원본 v5 Elasticsearch 인덱스가 비어 있습니다.')
    age = (datetime.now(timezone.utc) - parse_time(latest[0]['_source']['@timestamp'])).total_seconds()
    if not (-5 < age < 25):
        raise RuntimeError(f'v5 최신 데이터 시각이 현재와 맞지 않습니다 (age={age:.1f}s). '
                           '시계 및 수집 상태를 확인하세요.')
    return sha(GENERATOR)


def run_scenarios(folder, generator_hash, models):
    folder.mkdir(parents=True, exist_ok=False)
    manifest = {
        'generated_at_utc': iso(datetime.now(timezone.utc)),
        'protocol': 'frozen-v6c-v6e-matched-normal-vs-attack-v1',
        'source_index': INDEX, 'source_host': ES,
        'model_files': {name: {'filename': m['file'], 'sha256': m['sha256']}
                        for name, m in models.items()},
        'generator': {'filename': GENERATOR.name, 'sha256': generator_hash},
        'scenarios': [{'slug': s, 'generator_scenario': gen, 'interval_sec': interval,
                       'expected_events': n, 'ground_truth_group': group}
                      for s, gen, interval, n, group in SCENARIOS],
        'notes': [
            'Labels represent operator intent in a controlled isolated simulator; never inferred from Modbus packets.',
            'Identical repeat-fc05/06 emitter is used in authorized-normal vs attack sessions; '
            'the model does not observe authorization and cannot distinguish identical inputs.',
            '5-second windows share temporal context; windows are NOT independent statistical samples.',
            'No model fitting or threshold changes during this evaluation.',
        ],
    }
    (folder / 'protocol.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print('실험 로그 디렉터리:', folder, flush=True)
    print('격리된 OpenPLC에만 실습용 쓰기를 전송합니다.', flush=True)
    print('실험 시작 전 30초 이력 제거를 위한 쓰기 없는 휴지 구간...', flush=True)
    time.sleep(40)
    for i, (slug, scenario, interval, count, group) in enumerate(SCENARIOS):
        if i:
            print('다음 세션 전 30초 이력 분리를 위한 휴지 구간...', flush=True)
            time.sleep(40)
        check_model_hashes(models)
        if sha(GENERATOR) != generator_hash:
            raise RuntimeError('실험 중 요청 발생기가 변경됐습니다.')
        print(f'[{i+1}/{len(SCENARIOS)}] {slug} '
              f'({group}, interval={interval}s, events={count})', flush=True)
        cmd = [sys.executable, '-u', str(GENERATOR), '--scenario', scenario,
               '--interval', str(interval)]
        output = folder / f'{slug}.log'
        with output.open('w', encoding='utf-8') as fh:
            try:
                p = subprocess.run(cmd, cwd=str(ROOT), stdout=fh,
                                   stderr=subprocess.STDOUT, check=False, timeout=180)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f'{slug}: 발생기 실행 시간 초과. 중단: {output}') from exc
        body = output.read_text(encoding='utf-8', errors='replace')
        print(body, end='' if body.endswith('\n') else '\n', flush=True)
        if p.returncode != 0 or len(EVENT.findall(body)) != count or not END.search(body):
            raise RuntimeError(f'{slug}: 실행 오류 또는 요청 수 불일치. {output}를 확인하세요.')
    print('최종 5초 수집 구간 및 Elasticsearch 인덱싱 반영 중...', flush=True)
    time.sleep(15)
    check_model_hashes(models)


def log_events(folder):
    events = []
    for slug, scenario, interval, count, group in SCENARIOS:
        path = folder / f'{slug}.log'
        if not path.is_file():
            raise RuntimeError('실험 로그가 없습니다: ' + str(path))
        txt = path.read_text(encoding='utf-8', errors='replace')
        starts, ends = START.findall(txt), END.findall(txt)
        found = EVENT.findall(txt)
        if len(starts) != 1 or len(ends) != 1 or len(found) != count:
            raise RuntimeError(slug + ': 시작/종료 로그 또는 요청 수 불일치')
        if starts[0][0] != scenario or ends[0][0] != scenario:
            raise RuntimeError(slug + ': 시나리오 이름이 다릅니다.')
        start_t, end_t = parse_time(starts[0][1]), parse_time(ends[0][1])
        if start_t > end_t:
            raise RuntimeError('시작 시간 > 종료 시간: ' + slug)
        for observed, number, fc, value, stamp in found:
            when = parse_time(stamp)
            if observed != scenario or not start_t <= when <= end_t + timedelta(seconds=2):
                raise RuntimeError('시나리오 또는 시간 경계 위반: ' + slug)
            expected_fc = 5 if scenario == 'repeat-fc05' else 6 if scenario == 'repeat-fc06' else None
            if expected_fc is not None and int(fc) != expected_fc:
                raise RuntimeError('잘못된 FC 코드: ' + slug)
            if scenario == 'benign' and int(fc) != (5 if int(number) % 2 else 6):
                raise RuntimeError('교대 쓰기 시나리오 FC 순서 오류: ' + slug)
            events.append({'scenario': slug, 'generator_scenario': observed,
                           'group': group, 'attack': group == 'attack_repeat',
                           'event_number': int(number), 'fc': int(fc),
                           'event_time': iso(when), 'value_logged': value,
                           'interval_sec': interval})
    return events


def query_write_window(event, seen):
    t = parse_time(event['event_time'])
    q = {
        'size': 50, 'track_total_hits': True,
        'sort': [{'@timestamp': {'order': 'asc'}}],
        'query': {'range': {'@timestamp': {
            'gte': iso(t), 'lte': iso(t + timedelta(seconds=6))}}},
    }
    results = es_api(INDEX, '_search', q)['hits']
    if results['total']['relation'] != 'eq' or results['total']['value'] != len(results['hits']):
        raise RuntimeError('이벤트 구간 ES 조회가 불완전합니다: ' + event['event_time'])
    candidates = [h for h in results['hits']
                  if int(h['_source'].get('write_count', 0)) == 1
                  and int(h['_source'].get(f"fc{event['fc']:02d}_count", 0)) == 1]
    if len(candidates) != 1:
        raise RuntimeError(f"{event['scenario']} #{event['event_number']}: "
                           f"v5 단일 쓰기 구간 매칭 {len(candidates)}건 — 임의 매칭 금지")
    h = candidates[0]
    if h['_id'] in seen:
        raise RuntimeError('서로 다른 이벤트가 같은 5초 구간에 매칭: ' + h['_id'])
    seen.add(h['_id'])
    return h


def extract_history(hit):
    src = hit['_source']
    if int(src['write_count']) != 1:
        raise RuntimeError('대상 구간의 쓰기 수가 1이 아닙니다.')
    end = parse_time(src['@timestamp'])
    q = {'size': 250, 'track_total_hits': True,
         'sort': [{'@timestamp': {'order': 'asc'}}],
         'query': {'range': {'@timestamp': {
             'gte': iso(end - timedelta(seconds=30)), 'lte': iso(end)}}}}
    result = es_api(INDEX, '_search', q)['hits']
    total = result['total']
    if total['relation'] != 'eq' or total['value'] != len(result['hits']):
        raise RuntimeError('최근 30초 ES 집계 누락')
    writes = []
    for item in result['hits']:
        doc = item['_source']
        n = int(doc.get('write_count', 0))
        if n == 0:
            continue
        if n != 1:
            raise RuntimeError('최근 30초 이력에 복수 쓰기 구간이 있어 순서를 알 수 없습니다.')
        a = int(doc.get('fc05_count', 0))
        b = int(doc.get('fc06_count', 0))
        if (a, b) not in ((1, 0), (0, 1)):
            raise RuntimeError('최근 30초 쓰기 FC05/FC06 집계 불일치')
        writes.append((parse_time(doc['@timestamp']), item['_id'], 5 if a else 6))
    writes.sort(key=lambda r: (r[0], r[1]))
    if not writes or writes[-1][1] != hit['_id']:
        raise RuntimeError('현재 이벤트가 30초 이력의 마지막 쓰기 이벤트가 아닙니다.')
    if len({w[0] for w in writes}) != len(writes):
        raise RuntimeError('동일 timestamp 중복 쓰기 — 순서 복원 불가')
    seq = [w[2] for w in writes]
    run = 1
    for fc in reversed(seq[:-1]):
        if fc != seq[-1]:
            break
        run += 1
    switches = sum(a != b for a, b in zip(seq, seq[1:]))
    return [float(run), float(switches)], writes


def check_session_contamination(events, matched):
    # Every write-containing window within each session's 30s context must
    # belong to its own scenario (otherwise a concurrent generator could bias).
    for slug, _, _, _, _ in SCENARIOS:
        sub = [e for e in events if e['scenario'] == slug]
        if not sub:
            continue
        start = parse_time(min(e['event_time'] for e in sub))
        finish = parse_time(max(e['es_timestamp'] for e in sub))
        q = {'size': 500, 'track_total_hits': True,
             'query': {'bool': {'filter': [
                 {'range': {'@timestamp': {'gte': iso(start - timedelta(seconds=30)),
                                            'lte': iso(finish)}}},
                 {'range': {'write_count': {'gt': 0}}},
             ]}}}
        x = es_api(INDEX, '_search', q)['hits']
        if x['total']['relation'] != 'eq' or x['total']['value'] != len(x['hits']):
            raise RuntimeError(slug + ': 세션 내 쓰기 전체 조회가 불완전합니다.')
        expected = {e['es_document_id'] for e in sub}
        observed = {h['_id'] for h in x['hits']}
        if observed != expected:
            raise RuntimeError(slug + ': 세션 내 외부 쓰기 또는 30초 이력 오염을 발견했습니다. '
                               '원본 ES를 수정하지 않고 평가를 중단합니다. '
                               f'extra={observed - expected}, missing={expected - observed}')


def load_shadow_hit(source_id):
    try:
        return es_api(SHADOW, '_doc/' + source_id)
    except RuntimeError:
        return None


def evaluate_logs(folder, models):
    raw_events = log_events(folder)
    seen = set()
    events = []
    for event in raw_events:
        hit = query_write_window(event, seen)
        src = hit['_source']
        basic = [float(src[k]) for k in BASIC]
        extra, _ = extract_history(hit)
        all_features = basic + extra
        if not np.all(np.isfinite(np.array(all_features))):
            raise RuntimeError('비정상 수치가 있습니다: ' + hit['_id'])
        event.update({'es_timestamp': src['@timestamp'],
                      'es_document_id': hit['_id'],
                      'features': dict(zip(BASIC + SEQ, all_features)),
                      'models': {}})
        for version, packinfo in models.items():
            pack = packinfo['model']
            vec = basic if version == 'v6c' else all_features
            decision = float(pack['model'].decision_function(np.array([vec])).ravel()[0])
            threshold = float(pack['decision_threshold'])
            if not math.isfinite(decision):
                raise RuntimeError(version + ' 점수가 유효하지 않습니다.')
            event['models'][version] = {'score': decision, 'threshold': threshold,
                                        'anomaly': bool(decision < threshold)}
        shadow = load_shadow_hit(hit['_id'])
        event['shadow'] = {'exists': bool(shadow and shadow.get('found'))}
        if shadow and shadow.get('found'):
            doc = shadow['_source']
            actual = doc.get('ml_decision_score')
            event['shadow'].update({'status': doc.get('analysis_status'),
                                    'pred': doc.get('pred'), 'score': actual})
            if (doc.get('analysis_status') != 'SCORED'
                    or actual is None or abs(float(actual) - event['models']['v6e']['score']) > 1e-8
                    or bool(doc.get('ml_is_anomaly')) != event['models']['v6e']['anomaly']):
                raise RuntimeError('v6e 섀도 vs 오프라인 ML 점수/판정 불일치: ' + hit['_id'])
        events.append(event)
    check_session_contamination(events, seen)
    check_model_hashes(models)
    report = make_report(events, models)
    out = folder / 'final-ml-evaluation.json'
    if out.exists():
        raise RuntimeError('기존 최종 성능평가 JSON 덮어쓰기 거부: ' + str(out))
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    txt_path = folder / 'final-ml-evaluation.txt'
    if txt_path.exists():
        raise RuntimeError('기존 최종 성능평가 TXT 덮어쓰기 거부: ' + str(txt_path))
    txt_path.write_text(report_text(report), encoding='utf-8')
    print(report_text(report), flush=True)
    print('원본 JSON:', out)
    print('요약 TXT:', txt_path)
    print('v5 / v6e 섀도 인덱스, 모델 및 start-demo.sh를 변경하지 않았습니다.')


def ratio(a, b):
    return a / b if b else None


def calc_confusion(events, version):
    tp = tn = fp = fn = 0
    for e in events:
        label = bool(e['attack'])
        pred = bool(e['models'][version]['anomaly'])
        if label and pred:
            tp += 1
        elif label:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    n = tp + tn + fp + fn
    return {'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
            'accuracy': ratio(tp + tn, n),
            'precision': ratio(tp, tp + fp),
            'recall': ratio(tp, tp + fn),
            'specificity': ratio(tn, tn + fp),
            'fpr': ratio(fp, fp + tn),
            'f1': ratio(2 * tp, 2 * tp + fp + fn)}


def make_report(events, models):
    groups = {}
    for group in ('normal_alternating', 'normal_authorized_repeat', 'attack_repeat'):
        subset = [e for e in events if e['group'] == group]
        groups[group] = {'n': len(subset),
                         'alert_count': {name: sum(bool(e['models'][name]['anomaly']) for e in subset)
                                         for name in models}}
    sessions = []
    for slug, _, interval, _, group in SCENARIOS:
        subset = [e for e in events if e['scenario'] == slug]
        sessions.append({'name': slug, 'group': group, 'interval_sec': interval,
                         'n': len(subset),
                         'alerts': {name: sum(bool(e['models'][name]['anomaly']) for e in subset)
                                    for name in models}})
    matched = []
    for suffix in ('fc05-9p2', 'fc06-11p7'):
        allowed = [e for e in events if e['scenario'] == 'authorized-' + suffix]
        attacks = [e for e in events if e['scenario'] == 'attack-' + suffix]
        for a, b in zip(allowed, attacks):
            matched.append({'authorized_id': a['es_document_id'],
                            'attack_id': b['es_document_id'],
                            'fc': a['fc'], 'event_number': a['event_number'],
                            'equal_11_features': a['features'] == b['features'],
                            'different_fields': [k for k in BASIC + SEQ if a['features'][k] != b['features'][k]]})
    return {'created_utc': iso(datetime.now(timezone.utc)),
            'title': 'Frozen v6c/v6e Modbus ML final controlled-scenario evaluation',
            'source_index': INDEX,
            'scenario_family_not_generalization': True,
            'label_definition': {'normal_alternating': 'Operator labels as authorized',
                                 'normal_authorized_repeat': 'Operator labels as authorized, same emitter as attack',
                                 'attack_repeat': 'Operator labels as unauthorized attack *simulation*, identical emitter as authorized'},
            'model_files': {n: {'filename': m['file'], 'sha256': m['sha256']}
                            for n, m in models.items()},
            'counts': {'total': len(events), 'normal': sum(not e['attack'] for e in events),
                       'attack': sum(e['attack'] for e in events)},
            'metrics': {name: calc_confusion(events, name) for name in models},
            'groups': groups, 'sessions': sessions, 'matching_pairs': matched,
            'shadow_matched': sum(bool(e['shadow']['exists']) for e in events),
            'events': events,
            'limitations': [
                'Model frozen, novel timing but same scenario family, same software generator; not independent real-world attack generalization.',
                'Operator approval/intent is not a feature; identical packet behavior cannot reveal permission.',
                'Scores use 5s ES windows and 30s window-end lookback; not individual packet timestamps.',
                'Correlated windows within sessions make event-level percentage optimistic as independent evidence.',
                'Each written event has exactly one v5 ES window; missing/ambiguous/unscorable events abort assessment, not relabeled normal.',
                'Policy alerts not included; scores are frozen OCSVM decision_function only.',
            ]}


def percent(x):
    return 'N/A' if x is None else f'{100*x:.2f}%'


def report_text(report):
    lines = ['===== 최종 통제 시나리오 성능평가: 동결 모델 v6c / v6e =====',
             '학습·임계값 변경 없음 | 모든 지표는 ML 판단만 사용',
             f"총 {report['counts']['total']}구간 | 정상 {report['counts']['normal']} | 공격 라벨 {report['counts']['attack']}",
             '', '모델 | TP | TN | FP | FN | 정확도 | 정밀도 | 재현율 | F1 | 정상 오탐률']
    for name in ('v6c', 'v6e'):
        m = report['metrics'][name]
        lines.append(f"{name} | {m['TP']} | {m['TN']} | {m['FP']} | {m['FN']} | "
                     f"{percent(m['accuracy'])} | {percent(m['precision'])} | "
                     f"{percent(m['recall'])} | {percent(m['f1'])} | {percent(m['fpr'])}")
    lines.extend(['', '===== 정상/공격 시나리오별 경보율 ====='])
    for group, stats in report['groups'].items():
        lines.append(f"{group}: N={stats['n']} " + ', '.join(
            f'{model}={stats["alert_count"][model]}/{stats["n"]}' for model in ('v6c', 'v6e')))
    lines.extend(['', '===== 세션별 경보 건수 ====='])
    for item in report['sessions']:
        lines.append(f"{item['name']} N={item['n']} v6c={item['alerts']['v6c']} v6e={item['alerts']['v6e']}")
    lines.extend(['', '===== 승인/공격 반복쓰기 특징 일치 점검 =====',
                  f"동일한 11특징 벡터 쌍: {sum(e['equal_11_features'] for e in report['matching_pairs'])}/{len(report['matching_pairs'])}",
                  f"실시간 섀도 결과 대조 성공: {report['shadow_matched']}/{report['counts']['total']}",
                  '', '해석 주의: 승인된 동일 FC 쓰기와 공격 라벨 쓰기는 동일한 발생기/간격입니다.',
                  '승인 정보가 ML 입력에 없으므로 네트워크 행동만으로 의도 분류가 불가능합니다.',
                  '위 지표는 새 시점·간격의 동일 실험 시나리오 계열에 한정됩니다.',
                  '세션 내 5초 구간은 독립 샘플이 아니므로 결과를 실제 운영 성능으로 일반화하지 마세요.'])
    return '\n'.join(lines) + '\n'


def show_plan():
    print('===== 최종 평가 고정 계획 (PLC 요청/ES 쓰기 없음) =====')
    print('정상 교대 16, 승인된 반복 8, 공격 반복 8; 총 32개 5초 쓰기 포함 구간')
    print('모델: v6c(9특징) vs v6e(11특징), 각 저장된 임계값 고정')
    for slug, scenario, interval, n, label in SCENARIOS:
        print(f'{slug}: {scenario}, {interval}s, {n}건, {label}')
    print('고정 평가의 목표: 공격 탐지율뿐 아니라 승인된 반복 쓰기의 오탐률 측정')
    print('참고: 동일 패턴의 승인 여부는 Modbus ML로 판단 불가')


def main():
    ap = argparse.ArgumentParser(description='격리된 OpenPLC에서 동결 v6c/v6e 최종 통제 시나리오 평가')
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--plan', action='store_true', help='평가 계획만 표시(안전)')
    modes.add_argument('--run', action='store_true', help='실습용 OpenPLC에 통제된 쓰기 시나리오 실제 전송')
    modes.add_argument('--logs-dir', type=Path, help='기존 실험 로그로 ES 재평가(PLC 요청 없음)')
    modes.add_argument('--report', type=Path, help='저장된 최종 JSON 결과만 다시 표시')
    args = ap.parse_args()
    if args.plan:
        show_plan()
        return
    if args.report:
        data = json.loads(args.report.expanduser().read_text(encoding='utf-8'))
        print(report_text(data))
        return
    models = frozen_models()
    if args.run:
        generator_hash = verify_environment()
        folder = ROOT / ('eval-modbus-final-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
        run_scenarios(folder, generator_hash, models)
    else:
        folder = args.logs_dir.expanduser().resolve()
    evaluate_logs(folder, models)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, TypeError, OSError, IndexError) as exc:
        raise SystemExit('평가 중단: ' + str(exc)) from exc
