#!/usr/bin/env python3
"""Modbus v6e: chronological network write-sequence features + One-Class SVM.

Read-only. Loads Elasticsearch anomaly-modbus-v5 windows, prior benign lab
session logs, and one existing comparison JSON. Does NOT send PLC commands,
change Elasticsearch, stop/restart detectors, or modify start-demo.sh.

Sequence information is recoverable *only* for one-write-per-5s windows.
In any ambiguous recent write window (>=2 writes), abort rather than invent
packet order. For production, calculate the same two features on the raw
Modbus packet stream and evaluate with independently held-out scenarios.
"""
import argparse
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

import joblib
import numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / 'data'
MODELS_DIR = ROOT.parent.parent / 'models' / 'modbus'
INDEX = 'anomaly-modbus-v5'
ES = 'http://localhost:9200/' + INDEX
OUTPUT = MODELS_DIR / 'detector-modbus-v6e-candidate.joblib'
BASE = MODELS_DIR / 'detector-modbus-v6c-candidate.joblib'
NAMES = ['request_count', 'fc01_count', 'fc02_count', 'fc03_count',
         'write_count', 'fc05_count', 'fc06_count',
         'fc05_30s_count', 'fc06_30s_count']
EXTRA = ['same_fc_run_30s', 'fc_switches_30s']
EVENT = re.compile(r'^EVENT scenario=(\S+) number=(\d+) fc=(\d+) '
                   r'value=(\S+) time=(\S+)\s*$', re.M)
BENIGN_OLD = re.compile(r'^BENIGN FC(05|06).*?\btime=(\S+)', re.M)
USED = set()
HISTORY_CACHE = {}


def timeparse(value):
    d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if d.tzinfo is None:
        raise ValueError('타임존 없는 시각: ' + value)
    return d.astimezone(timezone.utc)


def iso(d):
    return d.isoformat(timespec='microseconds')


def json_request(path, data=None):
    payload = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(ES + path, data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST' if payload is not None else 'GET')
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError) as e:
        raise RuntimeError(f'Elasticsearch 접근 오류: {e}') from e


def find_window(fc, event_time):
    t = timeparse(event_time)
    q = {'size': 50, 'sort': [{'@timestamp': {'order': 'asc'}}],
         'query': {'range': {'@timestamp': {
             'gte': iso(t), 'lte': iso(t + timedelta(seconds=6))}}}}
    hits = json_request('/_search', q)['hits']['hits']
    matches = [h for h in hits
               if int(h['_source'].get('write_count', 0)) == 1
               and int(h['_source'].get(f'fc{fc:02d}_count', 0)) == 1]
    if len(matches) != 1:
        raise RuntimeError(f'FC{fc:02d} {event_time}: ES 단일 쓰기 구간이 '
                           f'{len(matches)}개입니다. 추측하지 않고 중단합니다.')
    identity = matches[0]['_id']
    if identity in USED:
        raise RuntimeError(f'서로 다른 이벤트가 같은 5초 구간에 대응: {identity}')
    USED.add(identity)
    return matches[0]


def base9(source):
    try:
        return [float(source[f]) for f in NAMES]
    except (ValueError, KeyError, TypeError) as e:
        raise RuntimeError(f'기존 9개 특징 누락: {e}') from e


def derive_history(hit):
    """For a selected 1-write window, derive order from prior saved windows.

    30-second lookback is relative to end-of-window @timestamp, consistent
    with the v5 ES representation (not precise packet timestamps).
    """
    key = hit['_id']
    if key in HISTORY_CACHE:
        return HISTORY_CACHE[key]
    src = hit['_source']
    if int(src.get('write_count', 0)) != 1:
        raise RuntimeError('대상 구간의 write_count가 1이 아닙니다: ' + key)
    current = timeparse(src['@timestamp'])
    start = current - timedelta(seconds=30)
    q = {'size': 100, 'track_total_hits': True,
         'sort': [{'@timestamp': {'order': 'asc'}}],
         'query': {'range': {'@timestamp': {
             'gte': iso(start), 'lte': iso(current)}}}}
    result = json_request('/_search', q)
    hits = result['hits']['hits']
    total = result['hits'].get('total', {})
    if isinstance(total, dict) and (total['relation'] != 'eq' or total['value'] > len(hits)):
        raise RuntimeError('30초 구간 검색 결과가 100개를 초과했습니다. 임의 생략 불가.')
    # If timestamp duplicates exist, an ordering cannot be guaranteed.
    writes = []
    for item in hits:
        r = item['_source']
        wc = int(r.get('write_count', 0))
        if wc == 0:
            continue
        if wc != 1:
            raise RuntimeError('30초 이력에 복수 쓰기 포함: '+ item['_id']
                               + ' — 5초 집계로 패킷 순서를 복원할 수 없음')
        a = int(r.get('fc05_count', 0))
        b = int(r.get('fc06_count', 0))
        if (a,b) not in ((1,0),(0,1)):
            raise RuntimeError('FC05/06 외 쓰기 또는 집계 불일치: '+item['_id'])
        writes.append((timeparse(r['@timestamp']), item['_id'], 5 if a else 6))
    writes.sort(key=lambda z:(z[0],z[1]))
    if not writes or writes[-1][1] != hit['_id']:
        raise RuntimeError('해당 구간이 30초 쓰기 이력의 마지막이 아닙니다: ' + key)
    if len(set(t for t, _, _ in writes)) != len(writes):
        raise RuntimeError('동일 시각 쓰기 문서가 중복됩니다. 순서 불명확.')
    fcs = [fc for _,_,fc in writes]
    same_run = 1
    for prev in reversed(fcs[:-1]):
        if prev != fcs[-1]:
            break
        same_run += 1
    switches = sum(a != b for a,b in zip(fcs, fcs[1:]))
    seq = [float(same_run), float(switches)]
    HISTORY_CACHE[key] = seq
    return seq


def extended(hit):
    x = base9(hit['_source'])
    if int(hit['_source'].get('write_count',0)) == 0:
        return x + [0., 0.]
    return x + derive_history(hit)


def event_logs(filename, expect, legacy=False):
    path = DATA_DIR / filename
    if not path.is_file():
        raise RuntimeError('학습 로그 누락: ' + str(path))
    text = path.read_text(errors='replace')
    if legacy:
        events = [(int(fc), t) for fc,t in BENIGN_OLD.findall(text)]
    else:
        if 'SESSION_END scenario=benign' not in text:
            raise RuntimeError('정상 실험 종료 기록 없음: ' + filename)
        events = [(int(fc), t) for scen,_,fc,_,t in EVENT.findall(text)
                  if scen == 'benign']
    if len(events) != expect:
        raise RuntimeError(f'{filename}: 정상 쓰기 {expect}개 예상, 실제 {len(events)}개')
    return [extended(find_window(fc,t)) for fc,t in events]


def evaluate(pack, mat):
    values = pack['model'].decision_function(mat).ravel()
    return values < float(pack['decision_threshold'])


def stats(actual, predicted):
    a = np.asarray(actual, dtype=bool)
    p = np.asarray(predicted, dtype=bool)
    tp = int(np.sum(a & p)); tn = int(np.sum(~a & ~p))
    fp = int(np.sum(~a & p)); fn = int(np.sum(a & ~p))
    precision = tp/(tp+fp) if tp+fp else None
    recall = tp/(tp+fn) if tp+fn else None
    accuracy = (tp+tn)/len(a)
    f1 = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
    return tp,tn,fp,fn,accuracy,precision,recall,f1


def pct(val):
    return 'N/A' if val is None else f'{val:.2%}'


def display(name, actual, prediction):
    s=stats(actual,prediction)
    print(f'{name:8} | {s[0]:2d} | {s[1]:2d} | {s[2]:2d} | {s[3]:2d} | '
          f'{pct(s[4]):>7} | {pct(s[5]):>7} | {pct(s[6]):>7} | {pct(s[7]):>7}')
    return s


def main():
    parser = argparse.ArgumentParser(description='Modbus 네트워크 순서 특징 v6e 학습 및 과거 실험 참고 비교')
    parser.add_argument('--fresh-json', type=Path,
        default=DATA_DIR/'ml-comparison.json',
        help='기존 24구간 비교 JSON. 실험을 다시 실행하지 않습니다.')
    args=parser.parse_args()
    if OUTPUT.exists():
        raise RuntimeError('기존 v6e 후보를 덮어쓰지 않습니다: ' + str(OUTPUT))
    if not BASE.is_file():
        raise RuntimeError('기준 v6c 모델 누락: ' + str(BASE))
    base = joblib.load(BASE)
    if list(base['features']) != NAMES:
        raise RuntimeError('v6c의 9개 입력 특징 순서가 예상과 다릅니다.')

    print('===== v6e 정상 데이터 구성 중 (읽기 전용) =====', flush=True)
    # Old 8 audit write rows omitted: their per-packet write order is not
    # recorded in the exported 9-feature CSV. Never impute false order.
    legacy = event_logs('eval-v6-new-benign.log', 8, True)
    normal_fast = event_logs('v6d-dev-benign-5s.log', 8)
    normal_slow = event_logs('v6d-dev-benign-10s.log', 8)
    patterns = [(5,5,5),(4,4,4),(4,5,4),(5,4,5),(4,5,5),(5,4,4)]
    reads = [[sum(p),*p,0.,0.,0.,0.,0.,0.,0.] for p in patterns]
    # Nine baseline values followed by exactly two new features.
    X_train=np.asarray(legacy + normal_fast + normal_slow + reads,dtype=float)
    if X_train.shape != (30,11):
        raise RuntimeError(f'학습 형상 오류 (30x11 예상): {X_train.shape}')
    # Both original and extended pipelines use the same nu/gamma here.
    model=make_pipeline(StandardScaler(), OneClassSVM(kernel='rbf',gamma=.03,nu=.05))
    model.fit(X_train)
    scores=model.decision_function(X_train).ravel()
    threshold=float(scores.min()-1e-6)
    candidate={
        'version':'v6e-11features-research-only',
        'model':model, 'features':NAMES+EXTRA, 'window_seconds':5,
        'decision_threshold':threshold, 'nu':0.05,'gamma':0.03,
        'training_normal_count':len(X_train),
        'training_unique_patterns':len(np.unique(X_train,axis=0)),
        'history_lookback_seconds':30,
        'feature_notes':{'same_fc_run_30s':'Trailing same-FC run ending in current single-write 5s window',
           'fc_switches_30s':'Number of FC05<->FC06 transitions across writes in prior 30 seconds including current window'},
        'limitations':'ES window-end timestamps approximate, not packet exact; ambiguous multiwrite windows rejected. No v6e live pipeline yet.',
    }
    print(f'정상 학습: {len(X_train)}구간 / 고유 특징: {candidate["training_unique_patterns"]}개')
    print('특징: 9개 기존 + 2개 순서 특징, 임계값:',threshold)
    print('  - 쓰기 연속 길이: 마지막 FC가 연속으로 등장한 횟수(30초 이내)')
    print('  - FC 전환 횟수: 최근 30초 쓰기들 간 FC05↔FC06 변화 횟수')
    print('  - 원본 audit의 정상 8개는 정확한 쓰기 순서 정보 부재로 학습에서 제외')

    # Validate, but do not tune using the already inspected 24 rows.
    source=args.fresh_json.expanduser().resolve()
    if not source.is_file():
        raise RuntimeError('비교 JSON 파일 누락: '+str(source))
    comp=json.loads(source.read_text())
    rows=comp['events']
    if len(rows)!=24 or sum(bool(r['attack']) for r in rows)!=8:
        raise RuntimeError('참고 비교 JSON의 건수/라벨이 예상과 다릅니다.')
    X_base=[]; X_new=[]; labels=[]; detail=[]
    for r in rows:
        identity=r['es_document_id']
        hit=json_request('/_doc/'+identity)
        if not hit.get('found', False):
            raise RuntimeError('ES 문서가 삭제됨: '+identity)
        src=hit['_source']
        if any(abs(a-b)>1e-8 for a,b in zip(base9(src), [float(r['features'][k]) for k in NAMES])):
            raise RuntimeError('비교 JSON과 ES 저장 특징 불일치: '+identity)
        if src['@timestamp'] != r['es_timestamp']:
            raise RuntimeError('비교 JSON과 ES 시각 불일치: '+identity)
        h={'_id':identity,'_source':src}
        X_base.append(base9(src)); X_new.append(extended(h))
        labels.append(bool(r['attack']))
        detail.append(r)
    a=np.asarray(X_base,dtype=float)
    b=np.asarray(X_new,dtype=float)
    print('\n===== 이미 확인한 24개 개발 구간 참고 비교 (독립 테스트 아님) =====')
    print('모델     | TP | TN | FP | FN | 정확도   | 정밀도   | 재현율   | F1')
    base_pred=evaluate(base,a)
    new_pred=evaluate(candidate,b)
    display('v6c',labels,base_pred)
    display('v6e',labels,new_pred)
    print('\n===== v6e 오분류 상세 =====')
    mistakes=0
    for r,real,pred,x in zip(detail,labels,new_pred,b):
        if real!=bool(pred):
            mistakes+=1
            typ='미탐(FN)' if real else '오탐(FP)'
            print(f'{typ} | {r["scenario"]} #{r["event_number"]} '
                  f'FC{r["fc"]:02d} | run={x[-2]:.0f} switches={x[-1]:.0f}')
    if mistakes==0:
        print('이 24개 구간에서 오분류 없음 (독립 테스트 성능을 의미하지 않음)')
    print('\n===== 학습 구간에서 실제 순서 특징의 범위 =====')
    print('연속 길이:',sorted(set(int(z) for z in X_train[:,-2])))
    print('전환 횟수:',sorted(set(int(z) for z in X_train[:,-1])))
    joblib.dump(candidate,OUTPUT)
    print('\n저장:',OUTPUT)
    print('운영 v5 / start-demo.sh / v6c 모델은 변경하지 않았습니다.')
    print('주의: 기존 24개는 이미 여러 차례 분석된 개발 데이터입니다.')
    print('v6e는 아직 실시간 파이프라인에 연결되지 않았습니다.')


if __name__=='__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, IndexError) as ex:
        raise SystemExit('v6e 중단: '+str(ex)) from ex
