import os
import argparse
import queue
import sys
import threading
import time

from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from elasticsearch import Elasticsearch

BASE = Path(__file__).resolve().parent
MODEL_PATH = BASE / "detector-modbus-v5-candidate.joblib"
ES_INDEX = "anomaly-modbus-v5"

FEATURES = [
    "request_count",
    "fc01_count",
    "fc02_count",
    "fc03_count",
    "write_count"
]

parser = argparse.ArgumentParser()
parser.add_argument(
    "--replay",
    action="store_true",
    help="PCAP 재생 모드: 실제 현재 시각으로 구간을 닫지 않음"
)
parser.add_argument(
    "--grace",
    type=float,
    default=1.0,
    help="실시간 구간 종료 후 추가 대기 초"
)
args = parser.parse_args()

if args.grace < 0:
    parser.error("--grace는 0 이상이어야 합니다.")

saved = joblib.load(MODEL_PATH)

if saved["features"] != FEATURES:
    raise RuntimeError("모델과 입력 특징 순서가 일치하지 않습니다.")

model = saved["model"]
window_size = int(saved["window_seconds"])

es = Elasticsearch([os.environ.get("ES_URL", "http://127.0.0.1:9200")])
events = queue.Queue()

start_time = None
current_window = 0
codes = []
write_history = {5: deque(), 6: deque()}



def detect(window_id, function_codes):
    counts = Counter(function_codes)

    features = [
        len(function_codes),
        counts[1],
        counts[2],
        counts[3],
        sum(counts[fc] for fc in (5, 6, 15, 16))
    ]

    X = np.array([features], dtype=float)
    score = float(model.decision_function(X)[0])

    threshold = float(saved["decision_threshold"])
    ml_alert = score < threshold

    window_end = start_time + (window_id + 1) * window_size

    rolling = {}
    triggered_codes = []

    for fc in (5, 6):
        history = write_history[fc]

        while history and window_end - history[0][0] >= 30:
            history.popleft()

        if counts[fc] > 0:
            history.append((window_end, counts[fc]))

        total = sum(n for _, n in history)
        rolling[fc] = total

        if counts[fc] > 0 and total >= 3:
            triggered_codes.append(fc)

    policy_alert = bool(triggered_codes)
    is_anomaly = ml_alert or policy_alert

    status = "anomaly" if is_anomaly else "normal"

    if ml_alert and policy_alert:
        detection_source = "ML+POLICY"
    elif ml_alert:
        detection_source = "ML"
    elif policy_alert:
        detection_source = "POLICY"
    else:
        detection_source = "NONE"

    timestamp = datetime.fromtimestamp(
        window_end, tz=timezone.utc
    ).isoformat(timespec="milliseconds")

    doc = {
        "@timestamp": timestamp,
        "pred": status,
        "is_anomaly": is_anomaly,
        "anomaly_score": score,
        "request_count": features[0],
        "fc01_count": counts[1],
        "fc02_count": counts[2],
        "fc03_count": counts[3],
        "fc05_count": counts[5],
        "fc06_count": counts[6],
        "write_count": features[4],
        "window_seconds": window_size,
        "model": "One-Class SVM + Rolling Policy",
        "model_version": "v5-hybrid-candidate",
        "source": "modbus-network-ml",
        "ml_is_anomaly": ml_alert,
        "policy_is_anomaly": policy_alert,
        "detection_source": detection_source,
        "fc05_30s_count": rolling[5],
        "fc06_30s_count": rolling[6],
        "policy_window_seconds": 30,
        "policy_threshold": 3,
        "ml_decision_threshold": threshold
    }

    print(
        f"Window {window_id:03d} | "
        f"Requests={features[0]:3d} | "
        f"Writes={features[4]:3d} | "
        f"Score={score:.5f} | "
        f"{status.upper()} | "
        f"Source={detection_source}",
        flush=True
    )

    try:
        result = es.index(index=ES_INDEX, body=doc)
        print(f"ES saved: {result['_id']}", flush=True)
    except Exception as exc:
        print(f"ES error: {exc}", file=sys.stderr, flush=True)


def read_input():
    for line in sys.stdin:
        parts = line.strip().split("\t")

        if len(parts) != 2:
            continue

        try:
            timestamp = float(parts[0])
            fc = int(parts[1])
        except ValueError:
            continue

        events.put((timestamp, fc))

    events.put(None)


threading.Thread(target=read_input, daemon=True).start()

mode = "REPLAY" if args.replay else "LIVE"
print(f"Modbus ML v5 hybrid started. mode={mode}", flush=True)

try:
    while True:
        timeout = None

        if not args.replay and start_time is not None:
            deadline = (
                start_time
                + (current_window + 1) * window_size
                + args.grace
            )
            timeout = max(0.0, deadline - time.time())

        try:
            item = events.get(timeout=timeout)
        except queue.Empty:
            # 실시간 모드: 구간이 끝났으면 패킷이 없어도 처리
            if codes:
                detect(current_window, codes)
                codes = []

            current_window += 1
            continue

        if item is None:
            # EOF: 재생 파일의 마지막 미완료 구간은 제외
            if codes:
                deadline = (
                    start_time
                    + (current_window + 1) * window_size
                    + args.grace
                )

                if not args.replay and time.time() >= deadline:
                    detect(current_window, codes)
                else:
                    print(
                        f"Last window {current_window} skipped "
                        "(completion not verified)",
                        flush=True
                    )
            break

        timestamp, fc = item

        if start_time is None:
            start_time = timestamp

        window_id = int((timestamp - start_time) // window_size)

        if window_id < current_window:
            print(
                f"Late packet skipped: window={window_id}",
                flush=True
            )
            continue

        # 중간에 비어 있는 구간이 있으면 데이터 없이 통과
        while current_window < window_id:
            if codes:
                detect(current_window, codes)
                codes = []

            current_window += 1

        codes.append(fc)

except KeyboardInterrupt:
    print("Modbus ML v3 interrupted.", flush=True)
