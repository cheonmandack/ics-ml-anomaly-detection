#!/usr/bin/env python3
"""Import offline network-ML result CSVs into Elasticsearch 7.x.

Uses only Python standard library. Safe to rerun: a stable Elasticsearch _id
is calculated for every (experiment, window, src/dst, model) feature row.
"""
import argparse
import csv
import hashlib
import ipaddress
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

INDEX_DEFAULT = "network-ml-anomaly"
INTEGER_FIELDS = (
    "window_seconds", "feature_version", "packet_count", "byte_count",
    "unique_dst_ports", "unique_src_ports", "tcp_packets", "udp_packets",
    "icmp_packets", "other_ip_packets", "tcp_syn_packets",
    "tcp_syn_no_ack_packets", "tcp_rst_packets", "icmp_echo_requests",
    "icmp_echo_replies",
)
FLOAT_FIELDS = (
    "packets_per_second", "bytes_per_second", "mean_packet_bytes",
    "std_packet_bytes", "mean_interarrival_ms", "anomaly_score",
)
IP_FIELDS = ("scada_ip", "src_ip", "dest_ip")
KEY_FIELDS = (
    "experiment_id", "@timestamp", "src_ip", "dest_ip",
    "window_seconds", "feature_version", "model_name",
)
MAPPING_PROPERTIES = {
    "@timestamp": {"type": "date"},
    "ingested_at": {"type": "date"},
    "model_trained_at": {"type": "date"},
    "experiment_id": {"type": "keyword"},
    "scenario": {"type": "keyword"},
    "model_name": {"type": "keyword"},
    "pred": {"type": "keyword"},
    "is_anomaly": {"type": "boolean"},
    "data_source": {"type": "keyword"},
}
MAPPING_PROPERTIES.update({f: {"type": "ip"} for f in IP_FIELDS})
MAPPING_PROPERTIES.update({f: {"type": "integer"} for f in INTEGER_FIELDS})
MAPPING_PROPERTIES.update({f: {"type": "float"} for f in FLOAT_FIELDS})


def es_request(base, method, path, body=None, content_type="application/json"):
    url = base.rstrip("/") + path
    raw = None if body is None else (body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    req = Request(url, data=raw, method=method, headers={"Content-Type": content_type})
    try:
        with urlopen(req, timeout=30) as resp:
            data = resp.read()
            return resp.status, json.loads(data) if data else {}
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            return 404, {}
        raise RuntimeError(f"Elasticsearch HTTP {exc.code} ({method} {path}): {payload[:1200]}") from exc
    except URLError as exc:
        raise RuntimeError(f"Elasticsearch 연결 실패 ({url}): {exc}") from exc


def prepare_index(base, index):
    path = "/" + quote(index, safe="")
    status, result = es_request(base, "GET", path + "/_mapping")
    if status == 404:
        es_request(base, "PUT", path, {"mappings": {"properties": MAPPING_PROPERTIES}})
        print(f"[CREATE] 인덱스 생성: {index}")
        return
    existing = result.get(index, {}).get("mappings", {}).get("properties", {})
    for name, required in MAPPING_PROPERTIES.items():
        actual = existing.get(name, {}).get("type")
        if actual != required["type"]:
            raise RuntimeError(
                f"기존 인덱스 {index!r}의 {name!r} 매핑은 {actual!r}입니다. "
                f"기대한 매핑: {required['type']!r}. 안전을 위해 가져오기를 중단합니다."
            )
    print(f"[EXISTS] 기존 인덱스 매핑 확인: {index}")


def to_document(row, source_file):
    for key in KEY_FIELDS + ("pred", "anomaly_score"):
        if not row.get(key):
            raise ValueError(f"{source_file}: 필수 필드 누락 또는 공백: {key}")
    if row["pred"] not in ("normal", "anomaly"):
        raise ValueError(f"{source_file}: pred 값 확인 필요: {row['pred']!r}")
    doc = dict(row)
    for field in INTEGER_FIELDS:
        value = (doc.get(field) or "").strip()
        doc[field] = int(value) if value else None
    for field in FLOAT_FIELDS:
        value = (doc.get(field) or "").strip()
        number = float(value) if value else None
        doc[field] = number if number is not None and math.isfinite(number) else None
    for field in IP_FIELDS:
        value = (doc.get(field) or "").strip()
        if value:
            ipaddress.ip_address(value)
        doc[field] = value or None
    # Check date strings early rather than partially failing an ES bulk request.
    for field in ("@timestamp", "model_trained_at"):
        value = (doc.get(field) or "").strip()
        if value:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        doc[field] = value or None
    if doc["anomaly_score"] is None:
        raise ValueError(f"{source_file}: 유효한 anomaly_score 값이 필요합니다")
    doc["is_anomaly"] = doc["pred"] == "anomaly"
    doc["data_source"] = "network_ml"
    doc["ingested_at"] = datetime.now(timezone.utc).isoformat()
    identifier = "\x1f".join(str(row.get(k, "")) for k in KEY_FIELDS)
    stable_id = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    return stable_id, doc


def read_files(paths):
    documents = {}
    for filename in paths:
        path = Path(filename)
        if not path.is_file():
            raise FileNotFoundError(f"CSV 파일이 없습니다: {path}")
        counter = 0
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            for row_num, row in enumerate(reader, start=2):
                try:
                    identifier, doc = to_document(row, str(path))
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{path}:{row_num}: {exc}") from exc
                if identifier in documents:
                    raise ValueError(f"중복된 특징 행 식별자 발견: {path}:{row_num}")
                documents[identifier] = doc
                counter += 1
        print(f"[READ] {path}: {counter}행")
    return documents


def main():
    parser = argparse.ArgumentParser(description="네트워크 ML CSV를 Elasticsearch 7.x로 저장")
    parser.add_argument("files", nargs="+", help="입력 CSV (여러 파일 가능)")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch 주소")
    parser.add_argument("--index", default=INDEX_DEFAULT, help="저장 인덱스")
    args = parser.parse_args()
    if not args.index or args.index[0] in "-_." or args.index.lower() != args.index:
        parser.error("인덱스 이름은 소문자로 시작하는 유효한 Elasticsearch 이름이어야 합니다")
    docs = read_files(args.files)  # Validate all rows *before* modifying ES.
    if not docs:
        print("입력 행이 없습니다. 종료합니다.")
        return
    prepare_index(args.es, args.index)
    lines = []
    for doc_id, doc in docs.items():
        lines.append(json.dumps({"index": {"_index": args.index, "_id": doc_id}}, separators=(",", ":")))
        lines.append(json.dumps(doc, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    status, result = es_request(args.es, "POST", "/_bulk?refresh=wait_for", payload, "application/x-ndjson")
    if result.get("errors"):
        problems = []
        for item in result.get("items", []):
            action = item.get("index", {})
            if action.get("error"):
                problems.append(str(action["error"])[:350])
            if len(problems) >= 3:
                break
        raise RuntimeError(f"Bulk 요청에서 일부 저장 실패: {' | '.join(problems)}")
    anomalies = sum(doc["is_anomaly"] for doc in docs.values())
    print(f"[OK] 저장 성공: {len(docs)}개 특징 행 (이상: {anomalies}, 정상: {len(docs) - anomalies})")
    print(f"     index={args.index}, HTTP={status}; 동일 명령 재실행 시 같은 _id로 갱신됩니다.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
