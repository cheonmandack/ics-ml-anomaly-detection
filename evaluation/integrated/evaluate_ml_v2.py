#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-session ICS ML evaluation (Elasticsearch 7.x, Python standard library).

This script DOES NOT generate attacks or modify PLC state.
It marks a single experiment's phase boundaries and evaluates stored ML decisions.
"""

import argparse
import hashlib
import csv
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PHASES = {
    "normal": {"label": "정상 운전", "models": ["network", "plc", "modbus"], "kind": "normal"},
    "icmp_flood": {"label": "ICMP Flood", "models": ["network"], "kind": "attack"},
    "port_scan": {"label": "TCP Port Scan", "models": ["network"], "kind": "attack"},
    "plc_level": {"label": "PLC 수위값 변조", "models": ["plc"], "kind": "attack"},
    "fc05": {"label": "FC05 코일값 변조", "models": ["modbus"], "kind": "attack"},
    "unauthorized_modbus": {"label": "비인가 Modbus 접근", "models": ["modbus"], "kind": "attack"},
}
MODELS = {
    "network": {"index": "network-ml-anomaly-v2", "field": "is_anomaly"},
    "plc": {"index": "anomaly-plc3", "field": "pred"},
    "modbus": {"index": "anomaly-modbus", "field": "is_anomaly"},
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def atomic_write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
        temp = f.name
    os.replace(temp, path)


def load_session(path):
    if not path.is_file():
        raise ValueError(f"세션 파일이 없습니다: {path}. 먼저 init 명령을 실행하세요.")
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("phases"), list):
        raise ValueError("세션 JSON 형식이 올바르지 않습니다")
    return data


class ESError(Exception):
    pass


class ES:
    def __init__(self, base, timeout):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def request(self, method, path, data=None):
        body = None if data is None else json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:600]
            raise ESError(f"Elasticsearch HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ESError(f"Elasticsearch 연결 실패: {exc.reason}") from exc

    def documents(self, index, start, end, src_ip=None, target_ip=None):
        filters = [{"range": {"@timestamp": {"gte": start, "lt": end}}}]
        if src_ip:
            filters.append({"term": {"src_ip": src_ip}})
        if target_ip:
            filters.append({"term": {"dest_ip": target_ip}})
        query = {"size": 500, "sort": ["_doc"], "_source": [
            "@timestamp", "pred", "is_anomaly", "src_ip", "dest_ip",
            "protocol", "packet_count", "packets_per_second", "icmp_packets",
            "icmp_echo_requests", "icmp_echo_replies", "unique_dst_ports",
            "tcp_syn_packets", "anomaly_score", "function_code",
            "modbus_function", "value", "result", "sensor_value", "level"
        ], "query": {"bool": {"filter": filters}}}
        safe_index = urllib.parse.quote(index, safe="*-_")
        sid = None
        try:
            response = self.request("POST", f"/{safe_index}/_search?scroll=1m", query)
            while True:
                sid = response.get("_scroll_id", sid)
                hits = response.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for hit in hits:
                    # Keep Elasticsearch identity outside of the original event fields.
                    doc = dict(hit.get("_source", {}))
                    doc["_es_id"] = hit.get("_id", "")
                    doc["_es_index"] = hit.get("_index", index)
                    yield doc
                if not sid:
                    raise ESError("Elasticsearch 응답에 scroll ID가 없습니다")
                response = self.request("POST", "/_search/scroll", {"scroll": "1m", "scroll_id": sid})
        finally:
            if sid:
                try:
                    self.request("DELETE", "/_search/scroll", {"scroll_id": [sid]})
                except ESError:
                    pass


def classify(doc, model):
    """Return anomaly/normal/unknown. Conflicting verdicts are unknown."""
    verdicts = []
    if isinstance(doc.get("is_anomaly"), bool):
        verdicts.append("anomaly" if doc["is_anomaly"] else "normal")
    pred = doc.get("pred")
    if isinstance(pred, str) and pred.strip().lower() in ("normal", "anomaly"):
        verdicts.append(pred.strip().lower())
    if not verdicts or len(set(verdicts)) != 1:
        return "unknown"
    return verdicts[0]


REVIEW_FIELDS = [
    "row_id", "phase", "model", "index", "es_id", "timestamp_utc",
    "src_ip", "dest_ip", "protocol", "packet_count", "packets_per_second",
    "icmp_packets", "icmp_echo_requests", "unique_dst_ports", "tcp_syn_packets",
    "anomaly_score", "function_code", "modbus_function", "value", "result",
    "sensor_value", "level", "predicted", "suggested_truth", "true_label", "notes"
]


def review_row(doc, phase, model, index, verdict):
    identity = f"{phase['name']}|{model}|{index}|{doc.get('_es_id', '')}"
    row_id = hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]
    # This is a REVIEW HINT, NOT a ground-truth label. Users must verify each row.
    hint = "normal" if PHASES[phase['name']]["kind"] == "normal" else "review_attack"
    if hint == "review_attack" and model == "network" and phase.get("src_ip") and phase.get("target_ip"):
        hint = "attack_candidate_check_traffic"
    row = {key: "" for key in REVIEW_FIELDS}
    row.update({
        "row_id": row_id, "phase": phase["name"], "model": model, "index": index,
        "es_id": doc.get("_es_id", ""), "timestamp_utc": doc.get("@timestamp", ""),
        "predicted": verdict, "suggested_truth": hint,
    })
    for key in REVIEW_FIELDS:
        if key in doc:
            value = doc[key]
            row[key] = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
    return row


def evaluate_phase(es, phase, review_rows=None):
    config = PHASES[phase["name"]]
    results = []
    for model in config["models"]:
        index = MODELS[model]["index"]
        tally = {"total": 0, "anomaly": 0, "normal": 0, "unknown": 0}
        first = None
        error = ""
        # IP filtering only for network traffic: PLC and Modbus schemas may lack IP fields.
        src = phase.get("src_ip") if model == "network" else None
        dst = phase.get("target_ip") if model == "network" else None
        try:
            for doc in es.documents(index, phase["start"], phase["end"], src, dst):
                label = classify(doc, model)
                if review_rows is not None:
                    review_rows.append(review_row(doc, phase, model, index, label))
                tally["total"] += 1
                tally[label] += 1
                if label == "anomaly":
                    t = doc.get("@timestamp")
                    if isinstance(t, str):
                        try:
                            dt = parse_time(t)
                            first = dt if first is None or dt < first else first
                        except ValueError:
                            pass
        except ESError as exc:
            error = str(exc)
        known = tally["normal"] + tally["anomaly"]
        if error:
            status = "ERROR"
        elif tally["total"] == 0:
            status = "NO_DATA"
        elif known == 0:
            status = "UNKNOWN_LABEL"
        elif config["kind"] == "normal":
            status = "MEASURED"
        elif tally["anomaly"]:
            status = "DETECTED"
        elif tally["unknown"]:
            status = "INCONCLUSIVE"
        else:
            status = "NOT_DETECTED"
        delay = round((first - parse_time(phase["start"])).total_seconds(), 3) if first else None
        results.append({
            "phase": phase["name"], "phase_label": config["label"], "kind": config["kind"],
            "model": model, "index": index, "start_utc": phase["start"], "end_utc": phase["end"],
            "src_ip_filter": src or "", "target_ip_filter": dst or "", **tally,
            "known": known, "anomaly_pct_of_known": round(100 * tally["anomaly"] / known, 2) if known else None,
            "first_anomaly_utc": first.isoformat().replace("+00:00", "Z") if first else "",
            "log_timestamp_delta_sec": delay, "status": status, "error": error,
        })
    return results


def csv_write(path, records, fields):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def render_report(session, results):
    lines = [
        "# 산업제어시스템 ML 단일 통합 실험 평가 결과", "",
        f"- 세션 생성(UTC): {session['created_utc']}",
        "- 실험 구간 시작/종료 시각은 SCADA 평가 스크립트의 UTC 시각을 사용함", "- 평가 단위: Elasticsearch의 모델별 판정 문서(패킷 개수와 다름)", "",
        "## 정상 구간: 문서 단위 오탐 비율", "",
        "| 모델 | 전체 | 정상 | 이상 | 판정 불명 | 오탐 비율(판정 가능 문서 기준) | 상태 |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    normal_rows = [r for r in results if r["kind"] == "normal"]
    for r in normal_rows:
        pct = f"{r['anomaly_pct_of_known']:.2f}%" if r["anomaly_pct_of_known"] is not None else "N/A"
        lines.append(f"| {r['model']} | {r['total']} | {r['normal']} | {r['anomaly']} | {r['unknown']} | {pct} | {r['status']} |")
    lines += ["", "## 공격 구간: 시나리오별 검출 여부", "",
              "| 시나리오 | 모델 | 분석 문서 | 이상 문서 | 최초 이상 시각(UTC) | 시각 차(초) | 판정 |",
              "|---|---|---:|---:|---|---:|---|"]
    attack_rows = [r for r in results if r["kind"] == "attack"]
    for r in attack_rows:
        delay = str(r["log_timestamp_delta_sec"]) if r["log_timestamp_delta_sec"] is not None else "N/A"
        lines.append(f"| {r['phase_label']} | {r['model']} | {r['total']} | {r['anomaly']} | {r['first_anomaly_utc'] or 'N/A'} | {delay} | {r['status']} |")
    valid = [r for r in attack_rows if r["status"] in ("DETECTED", "NOT_DETECTED")]
    detected = sum(r["status"] == "DETECTED" for r in valid)
    lines += ["", f"- 평가 가능한 공격 구간: {len(valid)}개 / 전체 {len(attack_rows)}개",
              f"- 검출된 공격 구간: {detected}개",
              f"- 단일 실험 시나리오 검출 비율: {detected}/{len(valid)} = {100 * detected / len(valid):.2f}%" if valid else "- 시나리오 검출 비율: 산출 불가", "",
              "## 해석 시 주의 사항", "",
              "1. 공격 구간에는 정상 트래픽이 섞일 수 있으므로 해당 구간의 '이상 문서 비율'을 재현율(Recall)로 해석하면 안 됨.",
              "2. 공격 구간의 이상 문서가 해당 공격 때문이라고 단정할 수 없음. 해당 모듈의 기존 트래픽을 구분하고 Kibana 로그로 확인해야 함.",
              "3. 공격 출발지/목적지 IP 필터는 네트워크 ML에만 적용됨. IP 필터 없는 구간에는 배경 트래픽이 포함될 수 있음.",
              "4. '시각 차'는 이벤트 @timestamp와 실험 시작 표식의 차이로, 실제 탐지·저장·대시보드 지연을 의미하지 않음.",
              "5. 모델이 분석 창 시작 시각을 @timestamp로 사용하면 시각 차가 음수가 될 수 있으며, 이 경우 탐지 지연은 별도 계측해야 함.",
              "6. NO_DATA, UNKNOWN_LABEL, INCONCLUSIVE, ERROR는 정상/탐지 실패로 간주하지 않음.",
              "7. 단일 실험은 기능 검증이며, 통계적 의미의 일반화된 탐지율이나 F1 점수를 산출할 근거는 아님.", ""]
    for r in results:
        if r["error"]:
            lines.append(f"- 오류: {r['phase']}/{r['model']}: {r['error']}")
    return "\n".join(lines)



def safe_div(num, den):
    return round(num / den, 6) if den else None


def performance(counts):
    tp, tn, fp, fn = (counts[k] for k in ("TP", "TN", "FP", "FN"))
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        **counts,
        "total_labeled": tp + tn + fp + fn,
        "accuracy": safe_div(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "f1_score": safe_div(2 * tp, 2 * tp + fp + fn),
        "fpr": safe_div(fp, fp + tn),
    }


def compute_metrics(label_file):
    if not label_file.is_file():
        raise ValueError(f"레이블 CSV가 없습니다: {label_file}")
    with label_file.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError("레이블 CSV에 분석 문서가 없습니다")
    if not {"row_id", "model", "phase", "true_label", "predicted"}.issubset(rows[0]):
        raise ValueError("필수 열(row_id, model, phase, true_label, predicted)이 없습니다")
    seen = set()
    counts = {}
    excluded = {"unlabeled": 0, "excluded_by_reviewer": 0, "prediction_unknown": 0}
    reviewed = 0
    used = 0
    for line, r in enumerate(rows, 2):
        row_id = r["row_id"].strip()
        if not row_id or row_id in seen:
            raise ValueError(f"행 {line}: row_id 누락 또는 중복")
        seen.add(row_id)
        truth = (r.get("true_label") or "").strip().lower()
        pred = (r.get("predicted") or "").strip().lower()
        if truth not in ("normal", "attack", "exclude", ""):
            raise ValueError(f"행 {line}: true_label은 normal/attack/exclude/빈칸 중 하나여야 합니다")
        if pred not in ("normal", "anomaly", "unknown"):
            raise ValueError(f"행 {line}: predicted 값이 올바르지 않습니다: {pred}")
        if not truth:
            excluded["unlabeled"] += 1
            continue
        reviewed += 1
        if truth == "exclude":
            excluded["excluded_by_reviewer"] += 1
            continue
        if pred == "unknown":
            excluded["prediction_unknown"] += 1
            continue
        used += 1
        kind = ("TP" if pred == "anomaly" else "FN") if truth == "attack" else ("FP" if pred == "anomaly" else "TN")
        for group_type, group_name in (("model", r["model"]), ("phase", r["phase"])):
            key = (group_type, group_name)
            counter = counts.setdefault(key, {k: 0 for k in ("TP", "TN", "FP", "FN")})
            counter[kind] += 1
    if not reviewed:
        raise ValueError("검토된 정답 레이블이 없습니다. label_review.csv의 true_label을 입력하세요")
    if not used:
        raise ValueError("성능 지표에 사용할 수 있는 정답+예측 쌍이 없습니다")
    metrics = []
    for (group_type, name), counter in sorted(counts.items()):
        metrics.append({"group_type": group_type, "group": name, **performance(counter)})
    return metrics, {"rows": len(rows), "reviewed": reviewed, "used": used, **excluded}


def render_metrics_report(metrics, coverage):
    def pct(value):
        return "N/A" if value is None else f"{value * 100:.2f}%"
    lines = [
        "# ICS 머신러닝 정답 레이블 기반 성능평가", "",
        "- 단위: 사람이 근거를 검토해 정답을 부여한 **모델 판정 문서(특징행)**",
        "- 한 세션에서 수집한 문서는 서로 독립 표본이 아닐 수 있으며 일반화 성능을 의미하지 않음", "",
        f"- CSV 전체 행: {coverage['rows']}",
        f"- 정답 검토 완료: {coverage['reviewed']}",
        f"- 성능 계산 포함: {coverage['used']}",
        f"- 미기입: {coverage['unlabeled']}; 검토 제외: {coverage['excluded_by_reviewer']}; 판정 불명: {coverage['prediction_unknown']}",
        "", "## 모델별 혼동행렬과 성능", "",
        "| 모델 | TP | TN | FP | FN | 정확도 | 정밀도 | 재현율 | F1 | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in metrics:
        if r["group_type"] != "model":
            continue
        lines.append("| " + " | ".join([
            r["group"], *(str(r[k]) for k in ("TP", "TN", "FP", "FN")),
            *(pct(r[k]) for k in ("accuracy", "precision", "recall", "f1_score", "fpr"))
        ]) + " |")
    lines += ["", "## 시나리오별 문서 판정 성능 (보조 자료)", "",
              "| 구간 | TP | TN | FP | FN | 정확도 | 정밀도 | 재현율 | F1 |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in metrics:
        if r["group_type"] != "phase":
            continue
        lines.append("| " + " | ".join([
            r["group"], *(str(r[k]) for k in ("TP", "TN", "FP", "FN")),
            *(pct(r[k]) for k in ("accuracy", "precision", "recall", "f1_score"))
        ]) + " |")
    lines += ["", "## 평가 해석 시 필수 확인", "",
              "1. true_label은 예측 결과를 보고 정하지 말고, 공격 로그·IP/포트·PLC 상태 등 **독립적인 근거**로 확인할 것.",
              "2. 공격 시간대 전체를 공격으로 자동 레이블링하지 말 것. 정상 트래픽이 섞일 수 있음.",
              "3. 공격 구간과 정상 구간 각각 최소 하나의 정답 레이블이 있어야 주요 지표가 의미 있음. 분모가 0이면 N/A 처리함.",
              "4. 모델마다 서로 다른 문서 단위이므로 모델 간 TP/TN을 합쳐 전체 정확도를 주장하지 않음.",
              "5. 짧은 단일 세션의 행 단위 성능이지, 독립 실험에서의 공격 탐지 성공률이나 실환경 일반화 성능이 아님.",
              "6. 정답을 확인할 수 없는 문서는 exclude로 표시하고 판단 근거를 notes에 기록할 것.", ""]
    return "\n".join(lines)

def main():
    p = argparse.ArgumentParser(description="SCADA/PLC ML 단일 세션 평가 및 시간 표식")
    p.add_argument("--session", default="evaluation_session.json", help="실험 세션 JSON 경로")
    sub = p.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("init", help="실험 세션 초기화")
    x.add_argument("--force", action="store_true", help="기존 세션 덮어쓰기")
    x = sub.add_parser("begin", help="실험 구간 시작")
    x.add_argument("phase", choices=PHASES.keys())
    x.add_argument("--src-ip", help="네트워크 공격 출발지 IP 필터")
    x.add_argument("--target-ip", help="네트워크 공격 목적지 IP 필터")
    sub.add_parser("end", help="현재 구간 종료")
    sub.add_parser("status", help="현재 기록된 실험 상태")
    x = sub.add_parser("report", help="Elasticsearch 조회 후 CSV/Markdown 결과 작성")
    x.add_argument("--es", default="http://localhost:9200")
    x.add_argument("--output", default="evaluation_result")
    x.add_argument("--timeout", type=int, default=15)
    x = sub.add_parser("metrics", help="검토한 label_review.csv로 혼동행렬·정확도·F1 계산")
    x.add_argument("--labels", default="evaluation_result/label_review.csv")
    x.add_argument("--output", default="evaluation_result")
    a = p.parse_args()
    path = Path(a.session)
    try:
        if a.cmd == "init":
            if path.exists() and not a.force:
                p.error(f"이미 세션 파일이 있습니다: {path} (--force는 기존 실험 기록을 삭제합니다)")
            atomic_write_json(path, {"created_utc": utc_now(), "phases": []})
            print(f"[INIT] 세션 생성: {path}")
            return 0
        if a.cmd == "metrics":
            metrics, coverage = compute_metrics(Path(a.labels))
            out = Path(a.output)
            out.mkdir(parents=True, exist_ok=True)
            fields = ["group_type", "group", "TP", "TN", "FP", "FN", "total_labeled",
                      "accuracy", "precision", "recall", "f1_score", "fpr"]
            csv_write(out / "metrics_results.csv", metrics, fields)
            atomic_write_json(out / "metrics_results.json", {"coverage": coverage, "metrics": metrics})
            (out / "metrics_report.md").write_text(render_metrics_report(metrics, coverage), encoding="utf-8")
            print(f"[DONE] {out / 'metrics_results.csv'}")
            print(f"[DONE] {out / 'metrics_report.md'}")
            print(f"[COVERAGE] 전체 {coverage['rows']} / 정답 검토 {coverage['reviewed']} / 평가 포함 {coverage['used']}")
            for r in metrics:
                if r["group_type"] == "model":
                    print(f"  {r['group']:10s} TP={r['TP']} TN={r['TN']} FP={r['FP']} FN={r['FN']} "
                          f"Accuracy={r['accuracy'] if r['accuracy'] is not None else 'N/A'} "
                          f"F1={r['f1_score'] if r['f1_score'] is not None else 'N/A'}")
            return 0
        data = load_session(path)
        unfinished = [s for s in data["phases"] if "end" not in s]
        if a.cmd == "begin":
            if unfinished:
                raise ValueError(f"진행 중인 구간이 있습니다: {unfinished[-1]['name']} (end 먼저 실행)")
            if any(s["name"] == a.phase for s in data["phases"]):
                raise ValueError(f"이미 기록된 구간입니다: {a.phase} (한 세션에서 구간별 1회만 허용)")
            if (a.src_ip or a.target_ip) and "network" not in PHASES[a.phase]["models"]:
                raise ValueError("IP 필터는 network 모델 대상 구간에서만 사용할 수 있습니다")
            item = {"name": a.phase, "start": utc_now()}
            if a.src_ip:
                item["src_ip"] = a.src_ip
            if a.target_ip:
                item["target_ip"] = a.target_ip
            data["phases"].append(item)
            atomic_write_json(path, data)
            print(f"[BEGIN] {PHASES[a.phase]['label']} | UTC {item['start']}")
            return 0
        if a.cmd == "end":
            if not unfinished:
                raise ValueError("진행 중인 구간이 없습니다")
            item = unfinished[-1]
            item["end"] = utc_now()
            atomic_write_json(path, data)
            print(f"[END] {PHASES[item['name']]['label']} | UTC {item['end']}")
            return 0
        if a.cmd == "status":
            print(json.dumps(data, ensure_ascii=False, indent=2))
            return 0
        if unfinished:
            raise ValueError("종료되지 않은 구간이 있습니다. report 전에 end를 실행하세요")
        if not data["phases"]:
            raise ValueError("평가할 실험 구간이 없습니다")
        out = Path(a.output)
        out.mkdir(parents=True, exist_ok=True)
        es = ES(a.es, a.timeout)
        es.request("GET", "/")  # Fail early if ES is offline
        results = []
        review_rows = []
        for phase in data["phases"]:
            print(f"[QUERY] {phase['name']}: {phase['start']} .. {phase['end']}")
            results.extend(evaluate_phase(es, phase, review_rows))
        fields = ["phase", "phase_label", "kind", "model", "index", "start_utc", "end_utc",
                  "src_ip_filter", "target_ip_filter", "total", "normal", "anomaly", "unknown", "known",
                  "anomaly_pct_of_known", "first_anomaly_utc", "log_timestamp_delta_sec", "status", "error"]
        labels_path = out / "label_review.csv"
        if labels_path.exists():
            with labels_path.open(encoding="utf-8-sig", newline="") as f:
                previous = list(csv.DictReader(f))
            if any((r.get("true_label") or "").strip() for r in previous):
                raise ValueError(f"기존 레이블을 덮어쓸 수 없습니다: {labels_path}. 다른 --output 폴더를 지정하세요")
        csv_write(out / "evaluation_results.csv", results, fields)
        csv_write(labels_path, review_rows, REVIEW_FIELDS)
        atomic_write_json(out / "evaluation_results.json", results)
        (out / "evaluation_report.md").write_text(render_report(data, results), encoding="utf-8")
        print(f"[DONE] {out / 'evaluation_results.csv'}")
        print(f"[LABELS] {out / 'label_review.csv'} (true_label 검토 후 metrics 실행)")
        print(f"[DONE] {out / 'evaluation_report.md'}")
        for r in results:
            print(f"  {r['phase']:22s} {r['model']:8s} total={r['total']:5d} anomaly={r['anomaly']:5d} {r['status']}")
        return 0
    except (ValueError, ESError, OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
