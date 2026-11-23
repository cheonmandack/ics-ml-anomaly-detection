#!/usr/bin/env bash
# SCADA/PLC SIEM demo launcher. Run as the regular scada user, not root.
set -Eeuo pipefail

BASE="${DEMO_BASE:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
# Load local configuration
if [[ -f "$BASE/.env" ]]; then
    set -a
    source "$BASE/.env"
    set +a
fi

RUN="$BASE/demo-run"
PYTHON="${PYTHON:-$BASE/.venv/bin/python}"
PLC_IP="${PLC_IP:-}"
OT_IFACE="${OT_IFACE:-}"
PCAP_IFACE="${PCAP_IFACE:-}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
export ES_URL
# An optional legacy second-stage Snort-alert ML analyzer.
ENABLE_SNORT_ML="${ENABLE_SNORT_ML:-1}"

say() { printf '[demo] %s\n' "$*"; }
warn() { printf '[demo] WARNING: %s\n' "$*" >&2; }
fail() { printf '[demo] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -ne 0 ]] || fail 'Run as scada, not root (sudo is used for packet capture only).'
mkdir -p "$RUN"

alive() {
    local name="$1"; local pidfile="$RUN/$name.pid"; local pid
    [[ -s "$pidfile" ]] || return 1
    read -r pid < "$pidfile"
    [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && \
        [[ "$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')" != Z* ]]
}

has_external() {
    local expression="$1"
    pgrep -u "$(id -u)" -f "$expression" >/dev/null 2>&1
}

launch_python() {
    local name="$1" script="$2" dir="$3" extra_pattern="$4"
    shift 4
    if alive "$name"; then
        say "$name already running (PID $(cat "$RUN/$name.pid"))"
        return
    fi
    if has_external "$extra_pattern"; then
        warn "$name appears to be running outside this launcher; skipping to avoid duplicates."
        return
    fi
    [[ -f "$dir/$script" ]] || { warn "$name skipped: missing $dir/$script"; return; }
    (
        cd "$dir"
        exec setsid "$PYTHON" -u "$script" "$@"
    ) >"$RUN/$name.log" 2>&1 < /dev/null &
    echo "$!" > "$RUN/$name.pid"
    say "$name started (PID $(cat "$RUN/$name.pid")); log: $RUN/$name.log"
}

launch_modbus() {
    local name="modbus-ml"
    if alive "$name"; then
        say "$name already running (PID $(cat "$RUN/$name.pid"))"
        return
    fi
    if has_external '[l]ive-modbus-es(-v3|-v5)?\.py'; then
        warn 'Modbus ML appears to be running outside this launcher; skipping.'
        return
    fi
    [[ -f "$BASE/src/modbus/live-modbus-es-v5.py" ]] || { warn 'Modbus ML skipped: live-modbus-es-v5.py missing'; return; }
    (
        cd "$BASE/src/modbus"
        exec setsid bash -o pipefail -c '
            sudo -n tshark -l -i "$1" \
              -f "host $2 and tcp port 502" \
              -Y "modbus && ip.dst == $2" \
              -T fields -e frame.time_epoch -e modbus.func_code \
              | "$3" -u live-modbus-es-v5.py
        ' _ "$OT_IFACE" "$PLC_IP" "$PYTHON"
    ) >"$RUN/$name.log" 2>&1 < /dev/null &
    echo "$!" > "$RUN/$name.pid"
    say "$name started (PID $(cat "$RUN/$name.pid")); log: $RUN/$name.log"
}

start_demo() {
    export PYTHONDONTWRITEBYTECODE=1
    [[ -d "$BASE" ]] || fail "Project directory not found: $BASE"
    [[ -n "$PLC_IP" ]] || fail 'PLC_IP must be set in .env'
    [[ -n "$OT_IFACE" ]] || fail 'OT_IFACE must be set in .env'
    [[ -n "$PCAP_IFACE" ]] || fail 'PCAP_IFACE must be set in .env'
    command -v "$PYTHON" >/dev/null || fail "Python not found: $PYTHON"
    command -v curl >/dev/null || fail 'curl not found'
    command -v setsid >/dev/null || fail 'setsid not found'
    curl -fsS --max-time 3 "$ES_URL" >/dev/null || fail "Elasticsearch not reachable: $ES_URL"
    say "Elasticsearch OK: $ES_URL"

    local capture_needed=0
    if ! systemctl is-active --quiet network-ml-stream.service 2>/dev/null && \
       ! alive pcap-ml && ! has_external '[n]etwork_ml_stream(_v2)?\.py'; then
        capture_needed=1
    fi
    if ! alive modbus-ml && ! has_external '[l]ive-modbus-es(-v3|-v5)?\.py' && \
       [[ -f "$BASE/src/modbus/live-modbus-es-v5.py" ]]; then
        capture_needed=1
    fi
    if (( capture_needed )); then
        command -v sudo >/dev/null || fail 'sudo not found'
        sudo -v || fail 'Cannot obtain sudo permission for packet capture'
        sudo -n true || fail 'sudo credentials unavailable'
    fi

    # Some collector versions expect PLC IP as a positional argument.
    local -a collector_args=()
    if [[ -f "$BASE/src/plc/collect-plc.py" ]] && grep -Eq 'sys\.argv\[1\]' "$BASE/src/plc/collect-plc.py"; then
        collector_args+=("$PLC_IP")
    fi
    launch_python plc-collector collect-plc.py "$BASE/src/plc" '[c]ollect-plc\.py' "${collector_args[@]}"
    launch_python plc-ml ano-plc.py "$BASE/src/plc" '[a]no-plc\.py' --job detect

    if [[ "$ENABLE_SNORT_ML" == 1 ]]; then
        launch_python snort-ml ano-snort.py "$BASE/src/snort" '[a]no-snort\.py' --job detect
    else
        say 'Legacy Snort-alert ML disabled (ENABLE_SNORT_ML=0)'
    fi

    if systemctl is-active --quiet network-ml-stream.service 2>/dev/null; then
        say 'PCAP ML is already running via network-ml-stream.service; not duplicating.'
    elif alive pcap-ml; then
        say "PCAP ML already running (PID $(cat "$RUN/pcap-ml.pid"))"
    elif has_external '[n]etwork_ml_stream(_v2)?\.py'; then
        warn 'PCAP ML appears to be running outside this launcher; skipping.'
    elif [[ -f "$BASE/src/network/network_ml_stream_v2.py" ]]; then
        [[ -f "$BASE/src/network/detector-net-v1.joblib" ]] || warn 'Missing detector-net-v1.joblib; check pcap-ml.log.'
        launch_python pcap-ml network_ml_stream_v2.py "$BASE/src/network" '[n]etwork_ml_stream(_v2)?\.py' \
            --interface "$PCAP_IFACE" --seconds 30 --segments 0 --capture-mode sudo \
            --workdir "$RUN/network_ml_stream_runs_v2" \
            --es "$ES_URL" --index network-ml-anomaly-v2
    else
        warn 'PCAP ML skipped: network_ml_stream.py missing.'
    fi
    launch_modbus

    for svc in elasticsearch kibana logstash filebeat; do
        if command -v systemctl >/dev/null; then
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                say "$svc: active"
            else
                warn "$svc: inactive or not installed (start/check separately if needed)"
            fi
        fi
    done
    if pgrep -x snort >/dev/null 2>&1; then
        say 'Snort process detected.'
    else
        warn 'Snort process not detected; Snort-rule panels require it to run.'
    fi
    say 'Startup attempted. Run: ./start-demo.sh status  (check log files for errors)'
}

status_demo() {
    local name
    for name in plc-collector plc-ml snort-ml pcap-ml modbus-ml; do
        if alive "$name"; then
            say "$name: RUNNING PID=$(cat "$RUN/$name.pid")"
        else
            say "$name: not managed/running by this script (log: $RUN/$name.log)"
        fi
    done
    if systemctl is-active --quiet network-ml-stream.service 2>/dev/null; then
        say 'PCAP ML systemd service: ACTIVE'
    fi
    say "Logs: $RUN/*.log"
}

stop_demo() {
    local name pid
    for name in modbus-ml pcap-ml snort-ml plc-ml plc-collector; do
        if alive "$name"; then
            read -r pid < "$RUN/$name.pid"
            # Each launcher is placed in its own session/process group.
            kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
            say "Stop requested: $name (PID $pid)"
        fi
        rm -f "$RUN/$name.pid"
    done
    say 'External systemd services, Snort, and independently launched programs were not stopped.'
}

case "${1:-start}" in
    start) start_demo ;;
    status) status_demo ;;
    stop) stop_demo ;;
    *) echo "Usage: $0 {start|status|stop}" >&2; exit 2 ;;
esac
