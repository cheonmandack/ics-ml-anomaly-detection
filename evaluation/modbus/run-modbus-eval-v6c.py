import argparse
import os
import time
from datetime import datetime, timezone
from pymodbus.client.sync import ModbusTcpClient

parser = argparse.ArgumentParser()
parser.add_argument(
    "--scenario",
    choices=["benign", "repeat-fc05", "repeat-fc06"],
    required=True
)
parser.add_argument("--interval", type=float, required=True)
args = parser.parse_args()

if args.interval < 5:
    raise SystemExit("이번 평가에서는 간격을 5초 이상으로 설정하세요.")

if args.scenario == "benign":
    operations = [5, 6] * 4
elif args.scenario == "repeat-fc05":
    operations = [5] * 4
else:
    operations = [6] * 4

plc_ip = os.environ.get("PLC_IP", "").strip()

if not plc_ip:
    raise SystemExit("PLC_IP 환경 변수가 필요합니다.")

if os.environ.get("ALLOW_MODBUS_WRITES") != "YES":
    raise SystemExit(
        "Modbus 쓰기 실험 차단: 격리된 실습 PLC인지 확인한 후 "
        "ALLOW_MODBUS_WRITES=YES를 명시적으로 설정해야 합니다."
    )

client = ModbusTcpClient(plc_ip, port=502)

if not client.connect():
    raise SystemExit("PLC 연결 실패")

print(
    f"SESSION_START scenario={args.scenario} "
    f"time={datetime.now(timezone.utc).isoformat()}",
    flush=True
)

try:
    for i, fc in enumerate(operations, 1):

        # PLC의 기존 값을 먼저 읽음
        if fc == 5:
            result = client.read_coils(0, 1)
        else:
            result = client.read_holding_registers(0, 1)

        if result.isError():
            raise RuntimeError("PLC 값 읽기 실패")

        if fc == 5:
            value = bool(result.bits[0])
        else:
            value = int(result.registers[0])

        timestamp = datetime.now(timezone.utc)

        # 기존 값과 동일한 값으로 쓰기
        if fc == 5:
            response = client.write_coil(0, value)
        else:
            response = client.write_register(0, value)

        if response.isError():
            raise RuntimeError("Modbus 쓰기 실패")

        print(
            f"EVENT scenario={args.scenario} "
            f"number={i} "
            f"fc={fc:02d} "
            f"value={value} "
            f"time={timestamp.isoformat()}",
            flush=True
        )

        if i < len(operations):
            time.sleep(args.interval)

finally:
    client.close()

print(
    f"SESSION_END scenario={args.scenario} "
    f"time={datetime.now(timezone.utc).isoformat()}",
    flush=True
)
