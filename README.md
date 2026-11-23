# ICS Machine Learning-Based Anomaly Detection

산업제어시스템(ICS) 환경에서 발생하는 네트워크 통신 및 PLC 공정 데이터를 분석하고, 머신러닝 기반 이상탐지 결과를 Elasticsearch/SIEM에 통합하는 보안 모니터링 프로젝트입니다.

## 1. Project Overview

산업제어시스템에서는 네트워크 침입뿐 아니라 PLC 제어 명령 및 공정 데이터의 비정상적인 변화도 보안 위협이 될 수 있습니다.

본 프로젝트에서는 Snort 기반 규칙 탐지와 머신러닝 이상탐지를 함께 활용하여 다음 네 가지 데이터를 분석하도록 시스템을 구현했습니다.

- Snort IDS 경고 로그
- PCAP 기반 네트워크 통신 특징
- PLC 공정 데이터
- Modbus TCP 제어 요청

각 탐지 결과는 Elasticsearch에 저장하고, Elastic SIEM 환경에서 통합 조회하도록 구성했습니다.

## 2. System Architecture

```text
              ICS / SCADA Environment
                        |
       +----------------+----------------+
       |                |                |
   PLC Process      Network Traffic   Snort IDS
       |                |                |
  PLC Collector     PCAP / TShark     Alert Logs
       |                |                |
   PLC ML             Network ML       Snort ML
       |                |                |
       +----------------+----------------+
                        |
             Modbus TCP Analysis
                        |
                   Modbus ML
                        |
              Detection Events
                        |
                  Elasticsearch
                        |
                  Elastic SIEM
```

위 그림은 데이터 분석 모듈과 SIEM 연계 관계를 단순화한 개념도입니다.

## 3. Tech Stack

| Category | Technology |
|---|---|
| OS | Ubuntu Linux |
| Language | Python 3.10 |
| PLC | OpenPLC |
| Protocol | Modbus TCP |
| IDS | Snort |
| Packet Analysis | TShark, TCPDump |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| Database | Elasticsearch 7.17 |
| Monitoring | Elastic SIEM / Kibana |

## 4. Detection Modules

### PLC Anomaly Detection

PLC 공정 데이터와 입출력 상태를 수집하고 Isolation Forest 모델을 사용하여 이상징후를 탐지합니다.

- `src/plc/collect-plc.py`
- `src/plc/ano-plc.py`
- `src/plc/detector-plc.pkl`

### Snort Alert Anomaly Detection

Snort 경고 로그에서 네트워크 통신 및 탐지 관련 특징을 추출하고 Isolation Forest 모델로 분석합니다.

- `src/snort/ano-snort.py`
- `src/snort/detector.pkl`

### Network Traffic Anomaly Detection

PCAP 데이터에서 시간 구간별 통신 특징을 추출하고 머신러닝 모델을 통해 이상 통신 패턴을 분석합니다.

- `src/network/network_ml_stream_v2.py`
- `src/network/pcap_to_features.py`
- `src/network/ano-snort-threshold-v2.py`
- `src/network/import_network_ml.py`

### Modbus TCP Anomaly Detection

Modbus 기능 코드별 요청 횟수와 쓰기 명령의 반복 및 순서 특징을 분석합니다.

- 실시간 탐지: v5 모델
- 후속 모델 비교 평가: v6c 및 v6e

실시간 탐지 코드와 후속 모델 평가 결과는 서로 다른 버전임을 구분합니다.

## 5. Experimental Results

### Network ML

제한된 최종 평가 표본 10건에서 정상 7건과 이상 3건을 모두 올바르게 판정했습니다.

- Accuracy: 100%
- False Positive: 0
- False Negative: 0

해당 결과는 10건의 평가 표본에 한정되며 실제 산업 환경에서의 일반적인 탐지 성능을 의미하지 않습니다.

### Modbus ML Comparison

32건의 실험 데이터(정상 24건, 공격 8건)를 이용한 v6c 및 v6e 모델 비교 결과입니다.

| Metric | v6c | v6e |
|---|---:|---:|
| Accuracy | 68.75% | 75.00% |
| Precision | 43.75% | 50.00% |
| Recall | 87.50% | 87.50% |
| F1-score | 0.5833 | 0.6364 |
| False Positive | 9 | 7 |
| False Negative | 1 | 1 |

실험에서 v6e 모델은 v6c 대비 오탐이 감소했으나, 제한된 데이터와 실험 시나리오에 따른 결과입니다.

세부 평가 자료는 `results/metrics/`에서 확인할 수 있습니다.

## 6. Project Structure

```text
.
├── src/
│   ├── plc/
│   ├── snort/
│   ├── network/
│   └── modbus/
├── models/
│   └── modbus/
├── training/
│   └── modbus/
├── evaluation/
│   ├── integrated/
│   └── modbus/
├── results/
│   └── metrics/
├── scripts/
│   └── start-demo.sh
├── requirements.txt
├── .env.example
└── README.md
```

## 7. Installation

Python 3.10 및 Elasticsearch 7.17 환경을 기준으로 의존성을 구성했습니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

설정 파일 생성:

```bash
cp .env.example .env
```

`.env`에서 Elasticsearch 주소, PLC IP 및 네트워크 인터페이스를 실제 실습 환경에 맞게 수정해야 합니다.

실행 스크립트 상태 확인:

```bash
bash scripts/start-demo.sh status
```

전체 탐지 프로그램의 실제 통합 실행은 별도 검증이 필요합니다. 실행 시 격리된 실습 네트워크, PLC, Snort 및 Elasticsearch 환경이 준비되어 있어야 합니다.

## 8. Limitations

- 제한된 실험 환경과 데이터 규모를 기반으로 평가했습니다.
- 일부 평가 프로그램은 실습 환경의 고정 IP 및 기존 수집 서비스를 요구합니다.
- 일부 학습 및 평가 과정은 추가 재현성 검증이 필요합니다.
- 실제 산업 현장에 적용하기 전 성능, 오탐, 통신 부하 및 운영 안전성 검증이 필요합니다.

## 9. Security Notice

본 프로젝트는 격리된 교육 및 연구용 ICS 환경을 대상으로 합니다.

실제 운영 중인 산업제어시스템에 공격 시나리오나 실험 트래픽을 실행해서는 안 됩니다.

인증정보, 실제 환경 설정, 원본 패킷 캡처 및 민감한 로그는 공개 저장소에서 제외합니다.
