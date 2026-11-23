# ICS Machine Learning-Based Anomaly Detection

**산업제어시스템 보안을 위한 머신러닝 기반 공정 이상탐지 통합 SIEM**

산업제어시스템(ICS)에서 발생하는 네트워크 보안 이벤트와 PLC 공정 데이터를 분석하고, 머신러닝 기반 이상탐지 결과를 Elasticsearch와 Kibana에 통합하는 보안 모니터링 프로젝트입니다.

Snort의 규칙 기반 탐지와 머신러닝 기반 이상탐지를 함께 활용하여 네트워크 통신, PLC 공정 상태 및 Modbus 제어 요청의 이상징후를 분석합니다.

## 1. Project Overview

### Background

산업제어시스템은 PLC와 SCADA 등 다양한 제어장치를 통해 산업 설비의 상태를 감시하고 제어합니다. 이러한 환경에서 사이버공격은 단순한 네트워크 장애를 넘어 공정값 변조와 비정상적인 제어 동작으로 이어질 수 있습니다.

기존의 규칙 기반 침입탐지시스템은 사전에 정의된 공격 패턴을 탐지하는 데 효과적이지만, 정상적인 프로토콜 형식을 유지하면서 발생하는 비정상적인 제어 행위나 공정 상태의 변화를 파악하는 데 한계가 있습니다.

이에 본 프로젝트에서는 네트워크 통신과 PLC 공정 데이터를 서로 다른 분석 대상으로 구분하고, 머신러닝 기반 이상탐지를 적용하여 다양한 이상징후를 관측할 수 있는 시스템을 구현했습니다.

### Objectives

- Snort 규칙 탐지와 머신러닝 기반 이상탐지 병행
- 네트워크 통신 및 PLC 공정 데이터의 이상징후 분석
- Modbus TCP 제어 요청의 빈도와 반복·전환 패턴 분석
- Elasticsearch 기반 보안 이벤트 및 이상탐지 결과 저장
- Kibana를 활용한 통합 보안 모니터링 대시보드 구현

## 2. System Architecture

<img width="2688" height="1596" alt="시스템 아키텍처" src="https://github.com/user-attachments/assets/5d08b915-e8ec-4c22-bd5a-0687d9d88c53" />

**그림 1. 전체 시스템 아키텍처**

시스템은 데이터 수집, 탐지·분석, 결과 저장, 통합 시각화의 네 단계로 구성됩니다.

| 단계 | 주요 기능 |
|---|---|
| 데이터 수집 | Snort 경고 로그, 네트워크 패킷, PLC 공정 데이터 및 Modbus 제어 요청 수집 |
| 탐지·분석 | Snort 규칙 탐지와 Isolation Forest 및 One-Class SVM 기반 이상탐지 |
| 결과 저장 | Elasticsearch에 원본 데이터와 모듈별 탐지 결과 저장 |
| 통합 시각화 | Kibana 대시보드를 통해 보안 이벤트와 공정 상태 조회 |

각 머신러닝 모듈은 독립적으로 이상 여부를 판정하며, 결과를 Elasticsearch에 저장합니다.

본 프로젝트에서 **통합 모니터링은 각 모듈의 결과를 공통 환경에서 조회하는 것을 의미**하며, 모델의 예측값을 결합하거나 이벤트 간의 연관성을 자동으로 분석하는 기능은 포함하지 않습니다.

## 3. Technology Stack

| Category | Technology |
|---|---|
| Operating System | Ubuntu Linux |
| Programming Language | Python 3.10 |
| PLC / Process Simulation | OpenPLC Runtime, Structured Text |
| Industrial Protocol | Modbus TCP |
| Intrusion Detection | Snort |
| Packet Capture & Analysis | tcpdump, TShark |
| Machine Learning | Scikit-learn, Isolation Forest, One-Class SVM |
| Data Processing | Pandas, NumPy |
| Log Collection | Filebeat, Logstash |
| Data Storage | Elasticsearch 7.17 |
| Visualization | Kibana |

## 4. Anomaly Detection Modules

본 시스템은 네 가지 데이터를 대상으로 독립적인 머신러닝 분석 모듈을 구성했습니다.

### 4.1. Snort Alert-Based Anomaly Detection

**Algorithm: Isolation Forest**

Snort는 네트워크 패킷을 사전에 정의된 탐지 규칙과 비교하여 경고 로그를 생성합니다. 생성된 로그는 Filebeat와 Logstash를 거쳐 Elasticsearch에 저장됩니다.

Snort 로그 기반 머신러닝 모듈은 Elasticsearch에 저장된 경고 로그를 조회하고, 다음과 같은 특징을 추출하여 이상 여부를 분석합니다.

- 출발지 및 목적지 IP 주소
- 통신 프로토콜과 포트 번호
- TTL 및 패킷 길이
- Snort 경고 우선순위와 탐지 분류

범주형 특징은 원-핫 인코딩을 적용하고, 수치형 특징은 정규화 및 표준화 과정을 거쳐 모델 입력으로 사용합니다.

이 모듈은 **Snort에서 경고가 발생한 로그만 분석**합니다. 따라서 머신러닝에서 정상으로 판정되더라도 해당 통신이 안전하다는 의미는 아닙니다.

관련 파일: `src/snort/`

### 4.2. Network Traffic Anomaly Detection

**Algorithm: Isolation Forest**

네트워크 이상탐지 모듈은 Snort 경고 발생 여부와 관계없이 수집 대상 네트워크의 패킷 통계 특징을 분석합니다.

tcpdump를 이용하여 패킷을 수집하고, 기본 30초 단위로 PCAP 파일을 분할합니다. 수집된 패킷은 5초 구간별로 나누어 출발지·목적지 IP 주소 쌍을 기준으로 통신 특징을 추출합니다.

주요 분석 특징은 다음과 같습니다.

- 패킷 수 및 초당 패킷 수
- 전송 바이트 수
- TCP SYN 패킷 수
- ICMP 패킷 수
- 목적지 포트 수

정상 운전 중 수집한 통신 특징으로 Isolation Forest를 학습한 뒤, 새로운 통신 구간의 이상 점수를 계산하여 정상·이상 여부를 판정합니다.

관련 파일: `src/network/`

### 4.3. PLC Process Anomaly Detection

**Algorithm: Isolation Forest**

PLC 공정 이상탐지 모듈은 네트워크 통신뿐 아니라 실제 공정에서 발생하는 상태 변화를 분석하기 위해 구현했습니다.

OpenPLC에서 동작하는 물탱크 공정을 대상으로 Modbus TCP를 이용하여 다음 데이터를 수집합니다.

- PLC 입력 상태 (`%IX0.0`)
- PLC 출력 상태 (`%QX0.0`)
- 물탱크 수위값 (`%QW0`)

수집된 공정 데이터는 Elasticsearch에 저장되며, 머신러닝 모듈은 입력·출력 상태와 수위값을 조합하여 정상 운전 패턴과 다른 관측값을 탐지합니다.

이상 판정 결과는 원래의 공정 데이터 및 발생 시각과 함께 저장하여 Kibana에서 공정값 변화와 이상 발생 시점을 확인할 수 있도록 했습니다.

관련 파일: `src/plc/`

### 4.4. Modbus TCP Anomaly Detection

**Algorithm: One-Class SVM (RBF Kernel)**

Modbus 통신 이상탐지 모듈은 정상적인 프로토콜 형식을 사용하는 요청에서도 비정상적인 제어 패턴이 나타날 수 있다는 점에 착안하여 구현했습니다.

TShark를 이용해 PLC로 향하는 Modbus TCP 요청을 수집하고, 5초 단위 요청 집계와 최근 30초의 통신 이력을 이용하여 총 11개의 특징을 구성합니다.

| 구분 | 분석 특징 |
|---|---|
| 요청 빈도 | 전체 요청 수, FC01·FC02·FC03 요청 수 |
| 쓰기 요청 | 전체 쓰기 수, FC05·FC06 요청 수 |
| 쓰기 이력 | 최근 30초 FC05·FC06 누적 요청 수 |
| 요청 순서 | 동일 기능 코드 연속 횟수, 기능 코드 전환 횟수 |

StandardScaler와 RBF 커널 기반 One-Class SVM을 결합하여 정상적인 제어 요청 패턴에서 벗어나는 통신을 탐지합니다.

동일한 집계 구간에 쓰기 요청이 여러 건 포함되어 발생 순서를 확정할 수 없는 경우에는 판정을 생략하고, 판정 불가 상태와 사유를 Elasticsearch에 기록합니다.

관련 파일: `src/modbus/`, `models/modbus/`

## 5. SIEM Integration & Monitoring

### Elasticsearch Integration

각 분석 모듈의 입력 데이터 및 이상탐지 결과는 Elasticsearch에 저장합니다.

Snort 경고 로그는 Filebeat와 Logstash를 이용하여 수집·정규화하고, Python 기반 머신러닝 모듈의 판정 결과는 모듈별 인덱스로 구분하여 저장합니다.

분석 결과에는 발생 시각, 정상·이상 판정값, 관련 네트워크 정보 또는 PLC 공정값 등을 기록합니다.

### Kibana Dashboard

Kibana를 이용하여 네트워크 보안 이벤트와 공정 데이터의 이상탐지 결과를 통합 조회할 수 있도록 대시보드를 구성했습니다.

주요 모니터링 항목은 다음과 같습니다.

- 조회 기간 내 이상탐지 건수
- 시간에 따른 이상탐지 발생 추이
- 최근 보안 이벤트 및 관련 IP 주소
- PLC 수위값의 시계열 변화와 이상 판정 시점
- Modbus 제어 요청의 이상 판정 결과

이를 통해 운영자는 동일한 시간대를 기준으로 네트워크 통신과 공정 상태의 변화를 비교하고, 추가 분석이 필요한 이벤트를 확인할 수 있습니다.

## 6. Experimental Environment

### 6.1. Testbed

실험은 가상화 기반의 SCADA 분석 서버, OpenPLC 제어시스템 및 공격자 호스트로 구성한 환경에서 수행했습니다.

| 구성 요소 | 역할 |
|---|---|
| SCADA 분석 서버 | Ubuntu 기반 데이터 수집, 이상탐지 및 SIEM 연계 |
| OpenPLC Runtime | 물탱크 공정 시뮬레이션 및 PLC 제어 |
| 공격자 호스트 | 네트워크 공격 트래픽 및 Modbus 제어 요청 발생 |
| Elasticsearch / Kibana | 데이터 저장, 검색 및 통합 모니터링 |

물탱크 공정은 Structured Text로 구현했으며, 정상 운전 시 수위가 0부터 100까지 증가와 감소를 반복하도록 구성했습니다.

### 6.2. Attack Scenarios

| 시나리오 | 실험 내용 | 평가 대상 |
|---|---|---|
| Normal Operation | 정상적인 네트워크 통신 및 물탱크 공정 운전 | Network / PLC / Modbus ML |
| ICMP Flood | ICMP Echo Request 반복 전송 | Network ML |
| TCP Port Scan | 여러 목적지 포트에 대한 연결 시도 | Network ML |
| PLC Value Manipulation | 물탱크 수위값을 150으로 변조 | PLC ML |
| Modbus Write Requests | FC05·FC06을 이용한 반복 쓰기 요청 | Modbus ML |

실험은 격리된 가상 환경에서 수행했으며, 수집된 통신 및 공정 관측값을 기준으로 모델별 탐지 결과를 평가했습니다.

## 7. Experimental Results

졸업논문의 최종 성능평가에서는 PCAP 기반 네트워크 ML, PLC 공정 ML 및 Modbus 통신 ML을 대상으로 정상·이상 판정 성능을 검증했습니다.

| 모델 | Accuracy | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|
| Network ML | 100% | 100% | 100% | 100% |
| PLC ML | 100% | 100% | 100% | 100% |
| Modbus ML | 100% | 100% | 100% | 100% |

| 모델 | TP | TN | FP | FN |
|---|---:|---:|---:|---:|
| Network ML | 30 | 70 | 0 | 0 |
| PLC ML | 10 | 184 | 0 | 0 |
| Modbus ML | 40 | 80 | 0 | 0 |

다만 이는 **제한된 가상화 환경과 특정 평가 데이터에서 얻은 결과**입니다. 특히 Network ML의 판정 임계값은 최종 평가 데이터를 참고하여 조정했으므로, 결과를 독립적인 미사용 데이터에 대한 일반화 성능으로 해석할 수 없습니다.

Snort 로그 기반 ML은 구현 대상에 포함했지만, 별도의 정량 성능평가에는 포함하지 않았습니다.

## 8. Project Structure

```text
ics-ml-anomaly-detection/
├── src/
│   ├── plc/                 # PLC 데이터 수집 및 이상탐지
│   ├── snort/               # Snort 경고 로그 기반 ML
│   ├── network/             # PCAP 기반 네트워크 ML
│   └── modbus/              # Modbus 통신 이상탐지
│
├── models/
│   └── modbus/              # Modbus 후보 모델
│
├── training/
│   └── modbus/              # 학습 및 모델 비교
│
├── evaluation/
│   ├── integrated/          # 통합 평가 프로그램
│   └── modbus/              # Modbus 평가 프로그램
│
├── results/
│   └── metrics/             # 평가 결과 및 성능 지표
│
├── scripts/
│   └── start-demo.sh        # 실험 환경 실행 관리
│
├── .env.example             # 환경 설정 예시
├── .gitignore
├── requirements.txt
└── README.md
```

## 9. Installation & Configuration

본 프로젝트는 Ubuntu Linux, Python 3.10 및 Elasticsearch 7.17 환경을 기준으로 구성했습니다.

### Clone Repository

```bash
git clone https://github.com/cheonmandack/ics-ml-anomaly-detection.git
cd ics-ml-anomaly-detection
```

### Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
```

`.env` 파일에서 실제 실습 환경의 Elasticsearch 주소, PLC IP 주소 및 패킷 수집 인터페이스를 설정해야 합니다.

### Script Status

```bash
bash scripts/start-demo.sh status
```

통합 실행 스크립트는 PLC 데이터 수집 및 이상탐지, Snort 로그 분석, 네트워크 분석, Modbus 분석 모듈의 실행 상태를 관리하도록 구성했습니다.

전체 시스템을 실행하려면 OpenPLC, Snort, Elasticsearch 및 관련 로그 수집 서비스가 별도로 준비되어 있어야 합니다.

현재 저장소는 연구용 코드와 학습 모델을 정리한 형태이며, 새로운 환경에서의 전체 시스템 재현 및 통합 실행은 추가 검증이 필요합니다.
