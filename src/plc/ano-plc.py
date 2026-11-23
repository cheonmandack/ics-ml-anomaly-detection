import os
import time
import argparse
import joblib
import pandas as pd
from datetime import datetime
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest

def connect_ea():
    es = Elasticsearch(os.environ.get("ES_URL", "http://127.0.0.1:9200"))
    if es.ping():
        print('[*] Successfully connected to Elasticsearch')
        return es
    else:
        print('[!] Failed to connect to Elasticsearch')
        return None

def fetch_data(es, timestamp):
    logs = []
    docs = es.search(index='plc3-data', body={
        "query": {
            "range": {
                "@timestamp": {"lt": timestamp}
            }
        },
        "sort": {
            "@timestamp": {"order": "desc"}
        }
    }, scroll='1m', size=100)
    scroll_id = docs['_scroll_id']
    n_docs = len(docs['hits']['hits'])
    logs += [d['_source'] for d in docs['hits']['hits']]
    cnt = n_docs

    while n_docs > 0:
        docs = es.scroll(scroll_id=scroll_id, scroll='1m')
        logs += [d['_source'] for d in docs['hits']['hits']]
        n_docs = len(docs['hits']['hits'])
        cnt += n_docs

    print(f'{cnt} docs retrieved')
    es.clear_scroll(scroll_id=scroll_id)
    return logs

def fetch_logs_for_detection(es, start_time, end_time):
    logs = []
    docs = es.search(index='plc3-data', body={
        "query": {
            "range": {
                "@timestamp": {
                    "gt": start_time,
                    "lte": end_time
                }
            }
        },
        "sort": {
            "@timestamp": {"order": "desc"}
        }
    }, scroll='1m', size=100)
    scroll_id = docs['_scroll_id']
    n_docs = len(docs['hits']['hits'])
    logs += [d['_source'] for d in docs['hits']['hits']]
    cnt = n_docs

    while n_docs > 0:
        docs = es.scroll(scroll_id=scroll_id, scroll='1m')
        logs += [d['_source'] for d in docs['hits']['hits']]
        n_docs = len(docs['hits']['hits'])
        cnt += n_docs

    print(f'{cnt} docs retrieved')
    es.clear_scroll(scroll_id=scroll_id)
    return logs

def transform_to_dataset(logs, do_save=False):
    data = []
    data_rec = []
    for log in logs:
        timestamp = log['@timestamp']
        val_IX0_0 = log['IX0_0']
        val_QX0_0 = log['QX0_0']
        val_QW0 = log['QW0']
        data_rec.append([int(val_IX0_0), int(val_QX0_0), val_QW0])
        data.append([timestamp, val_IX0_0, val_QX0_0, val_QW0])

    columns_rec = ['IX0_0', 'QX0_0', 'QW0']
    columns = ['@timestamp', 'IX0_0', 'QX0_0', 'QW0']
    data_rec = pd.DataFrame(data_rec, columns=columns_rec)
    data = pd.DataFrame(data, columns=columns)

    if do_save:
        print('[*] Successfully saved dataset')
        data_rec.to_csv('./data-plc.csv', index=False)
    return data_rec, data

def train_detector(data):
    clf = IsolationForest(contamination=0.01)
    print('[*] Fit anomaly detector')
    clf.fit(data)

    res = pd.DataFrame(clf.predict(data))
    print(f'the number of anomaly: {res.value_counts().get(-1, 0)}')
    print(f'the number of normal: {res.value_counts().get(1, 0)}')

    print('[*] Save the trained model')
    joblib.dump(clf, os.path.join(os.path.dirname(__file__), "detector-plc.pkl"))

def load_detector():
    clf = joblib.load(os.path.join(os.path.dirname(__file__), "detector-plc.pkl"))
    return clf

def detect_anomaly(es):
    from datetime import timedelta
    import hashlib

    clf = load_detector()

    with open('lasttime-plc', 'r') as f:
        start_time = f.read().strip()

    while True:
        cutoff = datetime.utcnow() - timedelta(seconds=5)
        end_time = cutoff.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        previous = datetime.fromisoformat(
            start_time.replace('Z', '+00:00')
        )
        query_start = (
            previous - timedelta(seconds=10)
        ).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        logs = fetch_logs_for_detection(
            es, query_start, end_time
        )

        if not logs:
            time.sleep(1)
            continue

        data_rec, data = transform_to_dataset(logs)

        scores = clf.decision_function(data_rec)
        ml_flags = [score < -0.04 for score in scores]
        rule_flags = (data_rec["QW0"].astype(float) > 100).tolist()
        predictions = [
            -1 if ml or rule else 1
            for ml, rule in zip(ml_flags, rule_flags)
        ]
        data['pred'] = [
            'anomaly' if x == -1 else 'normal'
            for x in predictions
        ]

        records = data.to_dict(orient='records')

        for record in records:
            key = (
                str(record['@timestamp']) + '|' +
                str(record['IX0_0']) + '|' +
                str(record['QX0_0']) + '|' +
                str(record['QW0'])
            )
            doc_id = hashlib.sha256(
                key.encode('utf-8')
            ).hexdigest()

            es.index(
                index='anomaly-plc3',
                id=doc_id,
                body=record
            )

        latest = max(
            record['@timestamp'] for record in records
        )

        if latest > start_time:
            with open('lasttime-plc', 'w') as f:
                f.write(latest)
            start_time = latest

        print(f'{len(records)} records checked')
        time.sleep(1)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--job', type=str, default='detect', choices=['train', 'detect'])
    return parser.parse_args()

def main():
    args = parse_args()
    es = connect_ea()

    if args.job == 'train':
        now = datetime.utcnow()
        timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        with open('lasttime-plc', 'w') as f:
            f.write(timestamp)

        logs = fetch_data(es, timestamp)
        data_rec, data = transform_to_dataset(logs)

        train_detector(data_rec)

    elif args.job == 'detect':
        detect_anomaly(es)

if __name__ == '__main__':
    main()
