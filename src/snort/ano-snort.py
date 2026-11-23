import os
import numpy as np
import pandas as pd
import joblib
import argparse
import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
# from elasticsearch_dsl import Search
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest

classifications = [
    'Not Suspicious Traffic',
    'Unknown Traffic',
    'Potentially Bad Traffic',
    'Attempted Information Leak',
    'Information Leak',
    'Large Scale Information Leak',
    'Attempted Denial of Service',
    'Denial of Service',
    'Attempted User Privilege Gain',
    'Unsuccessful User Privilege Gain',
    'Successful User Privilege Gain',
    'Attempted Administrator Privilege Gain',
    'Successful Administrator Privilege Gain',
    'Decode of an RPC Query',
    'Executable code was detected',
    'A suspicious string was detected',
    'A suspicious filename was detected',
    'An attempted login using a suspicious username was detected',
    'A system call was detected',
    'A TCP connection was detected',
    'A Network Trojan was detected',
    'A client was using an unusual port',
    'Detection of a Network Scan',
    'Detection of a Denial of Service Attack',
    'Detection of a non-standard protocol or event',
    'Generic Protocol Command Decode',
    'Access to a potentially vulnerable web application',
    'Web Application Attack',
    'Misc Activity',
    'Misc Attack',
    'Generic ICMP event',
    'Inappropriate Content was Detected',
    'Potential Corporate Privacy Violation',
    'Attempt to login by a default username and password',
    'Sensitive Data',
    'Known malicious file or file based exploit',
    'Known malware command and control traffic',
    'Known client side exploit attempt'
]

protocols_nams = ['ICMP', 'TCP', 'UDP', 'UNK']
protocols = {
    'ICMP': 1,
    'TCP': 2,
    'UDP': 3,
    'UNK': 0
}

def connect_ea():
    es = Elasticsearch(os.environ.get("ES_URL", "http://127.0.0.1:9200"))
    if es.ping():
        print('[*] Successfully connected to Elasticsearch')
        return es
    else:
        print('[!] Failed to connect to Elasticsearch')
        return None

def get_indices(es):
    return es.indices.get_alias(index='*')

def search_document_raw(es):
    query = '''
    {
        "query": {
            "term": {
                "input.type": "log"
            }
        }
    }
    '''
    docs = es.search(index='snort-logs-*', body=query)
    n_docs = docs['hits']['total']['value']
    print(f'{n_docs} docs retrieved')

# def search_document_high(es):
#     s = Search(using=es, index='snort-logs-*').query('term', **{'input.type': 'log'})
#     res = s.execute()
#     n_docs = res.hits.total.value
#     print(f'{n_docs} docs retrieved')

def fetch_logs_for_train(es, timestamp):
    logs = []
    docs = es.search(index='snort-logs-*', body={
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
    logs += [d['_source' ]for d in docs['hits']['hits']]
    cnt = n_docs

    while n_docs > 0:
        docs = es.scroll(scroll_id=scroll_id, scroll='1m')
        logs += [d['_source' ]for d in docs['hits']['hits']]
        n_docs = len(docs['hits']['hits'])
        cnt += n_docs

    print(f'{cnt} docs retrieved')
    es.clear_scroll(scroll_id=scroll_id)
    return logs

def fetch_logs_for_detection(es, start_time, end_time):
    logs = []
    docs = es.search(index='snort-logs-*', body={
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
    data_rec = []
    data = []
    for log in logs:
        if '_grokparsefailure' not in log['tags']:

            if ':' in log.get('src_ip', '') or ':' in log.get('dest_ip', ''):
                continue

            timestamp = log['@timestamp']
            protocol = protocols['UNK'] if protocols.get(log['protocol']) is None else protocols.get(log['protocol'])
            ttl = log['ttl']
            src_ip = log['src_ip'].split('.')
            print(log['src_ip'], log['src_ip'].split('.'))
            src_ip0 = int(src_ip[0])
            src_ip1 = int(src_ip[1])
            src_ip2 = int(src_ip[2])
            src_ip3 = int(src_ip[3])
            src_port = 0 if log.get('src_port') is None else log.get('src_port')
            dest_ip = log['dest_ip'].split('.')
            dest_ip0 = int(dest_ip[0])
            dest_ip1 = int(dest_ip[1])
            dest_ip2 = int(dest_ip[2])
            dest_ip3 = int(dest_ip[3])
            dest_port = 0 if log.get('dest_port') is None else log.get('dest_port')
            tos = int(log['tos'], 16)
            # code = log['code']
            priority = log['priority']
            # type = log['type']
            cls = classifications.index(log['cls'])
            iplen = log['iplen']
            # icmp_id = log['idmp_id']
            dgmlen = log['dgmlen']
            sid = log['sid']
            gid = log['gid']
            # icmp_type = log['icmp_type']
            # icmp_seq = log['icmp_seq']
            data_rec.append([protocol, ttl, src_ip0, src_ip1, src_ip2, src_ip3, src_port, dest_ip0, dest_ip1, dest_ip2, dest_ip3, dest_port, tos, cls, priority, iplen, dgmlen, gid, sid])
            data.append([timestamp, log['protocol'], ttl, log.get('src_ip'), src_port, log.get('dest_ip'), dest_port, tos, log['cls'], priority, iplen, dgmlen, gid, sid])
    columns_rec = ['protocol', 'ttl', 'src_ip0', 'src_ip1', 'src_ip2', 'src_ip3', 'src_port', 'dest_ip0', 'dest_ip1', 'dest_ip2', 'dest_ip3', 'dest_port', 'tos', 'cls', 'priority', 'iplen', 'dgmlen', 'gid', 'sid']
    columns = ['@timestamp', 'protocol', 'ttl', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'tos', 'cls', 'priority', 'iplen', 'dgmlen', 'gid', 'sid']
    data_rec = pd.DataFrame(data_rec,columns=columns_rec)
    data = pd.DataFrame(data,columns=columns)

    if do_save:
        print('[*] Successfully saved dataset')
        data_rec.to_csv('./data.csv', index=False)
    return data_rec, data

def one_hot(data, col, total):
    # one_hot = pd.get_dummies(data[col], prefix=col).astype(int)
    #
    # data = data.drop(col, axis=1)
    # data = pd.concat([data, one_hot], axis=1)
    one_hot_encoded = np.zeros((data.shape[0], len(total)), dtype=int)
    cat_to_ind = {cat:ind for ind, cat in enumerate(total)}

    for i, cat in enumerate(data[col]):
        if cat in cat_to_ind:
            one_hot_encoded[i, cat_to_ind[cat]] = 1

    one_hot_df = pd.DataFrame(one_hot_encoded, columns=[f'{col}_{cat}' for cat in total])
    data = data.drop(col, axis=1)
    data = pd.concat([data, one_hot_df], axis=1)
    return data

def normalize(data, col, min_val, max_val):
    # scaler = MinMaxScaler()
    # print(data[col])
    # data[[col]] = scaler.fit_transform(data[[col]])
    data[[col]] = (data[[col]] - min_val) / (max_val - min_val)
    return data

def standardize(data, col):
    if data[[col]].shape[0] == 0:
        print(f'[!] Skip standardizing {col}: no data')
        return data

    # 숫자형인지 확인
    if not pd.api.types.is_numeric_dtype(data[col]):
        print(f'[*] Attempting to convert {col} to numeric (original dtype: {data[col].dtype})')
        data[col] = pd.to_numeric(data[col], errors='coerce')  # 변환 실패 시 NaN

    std = data[[col]].std().iloc[0]
    if std == 0 or np.isnan(std):
        print(f'[!] Standard deviation is 0 or NaN for {col}, filling with 0')
        data[[col]] = 0
        return data

    scaler = StandardScaler()
    try:
        data[[col]] = scaler.fit_transform(data[[col]])
    except ValueError as e:
        print(f"[!] Error standardizing {col}: {e}")
    return data



def drop(data, col):
    return data.drop(col, axis=1)

def preprocess(data):
    print('[*] Preprocessing data')
    print(data.shape)
    data = one_hot(data, 'protocol', protocols_nams)
    data = one_hot(data, 'priority', [f'{ind}' for ind in range(4)])
    data = one_hot(data, 'cls', classifications)
    data = normalize(data, 'src_ip0', 0, 255)
    data = normalize(data, 'src_ip1', 0, 255)
    data = normalize(data, 'src_ip2', 0, 255)
    data = normalize(data, 'src_ip3', 0, 255)
    data = normalize(data, 'dest_ip0', 0, 255)
    data = normalize(data, 'dest_ip1', 0, 255)
    data = normalize(data, 'dest_ip2', 0, 255)
    data = normalize(data, 'dest_ip3', 0, 255)
    data = standardize(data, 'ttl') #
    data = standardize(data, 'dgmlen')  #
    data = standardize(data, 'iplen')   #
    data = standardize(data, 'src_port')    #
    data = standardize(data, 'dest_port')   #
    data = drop(data, 'sid')
    data = drop(data, 'gid')
    return data

def train_detector(data):
    clf = IsolationForest(contamination=0.01)
    print('[*] Fit anomaly detector')
    clf.fit(data)

    res = pd.DataFrame(clf.predict(data))   # 1: normal, -1: anomaly
    print(f'the number of anomaly: {res.value_counts().get(-1, 0)}')
    print(f'the number of normal: {res.value_counts().get(1, 0)}')

    print('[*] Save the trained model')
    joblib.dump(clf, os.path.join(os.path.dirname(__file__), "detector.pkl"))

def load_detector():
    clf = joblib.load(os.path.join(os.path.dirname(__file__), "detector.pkl"))
    return clf

def detect_anomaly(es):
    clf = load_detector()

    with open('lasttime', 'r') as f:
        start_time = f.readline().strip('')

    while True:
        now = datetime.utcnow()
        # now = datetime(year=2024, month=10, day=31, hour=20, minute=57, second=0) -
        cur_time = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        print(start_time, cur_time)

        logs = fetch_logs_for_detection(es, start_time, cur_time)
        if not logs:
            time.sleep(1)
            continue

        with open('lasttime', 'w') as f:
            f.write(cur_time)

        data_rec, data = transform_to_dataset(logs)

        data_p = preprocess(data_rec)
        # res = pd.DataFrame(clf.predict(data_p), columns=['pred'])['pred'].map({-1: 'anomaly', 1: 'normal'})
        if data_p.empty:
            print('[!] No valid data to detect anomalies')
            start_time = cur_time
            time.sleep(1)
            continue

        res = pd.DataFrame(clf.predict(data_p), columns=['pred'])['pred'].map({-1: 'anomaly', 1: 'normal'})

        data = pd.concat([data, res], axis=1)

        data = data.to_dict(orient='records')
        for record in data:
            es.index(index='anomaly-snort', body=record)

        start_time = cur_time
        time.sleep(1)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--job', type=str, default='detect', choices=['train', 'detect'])
    return parser.parse_args()

def main():
    args = parse_args()
    es = connect_ea()
    # search_document_raw(es)
    # search_document_high(es)

    if args.job == 'train':
        now = datetime.utcnow()
        # now = datetime(year=2025, month=8, day=4, hour=19, minute=15, second=0) - timedelta(hours=9)
        timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        with open('lasttime', 'w') as f:
            f.write(timestamp)

        logs = fetch_logs_for_train(es, timestamp)
        transform_to_dataset(logs, True)

        data = pd.read_csv('./data.csv')
        data = preprocess(data)
        train_detector(data)
    elif args.job == 'detect':
        detect_anomaly(es)


if __name__ == '__main__':
    main()
