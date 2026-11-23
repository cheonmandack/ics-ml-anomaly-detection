import os
import time
import sys
from datetime import datetime
from elasticsearch import Elasticsearch
from pymodbus.client.sync import ModbusTcpClient

def connect_ea():
    es = Elasticsearch(os.environ.get("ES_URL", "http://127.0.0.1:9200"))
    if es.ping():
        print('[*] Successfully connected to Elasticsearch')
        return es
    else:
        print('[!] Failed to connect to Elasticsearch')
        return None

def connect_plc(plc_ip):
    client = ModbusTcpClient(plc_ip, port=502)
    client.connect()
    return client

def collect_plc_data(es, client):
    addr_IX0_0 = 0x0000
    addr_QW0 = 0x0000
    addr_QX0_0 = 0x0000
    result_IX0_0 = client.read_discrete_inputs(addr_IX0_0, 1)
    result_QW0 = client.read_holding_registers(addr_QW0, 1)
    result_QX0_0 = client.read_coils(addr_QX0_0, 1)

    now = datetime.utcnow()
    cur_time = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    record = {
        '@timestamp': cur_time,
        'IX0_0': result_IX0_0.bits[0],
        'QX0_0': result_QX0_0.bits[0],
        'QW0': result_QW0.registers[0]
    }

    print(record)

    es.index(index='plc3-data', body=record)

def main():
    plc_ip = sys.argv[1]
    es = connect_ea()
    client = connect_plc(plc_ip)

    while True:
        print('collect...')
        collect_plc_data(es, client)
        time.sleep(1)

    client.close()

if __name__ == '__main__':
    main()
