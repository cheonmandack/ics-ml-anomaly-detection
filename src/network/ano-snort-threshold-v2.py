#!/usr/bin/env python3
"""Offline SCADA network anomaly experiment using PCAP-derived metadata.

This replaces alert-log feature input with 5-second IP-pair aggregates produced
by pcap_to_features.py. It does not change Snort, PLC, Filebeat, or Logstash.
Jobs: train on NORMAL features only, detect on an independent capture. For now,
this is OFFLINE/batch detection (not a continuously running SIEM agent).
"""
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn import __version__ as sklearn_version
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from pcap_to_features import FEATURE_COLUMNS, FEATURE_VERSION, es_bulk

DEFAULT_MODEL = 'detector-net-v1.joblib'


def load_features(files):
    arrays = []
    required = {'@timestamp', 'experiment_id', 'scenario', 'feature_version',
                'window_seconds', 'src_ip', 'dest_ip', *FEATURE_COLUMNS}
    for path in files:
        if not path.is_file():
            raise ValueError(f'Feature CSV not found: {path}')
        frame = pd.read_csv(path)
        missing = required.difference(frame.columns)
        if missing:
            raise ValueError(f'{path}: missing columns {sorted(missing)}')
        if frame.empty:
            raise ValueError(f'{path}: no feature rows')
        for col in ('feature_version', 'window_seconds'):
            frame[col] = pd.to_numeric(frame[col], errors='raise')
        if not frame['feature_version'].eq(FEATURE_VERSION).all():
            raise ValueError(f'{path}: unsupported feature_version')
        if not frame['window_seconds'].between(1, 60).all():
            raise ValueError(f'{path}: invalid window_seconds')
        for col in ('@timestamp', 'experiment_id', 'scenario', 'src_ip', 'dest_ip'):
            if frame[col].isna().any() or (frame[col].astype(str).str.strip() == '').any():
                raise ValueError(f'{path}: missing {col}')
        # Validate timestamps explicitly; timestamps are metadata, not features.
        pd.to_datetime(frame['@timestamp'], utc=True, errors='raise')
        for col in FEATURE_COLUMNS:
            frame[col] = pd.to_numeric(frame[col], errors='raise')
        values = frame[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
        if not np.isfinite(values).all():
            raise ValueError(f'{path}: feature table contains NaN/inf')
        if (values < 0).any():
            raise ValueError(f'{path}: feature table contains negative values')
        arrays.append(frame)
    combined = pd.concat(arrays, ignore_index=True)
    if combined['window_seconds'].nunique() != 1:
        raise ValueError('Different window lengths cannot be combined into one model')
    return combined


def train(args):
    frame = load_features(args.input)
    if not frame['scenario'].eq('normal').all():
        raise ValueError('Training requires only scenario=normal captures')
    if len(frame) < args.min_samples:
        raise ValueError(
            f'Only {len(frame)} normal feature rows; need at least {args.min_samples}. '
            'Capture more varied normal traffic before training.')
    if args.model.exists():
        raise ValueError(f'Model already exists: {args.model}; choose another name')
    X = frame[FEATURE_COLUMNS]
    clf = Pipeline([
        ('scaler', StandardScaler()),
        ('model', IsolationForest(n_estimators=200, contamination=args.contamination,
                                  random_state=42, n_jobs=-1)),
    ])
    clf.fit(X)
    package = {
        'pipeline': clf,
        'features': list(FEATURE_COLUMNS),
        'feature_version': FEATURE_VERSION,
        'window_seconds': int(frame['window_seconds'].iloc[0]),
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'normal_training_rows': len(frame),
        'training_experiments': sorted(frame['experiment_id'].unique().tolist()),
        'sklearn_version': sklearn_version,
        'contamination': args.contamination,
    }
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(package, args.model)
    pred = clf.predict(X)
    print(json.dumps({
        'result': 'trained', 'model': str(args.model),
        'normal_training_rows': len(frame),
        'training_flagged_anomaly_rows': int((pred == -1).sum()),
        'window_seconds': package['window_seconds'],
        'feature_count': len(FEATURE_COLUMNS),
        'note': 'Training outlier count is NOT a test-set false positive rate.',
    }, indent=2))


def detect(args):
    if not args.model.is_file():
        raise ValueError(f'Model not found: {args.model}; run --job train first')
    if args.output.exists():
        raise ValueError(f'Output already exists: {args.output}')
    frame = load_features(args.input)
    package = joblib.load(args.model)  # Only load a model file you created/trust.
    if not isinstance(package, dict) or package.get('feature_version') != FEATURE_VERSION:
        raise ValueError('Incompatible model package: feature version mismatch')
    if package.get('features') != FEATURE_COLUMNS:
        raise ValueError('Incompatible model package: feature columns differ')
    if not frame['window_seconds'].eq(package['window_seconds']).all():
        raise ValueError('Window length differs from training configuration')
    X = frame[FEATURE_COLUMNS]
    clf = package['pipeline']
    # Higher value means more anomalous.
    scores = -clf.decision_function(X)

    # Network ML v2: improved anomaly threshold
    ANOMALY_THRESHOLD = -0.05
    result = np.where(scores > ANOMALY_THRESHOLD, -1, 1)
    records = frame.copy()
    records['pred'] = np.where(result == -1, 'anomaly', 'normal')
    records['anomaly_score'] = scores
    records['model_name'] = args.model.name
    records['model_trained_at'] = package['trained_at']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    records.to_csv(args.output, index=False, float_format='%.8f')
    print(json.dumps({
        'result': 'detected', 'output': str(args.output),
        'total_windows_ip_pairs': len(records),
        'anomaly': int((result == -1).sum()),
        'normal': int((result == 1).sum()),
        'note': 'Anomalies are not necessarily malicious attacks.',
    }, indent=2))
    if args.es_url:
        # The persisted ES documents include feature vectors and ML predictions.
        count = es_bulk(args.es_url, args.index, records.to_dict(orient='records'))
        print(f'Indexed {count} detection rows in {args.index}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', choices=['train', 'detect'], required=True)
    parser.add_argument('--input', nargs='+', type=Path, required=True,
                        help='One or more CSVs from pcap_to_features.py')
    parser.add_argument('--model', type=Path, default=Path(DEFAULT_MODEL))
    parser.add_argument('--min-samples', type=int, default=30,
                        help='Minimum normal feature rows for training')
    parser.add_argument('--contamination', type=float, default=0.05,
                        help='IsolationForest expected outlier fraction, NOT accuracy')
    parser.add_argument('--output', type=Path,
                        help='Detection CSV output (required with --job detect)')
    parser.add_argument('--es-url', help='Optional Elasticsearch URL; detect job only')
    parser.add_argument('--index', default='scada-net-anomaly-v1')
    args = parser.parse_args()
    if not 0 < args.contamination <= 0.5:
        parser.error('--contamination must be (0, 0.5]')
    if not 30 <= args.min_samples <= 1_000_000:
        parser.error('--min-samples must be 30..1000000')
    if args.job == 'train':
        if args.output or args.es_url:
            parser.error('--output/--es-url apply only to --job detect')
        train(args)
    else:
        if args.output is None:
            parser.error('--job detect requires --output')
        detect(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f'[ERROR] {exc}', file=sys.stderr)
        raise SystemExit(1)
