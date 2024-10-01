import json
import pandas as pd

paths = [
    'cpu_encode.json',
    'cpu_decode.json',
    'cpu_encrypt.json',
    'cpu_decrypt.json',
    'cpu_single_threaded.json',
    'cpu_st_range.json',
    'cpu_multi_threaded.json',
    'cpu_mt_range.json',
    'cpu_polynomial.json',
    'gpu.json',
    'gpu_range.json',
    'gpu_polynomial.json',
    'gpu_encode.json',
    'gpu_decode.json',
    'gpu_encrypt.json',
    'gpu_decrypt.json'    
]
jsons = list()

for path in paths:
    with open(path) as f:
        jsons.append(json.load(f))

iterations = list()
for j in jsons:
    iterations.append(pd.DataFrame(data=[b for b in j["benchmarks"] if b["run_type"] == "iteration"]))
dataset = pd.concat(iterations)
dataset.reset_index(drop=True, inplace=True)

aggregates = list()
for j in jsons:
    aggregates.append(pd.DataFrame(data=[b for b in j["benchmarks"] if b["run_type"] == "aggregate"]))
dataset_aggr = pd.concat(aggregates)
dataset_aggr.reset_index(drop=True, inplace=True)

benchmarks = dataset
bm_name = benchmarks['name'].str.split('/').str[1]
benchmarks['k'] = benchmarks['name'].str.split('/').str[2]
name_parts = bm_name.str.split('_')
benchmarks['device'] = name_parts.str[0]
benchmarks['type'] = name_parts.str[1].fillna('range')
benchmarks['threading'] = 'multi'
benchmarks.loc[benchmarks['type'] == 'single', ['threading']] = benchmarks['type']
benchmarks.loc[benchmarks['type'] == 'single', ['type']] = 'range'
benchmarks.loc[benchmarks['type'] == 'multi', ['type']] = 'range'

time_filter = benchmarks['time_unit'] == 'ms'
benchmarks.loc[time_filter, ['real_time']] /= 1000
benchmarks.loc[time_filter, ['cpu_time']] /= 1000
benchmarks.loc[time_filter, ['time_unit']] = 's'
benchmarks = benchmarks[['device', 'type', 'threading', 'k', 'repetitions', 'repetition_index', 'iterations', 'real_time', 'cpu_time', 'time_unit']]

metrics = dataset_aggr
bm_name = metrics['name'].str.split('/').str[1]
metrics['k'] = metrics['name'].str.split('/').str[2].str.split('_').str[0]
name_parts = bm_name.str.split('_')
metrics['device'] = name_parts.str[0]
metrics['type'] = name_parts.str[1].fillna('range')
metrics['threading'] = 'multi'
metrics.loc[metrics['type'] == 'single', ['threading']] = metrics['type']
metrics.loc[metrics['type'] == 'single', ['type']] = 'range'
metrics.loc[metrics['type'] == 'multi', ['type']] = 'range'

time_filter_m = (metrics['time_unit'] == "ms") & (metrics['aggregate_unit'] == "time")
metrics.loc[time_filter_m, 'real_time'] /= 1000
metrics.loc[time_filter_m, 'cpu_time'] /= 1000
metrics.loc[metrics['time_unit'] == "ms", 'time_unit'] = 's'
metrics = metrics[['device', 'type', 'threading', 'k', 'repetitions', 'aggregate_name', 'aggregate_unit', 'iterations', 'real_time', 'cpu_time', 'time_unit']]

benchmarks.loc[(benchmarks['device'] == "gpu") & (benchmarks['type'] == "range"), ['tag']] = 'gpu'
metrics.loc[(metrics['device'] == "gpu") & (metrics['type'] == "range"), ['tag']] = 'gpu'
benchmarks.loc[(benchmarks['device'] == "cpu") & (benchmarks['type'] == "range"), ['tag']] = benchmarks['device'] + '-' + benchmarks['threading']
metrics.loc[(metrics['device'] == "cpu") & (metrics['type'] == "range"), ['tag']] = metrics['device'] + '-' + metrics['threading']
benchmarks.loc[(benchmarks['type'] == "poly"), ['tag']] = benchmarks['device'] + '-' 'polynomial'
metrics.loc[(metrics['type'] == "poly"), ['tag']] = metrics['device'] + '-' + 'polynomial'

benchmarks['k'] = pd.to_numeric(benchmarks['k'], errors='coerce')
metrics['k'] = pd.to_numeric(metrics['k'], errors='coerce')

benchmarks.to_csv('benchmarks.csv')
metrics.to_csv('metrics.csv')
