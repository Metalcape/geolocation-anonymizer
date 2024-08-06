#! /bin/bash

./main.out --type=st --benchmark_out=results/cpu_single_threaded.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20
./main.out --type=mt --benchmark_out=results/cpu_multi_threaded.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20