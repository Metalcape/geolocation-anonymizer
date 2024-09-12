#! /bin/bash

./main.out --type=st --benchmark_out=results/cpu_single_threaded.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20
./main.out --type=mt --benchmark_out=results/cpu_multi_threaded.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=poly --benchmark_out=results/cpu_multi_threaded_poly.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20
./main.out --type=gpu_st --benchmark_out=results/gpu_single_threaded.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_mt --benchmark_out=results/gpu_multi_threaded.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_range --benchmark_out=results/gpu_range.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_poly --benchmark_out=results/gpu_polynomial.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20
