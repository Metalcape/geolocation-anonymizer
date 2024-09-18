#! /bin/bash

./main.out --type=cpu_encode --benchmark_out=results/cpu_encode.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=cpu_decode --benchmark_out=results/cpu_decode.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_encode --benchmark_out=results/gpu_encode.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_decode --benchmark_out=results/gpu_decode.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=cpu_encrypt --benchmark_out=results/cpu_encrypt.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=cpu_decrypt --benchmark_out=results/cpu_decrypt.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_encrypt --benchmark_out=results/gpu_encrypt.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_decrypt --benchmark_out=results/gpu_decrypt.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=st --benchmark_out=results/cpu_single_threaded.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20
./main.out --type=mt --benchmark_out=results/cpu_multi_threaded.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=20
./main.out --type=gpu --benchmark_out=results/gpu.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_range --benchmark_out=results/gpu_range.json --benchmark_out_format=json --benchmark_time_unit=ms --benchmark_repetitions=20
./main.out --type=gpu_poly --benchmark_out=results/gpu_polynomial.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=10
./main.out --type=poly --benchmark_out=results/cpu_polynomial.json --benchmark_out_format=json --benchmark_time_unit=s --benchmark_repetitions=10
