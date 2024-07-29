#pragma once

#include <SEAL-4.1/seal/seal.h>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define N_MULT 20
#define POLY_MOD_DEG 15
#define PLAIN_MOD 65537
