#!/usr/bin/env python3
"""Benchmark SciPy banded Cholesky on an exported SSV problem.

Matrix Market parsing, conversion to LAPACK lower-band storage, and input
copies are deliberately outside the timed regions.  The reported direct-solve
time is the sum of the median factorization and triangular-solve times.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

import numpy as np
import scipy
from scipy import io as scipy_io
from scipy.linalg import cho_solve_banded, cholesky_banded


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--rhs", type=Path, required=True)
    parser.add_argument("--half-bandwidth", type=int, required=True)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=20)
    return parser.parse_args()


def lower_band(matrix, half_bandwidth: int) -> np.ndarray:
    matrix = matrix.tocoo(copy=False)
    if matrix.shape[0] != matrix.shape[1]:
        raise ValueError(f"matrix is not square: {matrix.shape}")

    lower = matrix.row >= matrix.col
    offsets = matrix.row[lower] - matrix.col[lower]
    if offsets.size and int(offsets.max()) > half_bandwidth:
        raise ValueError(
            f"observed half-bandwidth {int(offsets.max())} exceeds "
            f"requested {half_bandwidth}"
        )

    # LAPACK's lower-band layout stores A[i, j] at ab[i - j, j].
    band = np.zeros((half_bandwidth + 1, matrix.shape[0]), order="F")
    band[offsets, matrix.col[lower]] = matrix.data[lower]
    return band


def time_factorization(
    band: np.ndarray, warmups: int, repetitions: int
) -> tuple[np.ndarray, list[float]]:
    factor = None
    timings = []
    for repetition in range(warmups + repetitions):
        work = band.copy(order="F")
        start = time.perf_counter_ns()
        factor = cholesky_banded(
            work, lower=True, overwrite_ab=True, check_finite=False
        )
        elapsed = (time.perf_counter_ns() - start) * 1.0e-9
        if repetition >= warmups:
            timings.append(elapsed)
    assert factor is not None
    return factor, timings


def time_triangular_solve(
    factor: np.ndarray, rhs: np.ndarray, warmups: int, repetitions: int
) -> tuple[np.ndarray, list[float]]:
    solution = None
    timings = []
    for repetition in range(warmups + repetitions):
        work = rhs.copy()
        start = time.perf_counter_ns()
        solution = cho_solve_banded(
            (factor, True), work, overwrite_b=True, check_finite=False
        )
        elapsed = (time.perf_counter_ns() - start) * 1.0e-9
        if repetition >= warmups:
            timings.append(elapsed)
    assert solution is not None
    return solution, timings


def summary(samples: list[float]) -> dict[str, float]:
    return {
        "minimum_seconds": min(samples),
        "median_seconds": statistics.median(samples),
        "maximum_seconds": max(samples),
    }


def main() -> None:
    args = parse_args()
    if args.half_bandwidth < 0:
        raise ValueError("half-bandwidth must be nonnegative")
    if args.warmups < 0 or args.repetitions <= 0:
        raise ValueError("warmups must be nonnegative and repetitions positive")

    matrix = scipy_io.mmread(args.matrix).tocsr()
    asymmetry = matrix - matrix.transpose()
    asymmetry.eliminate_zeros()
    if asymmetry.nnz:
        raise ValueError("banded Cholesky requires an exactly symmetric matrix")
    rhs = np.asarray(scipy_io.mmread(args.rhs), dtype=np.float64).reshape(-1)
    if rhs.size != matrix.shape[0]:
        raise ValueError(
            f"RHS length {rhs.size} does not match dimension {matrix.shape[0]}"
        )

    band = lower_band(matrix, args.half_bandwidth)
    factor, factor_timings = time_factorization(
        band, args.warmups, args.repetitions
    )
    solution, solve_timings = time_triangular_solve(
        factor, rhs, args.warmups, args.repetitions
    )

    rhs_norm = np.linalg.norm(rhs)
    if rhs_norm == 0.0:
        raise ValueError("relative residual is undefined for a zero RHS")
    relative_residual = float(np.linalg.norm(matrix @ solution - rhs) / rhs_norm)
    factor_summary = summary(factor_timings)
    solve_summary = summary(solve_timings)
    result = {
        "numpy_version": np.__version__,
        "scipy_version": scipy.__version__,
        "dimension": matrix.shape[0],
        "structural_nonzeros": matrix.nnz,
        "half_bandwidth": args.half_bandwidth,
        "band_storage_bytes": band.nbytes,
        "warmups": args.warmups,
        "repetitions": args.repetitions,
        "factorization": factor_summary,
        "triangular_solve": solve_summary,
        "median_direct_solve_seconds": (
            factor_summary["median_seconds"] + solve_summary["median_seconds"]
        ),
        "relative_residual": relative_residual,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
