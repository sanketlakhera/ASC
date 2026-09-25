"""Compare module and CLI performance against a base checkout on one runner.

With --candidate-bin, the candidate is the Rust CLI instead of a Python
checkout (M2 plan section 8): cli_findrefs runs `asc findrefs`, and the
rust_unit case pairs the reference script's 20 findrefs stages (base) with
`asc bench-findrefs` (candidate). A Rust metric must also have a lower
median than Python's, not only avoid a significant slowdown.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import zipfile

from performance_compare import compare_pairs

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'
EFFECT_FLOOR_PERCENT = 3.0
GATED_METRICS = {
    'unit/insn_locator',
    'unit/string_locator',
    'unit/code_scan',
    'unit/method_locator',
    'unit/field_locator',
    'unit/type_locator',
    'unit/method_ref_scan',
    'unit/field_ref_scan',
    'core/decompile',
    'cli_getclass/cli_getclass',
    'cli_findrefs/cli_findrefs',
}


def should_gate(metric, result):
    return metric in GATED_METRICS and result['regression']


def revision(root):
    return subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()


def _wrap_workload_test(root, directory, test_name):
    """Wrap a workload test file so old top-level imports (findrefs, utils, core, models)
    are rewritten to droidasc.asc_core.*, matching the current package structure."""
    import re
    from pathlib import Path
    workdir = directory if isinstance(directory, Path) else Path(directory)
    src = (workdir / test_name).read_text(encoding='utf-8')
    # Rewrite: `from findrefs.|from utils.|from core.|from models.`
    #       → `from droidasc.asc_core.\1.`
    src = re.sub(
        r'^from (findrefs|utils|core|models)\.',
        r'from droidasc.asc_core.\1.',
        src,
        flags=re.MULTILINE,
    )
    wrapper = workdir / f'_benchmark_{test_name}'
    wrapper.write_text(
        f'import sys\n'
        f'sys.path.insert(0, {str(root)!r})\n'
        f'{src}',
        encoding='utf-8',
    )
    return wrapper


def sample_command(root, directory, case, binary):
    """The command one sample runs and the kind of output it prints ('unit',
    'core' or a CLI case). binary is the Rust candidate, or None for Python."""
    if binary is not None and case == 'rust_unit':
        return [str(binary), 'bench-findrefs', 'classes.dex'], 'unit'
    if binary is not None and case == 'cli_findrefs':
        return [str(binary), 'findrefs', 'fixture.apk', '--threads', '1', '--debug', 'string', 'create'], case
    if case in ('unit', 'core', 'rust_unit'):
        # the Python side of rust_unit is the reference script, as for unit
        kind = 'core' if case == 'core' else 'unit'
        wrapper = _wrap_workload_test(root, directory, 'test.py' if kind == 'core' else 'test_findrefs.py')
        return [sys.executable, str(wrapper)], kind
    command = [sys.executable, str(root / 'main.py')]
    if case == 'cli_getclass':
        command += ['getclass', 'fixture.apk', 'com.google.android.material.timepicker.ClockFaceView', '--threads', '1', '--debug']
    else:
        command += ['findrefs', 'fixture.apk', '--threads', '1', '--debug', 'string', 'create']
    return command, case


def measure(root, directory, case, output, sample, binary=None):
    env = dict(os.environ, PYTHONPATH='', PYTHONHASHSEED='0')
    command, kind = sample_command(root, directory, case, binary)
    result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=30)
    (output / f'{case}-{sample}.stdout.log').write_text(result.stdout, encoding='utf-8')
    (output / f'{case}-{sample}.stderr.log').write_text(result.stderr, encoding='utf-8')
    if result.returncode:
        raise ValueError(f'{case} exited {result.returncode}; see {output}')
    if kind == 'unit':
        times = {key: float(value) for key, value in re.findall(r'\[DEBUG\] (\w+) Time: ([\d.]+) us', result.stdout)}
        answer = {key: int(value) for key, value in re.findall(r'\[DEBUG\] ([\w ]+): (\d+)\s*$', result.stdout, re.M)}
    elif kind == 'core':
        match = re.search(r'Total Execution Time in test.py: ([\d.]+) s', result.stdout)
        if match is None:
            raise ValueError('missing core timing')
        times = {'decompile': float(match[1]) * 1e6}
        answer = result.stdout.split('[INFO]')[0].strip()
    else:
        match = re.search(r'\[DEBUG\] Total Execution Time: ([\d.]+) us', result.stdout)
        if match is None:
            raise ValueError('missing CLI timing')
        times = {case: float(match[1])}
        answer = (result.stdout.split('-' * 50)[-1].strip() if case == 'cli_getclass' else
                  sorted(line for line in result.stdout.splitlines() if ' | ' in line))
    if not answer or (kind in ('core', 'cli_getclass') and 'class ClockFaceView' not in answer):
        raise ValueError(f'{case}: missing result')
    return times, answer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, default=ROOT)
    parser.add_argument('--samples', type=int, default=31)
    parser.add_argument('--cases', nargs='+', choices=('unit', 'core', 'cli_getclass', 'cli_findrefs', 'rust_unit'),
                        default=None)
    parser.add_argument('--candidate-bin', type=Path,
                        help='Rust asc binary as the candidate (cases cli_findrefs and rust_unit)')
    parser.add_argument('--output', type=Path, default=Path('artifacts/comparison'))
    args = parser.parse_args()
    if args.samples < 15:
        parser.error('at least 15 paired samples are required')
    if args.cases is None:
        args.cases = (['cli_findrefs', 'rust_unit'] if args.candidate_bin
                      else ['unit', 'core', 'cli_getclass', 'cli_findrefs'])
    if args.candidate_bin and set(args.cases) - {'cli_findrefs', 'rust_unit'}:
        parser.error('--candidate-bin compares only cli_findrefs and rust_unit')
    if 'rust_unit' in args.cases and not args.candidate_bin:
        parser.error('rust_unit needs --candidate-bin')
    binary = args.candidate_bin.resolve() if args.candidate_bin else None
    roots = {'base': args.baseline.resolve(), 'candidate': args.candidate.resolve()}
    affinity = None
    if hasattr(os, 'sched_getaffinity'):
        affinity = [min(os.sched_getaffinity(0))]
        os.sched_setaffinity(0, affinity)
    report = {'python': sys.version, 'platform': platform.platform(),
              'cpu_affinity': affinity, 'pythonhashseed': '0', 'samples': {}, 'errors': []}
    args.output.mkdir(parents=True, exist_ok=True)
    for side in roots:
        (args.output / side).mkdir(exist_ok=True)
    try:
        report['revisions'] = {side: revision(root) for side, root in roots.items()}
        contract = json.loads((FIXTURES / 'reference-baseline.json').read_text())
        archive = FIXTURES / 'reference-workload.zip'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != contract['archive_sha256']:
            raise ValueError('reference archive identity mismatch')
        with tempfile.TemporaryDirectory() as directory:
            with zipfile.ZipFile(archive) as source:
                if set(source.namelist()) != {'classes.dex', 'test.py', 'test_findrefs.py'}:
                    raise ValueError('unexpected archive members')
                source.extractall(directory)
            with zipfile.ZipFile(Path(directory) / 'fixture.apk', 'w', compression=zipfile.ZIP_DEFLATED) as apk:
                apk.write(Path(directory) / 'classes.dex', 'classes.dex')
            for case in args.cases:
                expected_keys = (set(contract['findrefs_times_us']) if case in ('unit', 'rust_unit')
                                 else {'decompile' if case == 'core' else case})
                samples = {key: {'base': [], 'candidate': []} for key in expected_keys}
                report['samples'][case] = samples
                for index in range(-1, args.samples):
                    answers = {}
                    order = ('base', 'candidate') if index % 2 == 0 else ('candidate', 'base')
                    for side in order:
                        times, answers[side] = measure(roots[side], directory, case, args.output / side, index,
                                                       binary if side == 'candidate' else None)
                        if times.keys() != expected_keys:
                            raise ValueError(f'{case}: missing or unexpected timing metrics')
                        if case in ('unit', 'rust_unit') and answers[side] != contract['findrefs_counts']:
                            raise ValueError(f'{side}: reference count mismatch')
                        if index >= 0:
                            for key, value in times.items():
                                samples[key][side].append(value)
                    if answers['base'] != answers['candidate']:
                        raise ValueError(f'{case}: base/candidate outputs differ')
        metric_count = len(GATED_METRICS)
        report['comparisons'] = {}
        report['gated_metrics'] = sorted(GATED_METRICS)
        report['effect_floor_percent'] = EFFECT_FLOOR_PERCENT
        for case, metrics in report['samples'].items():
            for key, values in metrics.items():
                metric = f'{case}/{key}'
                result = compare_pairs(values['base'], values['candidate'], metric_count,
                                       effect_floor_percent=EFFECT_FLOOR_PERCENT)
                rust = binary is not None
                result['gated'] = rust or metric in GATED_METRICS
                report['comparisons'][metric] = result
                if (rust and result['regression']) or (not rust and should_gate(metric, result)):
                    report['errors'].append(
                        f'{metric}: significant material slowdown '
                        f'({result["paired_median_change_percent"]:+.2f}%)'
                    )
                elif rust and result['candidate_median'] >= result['base_median']:
                    report['errors'].append(
                        f'{metric}: Rust median {result["candidate_median"]:.1f} us is not below '
                        f'Python {result["base_median"]:.1f} us')
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        report['errors'].append(str(error))
    (args.output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'samples'}, indent=2))
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    sys.exit(main())
