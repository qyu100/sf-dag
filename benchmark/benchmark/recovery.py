# Copyright(C) Facebook, Inc. and its affiliates.
from bisect import bisect_left, bisect_right
from csv import DictReader, writer
from datetime import datetime
from glob import glob
from json import load
from os import environ, makedirs
from os.path import basename, join, splitext
from re import findall, search

environ.setdefault('MPLCONFIGDIR', '/tmp/matplotlib')
environ.setdefault('XDG_CACHE_HOME', '/tmp')

import numpy as np

if not hasattr(np, 'Inf'):
    np.Inf = np.inf

import matplotlib.pyplot as plt

from benchmark.utils import PathMaker


class RecoveryError(Exception):
    pass


RECOVERY_COLORS = ['tab:green', 'tab:red', 'tab:orange', 'tab:cyan', 'tab:blue', 'tab:purple']


def configure_recovery_plot_style():
    plt.rcParams['font.weight'] = 'bold'
    plt.rcParams['axes.labelweight'] = 'bold'
    plt.rcParams['axes.titleweight'] = 'bold'
    plt.rcParams['figure.titleweight'] = 'bold'
    plt.rcParams['font.family'] = 'sans-serif'


def finish_recovery_plot():
    plt.xlabel('Time (s)', fontsize=26, fontweight='bold')
    plt.ylabel('Throughput (KTps)', fontsize=26, fontweight='bold')
    plt.xticks(fontweight='bold')
    plt.yticks(fontweight='bold')
    plt.tick_params(axis='both', which='major', labelsize=24)
    plt.xlim(left=0)
    plt.ylim(bottom=0)
    plt.grid(True, linestyle='--')
    plt.legend(
        loc='lower right',
        prop={'weight': 'bold', 'size': 24},
        columnspacing=1.5,
        handletextpad=0.6,
    )
    plt.tight_layout()


class RecoveryPlotter:
    def __init__(
        self,
        logs_dir=PathMaker.logs_path(),
        committee_file=PathMaker.committee_file(),
        parameters_file=PathMaker.parameters_file(),
        window=2.4,
        step=0.2,
        before=10.0,
        after=20.0,
        full=True,
        output='recovery-tps',
        label='Throughput',
    ):
        self.logs_dir = logs_dir
        self.committee_file = committee_file
        self.parameters_file = parameters_file
        self.window = float(window)
        self.step = float(step)
        self.before = float(before)
        self.after = float(after)
        self.full = bool(full)
        self.output = output
        self.label = label

        if self.window <= 0 or self.step <= 0:
            raise RecoveryError('Window and step must be positive')

    @staticmethod
    def _to_posix(string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    @staticmethod
    def _merge_earliest(items):
        merged = {}
        for key, value in items:
            if key not in merged or merged[key] > value:
                merged[key] = value
        return merged

    def _faulty_author(self):
        try:
            with open(self.parameters_file, 'r') as f:
                parameters = load(f)
                crash_author = parameters.get('crash_author')
                if crash_author:
                    return crash_author
        except OSError:
            pass

        try:
            with open(self.committee_file, 'r') as f:
                committee = load(f)
        except OSError as e:
            raise RecoveryError(f'Failed to read committee file: {e}')

        faulty = [
            name
            for name, authority in committee['authorities'].items()
            if not authority.get('is_honest', True)
        ]
        if not faulty:
            raise RecoveryError('Committee has no faulty authority')
        return faulty[0]

    def _load_primary_logs(self):
        filenames = sorted(glob(join(self.logs_dir, 'primary-*.log')))
        if not filenames:
            raise RecoveryError(f'No primary logs found in {self.logs_dir}')

        logs = []
        for filename in filenames:
            with open(filename, 'r') as f:
                logs.append(f.read())
        return logs

    def _parse_logs(self, logs):
        commits = []
        sizes = {}
        round_starts = []
        timeout_sents = []
        crash_starts = []
        log_times = []
        tx_size = None
        max_header_delay = None

        for log in logs:
            log_times.extend(self._to_posix(ts) for ts in findall(r'\[(.*Z) ', log))

            tmp = findall(r'\[(.*Z) .* Committed ([^ ]+)', log)
            commits.extend((digest, self._to_posix(ts)) for ts, digest in tmp)

            tmp = findall(r'Header ([^ ]+) contains (\d+) B', log)
            sizes.update({digest: int(size) for digest, size in tmp})

            if tx_size is None:
                match = search(r'Transaction size .* (\d+)', log)
                if match:
                    tx_size = int(match.group(1))

            if max_header_delay is None:
                match = search(r'Max header delay .* (\d+)', log)
                if match:
                    max_header_delay = int(match.group(1)) / 1_000

            tmp = findall(
                r'\[(.*Z) .* BENCH event=round_start round=(\d+) leader=([^ ]+) node=([^ \n]+)',
                log,
            )
            round_starts.extend(
                (int(round), leader, self._to_posix(ts), node)
                for ts, round, leader, node in tmp
            )

            tmp = findall(
                r'\[(.*Z) .* BENCH event=timeout_sent round=(\d+) node=([^ \n]+)',
                log,
            )
            timeout_sents.extend(
                (int(round), self._to_posix(ts), node)
                for ts, round, node in tmp
            )

            tmp = findall(
                r'\[(.*Z) .* BENCH event=crash_start node=([^ ]+) round=(\d+) proposal_index=(\d+) duration_ms=(\d+) source=([^ \n]+)',
                log,
            )
            crash_starts.extend(
                (self._to_posix(ts), node, int(round), int(index), int(duration), source)
                for ts, node, round, index, duration, source in tmp
            )

        commits = self._merge_earliest(commits)

        if tx_size is None:
            raise RecoveryError('Could not parse transaction size from primary logs')
        if not commits:
            raise RecoveryError('No commits found in primary logs')
        if not log_times:
            raise RecoveryError('Could not parse experiment start time from primary logs')

        return {
            'commits': commits,
            'sizes': sizes,
            'round_starts': round_starts,
            'timeout_sents': timeout_sents,
            'crash_starts': crash_starts,
            'start_time': min(log_times),
            'end_time': max(log_times),
            'tx_size': tx_size,
            'max_header_delay': max_header_delay,
        }

    def _anchor(self, parsed, faulty_author):
        if parsed['crash_starts']:
            ts, _, round, _, _, _ = min(parsed['crash_starts'], key=lambda x: x[0])
            return ts, round

        candidates = [
            (ts, round)
            for round, leader, ts, _ in parsed['round_starts']
            if leader == faulty_author
        ]
        if candidates:
            return min(candidates)

        timeout_sents = parsed['timeout_sents']
        if timeout_sents and parsed['max_header_delay'] is not None:
            round, ts, _ = min(timeout_sents, key=lambda x: x[1])
            return ts - parsed['max_header_delay'], round

        raise RecoveryError(
            'Could not locate faulty leader round. Re-run with the new BENCH round_start logs.'
        )

    def _series(self, parsed, anchor_time, anchor_round):
        commits = []
        for digest, ts in parsed['commits'].items():
            size = parsed['sizes'].get(digest)
            if size is None:
                continue
            commits.append((ts, size / parsed['tx_size']))

        if not commits:
            raise RecoveryError('No committed headers with known sizes found')

        commits.sort()
        times = [x[0] for x in commits]
        prefix = [0.0]
        for _, txns in commits:
            prefix.append(prefix[-1] + txns)

        experiment_start = parsed['start_time']
        if self.full:
            start = experiment_start
            end = parsed['end_time']
        else:
            start = max(experiment_start, anchor_time - self.before)
            end = anchor_time + self.after
        points = []
        t = start
        while t <= end + 1e-9:
            left = bisect_left(times, t - self.window)
            right = bisect_right(times, t)
            txns = prefix[right] - prefix[left]
            points.append({
                'elapsed_time_sec': t - experiment_start,
                'crash_elapsed_time_sec': anchor_time - experiment_start,
                'time_sec': t,
                'committed_tx_window': txns,
                'tps': txns / self.window,
                'window_sec': self.window,
                'anchor_round': anchor_round,
            })
            t += self.step
        return points

    def _write_csv(self, points):
        makedirs(PathMaker.results_path(), exist_ok=True)
        filename = join(PathMaker.results_path(), f'{self.output}.csv')
        with open(filename, 'w', newline='') as f:
            out = writer(f)
            out.writerow([
                'elapsed_time_sec',
                'crash_elapsed_time_sec',
                'time_sec',
                'committed_tx_window',
                'tps',
                'window_sec',
                'anchor_round',
            ])
            for point in points:
                out.writerow([
                    f"{point['elapsed_time_sec']:.3f}",
                    f"{point['crash_elapsed_time_sec']:.3f}",
                    f"{point['time_sec']:.3f}",
                    f"{point['committed_tx_window']:.3f}",
                    f"{point['tps']:.3f}",
                    f"{point['window_sec']:.3f}",
                    point['anchor_round'],
                ])
        return filename

    def _plot(self, points, parsed, anchor_time, anchor_round):
        makedirs(PathMaker.plots_path(), exist_ok=True)

        xs = [x['elapsed_time_sec'] for x in points]
        ys = [x['tps'] / 1_000 for x in points]
        crash_x = anchor_time - parsed['start_time']

        plt.figure(figsize=(10, 6))
        configure_recovery_plot_style()

        plt.plot(
            xs,
            ys,
            label=self.label,
            linewidth=4,
            color='tab:green',
        )
        plt.axvline(
            crash_x,
            color='black',
            linestyle='--',
            linewidth=3,
            label='Crashed leader',
        )

        finish_recovery_plot()

        outputs = []
        for ext in ['png', 'pdf']:
            filename = PathMaker.plot_file(self.output, ext)
            plt.savefig(filename, bbox_inches='tight')
            outputs.append(filename)
        plt.close()
        return outputs

    def run(self):
        faulty_author = self._faulty_author()
        logs = self._load_primary_logs()
        parsed = self._parse_logs(logs)
        anchor_time, anchor_round = self._anchor(parsed, faulty_author)
        points = self._series(parsed, anchor_time, anchor_round)
        csv_file = self._write_csv(points)
        plots = self._plot(points, parsed, anchor_time, anchor_round)
        return {
            'faulty_author': faulty_author,
            'anchor_round': anchor_round,
            'anchor_time': anchor_time,
            'csv': csv_file,
            'plots': plots,
        }


class RecoveryCsvPlotter:
    def __init__(self, csv_files, labels=None, colors=None, output='recovery-tps-compare'):
        self.csv_files = [x.strip() for x in csv_files if x.strip()]
        if not self.csv_files:
            raise RecoveryError('At least one recovery CSV file is required')

        if labels:
            self.labels = [x.strip() for x in labels if x.strip()]
        else:
            self.labels = [
                splitext(basename(filename))[0]
                for filename in self.csv_files
            ]

        if len(self.labels) != len(self.csv_files):
            raise RecoveryError('The number of labels must match the number of CSV files')

        self.colors = [x.strip() for x in colors if x.strip()] if colors else RECOVERY_COLORS
        if len(self.colors) < len(self.csv_files):
            raise RecoveryError('The number of colors must be at least the number of CSV files')

        self.output = output

    @staticmethod
    def _read_csv(filename):
        xs = []
        ys = []
        crash_x = None
        with open(filename, 'r') as f:
            for row in DictReader(f):
                xs.append(float(row['elapsed_time_sec']))
                ys.append(float(row['tps']) / 1_000)
                if crash_x is None and row.get('crash_elapsed_time_sec'):
                    crash_x = float(row['crash_elapsed_time_sec'])

        if not xs:
            raise RecoveryError(f'No points found in {filename}')
        return xs, ys, crash_x

    def run(self):
        makedirs(PathMaker.plots_path(), exist_ok=True)
        plt.figure(figsize=(10, 6))
        configure_recovery_plot_style()

        for i, (filename, label) in enumerate(zip(self.csv_files, self.labels)):
            xs, ys, crash_x = self._read_csv(filename)
            color = self.colors[i]
            plt.plot(
                xs,
                ys,
                label=label,
                linewidth=4,
                color=color,
            )
            if crash_x is not None:
                plt.axvline(
                    crash_x,
                    color=color,
                    linestyle='--',
                    linewidth=3,
                    label=f'{label} crash',
                )

        finish_recovery_plot()

        outputs = []
        for ext in ['png', 'pdf']:
            filename = PathMaker.plot_file(self.output, ext)
            plt.savefig(filename, bbox_inches='tight')
            outputs.append(filename)
        plt.close()
        return outputs
