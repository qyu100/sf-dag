# Copyright(C) Facebook, Inc. and its affiliates.
from bisect import bisect_right
from csv import writer
from datetime import datetime
from glob import glob
from os import makedirs
from os.path import join
from re import findall, search

import numpy as np

if not hasattr(np, 'Inf'):
    np.Inf = np.inf

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from benchmark.utils import PathMaker


class RecoveryError(Exception):
    pass


class RecoveryPlotter:
    def __init__(
        self,
        directory='logs',
        window=5.0,
        step=0.2,
        duration=60.0,
        label='Opt-Dispersed-Simple-IT',
        color='tab:green',
    ):
        self.directory = directory
        self.window = float(window)
        self.step = float(step)
        self.duration = float(duration)
        self.label = label
        self.color = color

    def run(self):
        logs = self._load_logs(self.directory)
        tx_size = self._transaction_size(logs)
        proposals = self._parse_proposals(logs)
        commits_by_digest = self._parse_commits(logs)
        sizes = self._parse_sizes(logs)
        crash_time = self._parse_fault_time(logs)

        if not commits_by_digest:
            raise RecoveryError('No committed blocks found in logs')

        start_time = min(proposals) if proposals else min(
            min(x) for x in commits_by_digest.values()
        )
        crash_offset = None if crash_time is None else crash_time - start_time
        commit_events = self._half_commit_events(commits_by_digest, sizes, tx_size, len(logs))
        if not commit_events:
            raise RecoveryError('No committed blocks reached half-committee visibility')

        points = self._sliding_tps(commit_events, start_time)
        csv_file = self._write_csv(points, crash_offset)
        pdf_file, png_file = self._plot(points, crash_offset)

        return (
            f'Recovery plot written to {pdf_file} and {png_file}\n'
            f'Recovery data written to {csv_file}\n'
            f'Fault time: {"n/a" if crash_offset is None else f"{crash_offset:.3f} s"}\n'
            f'Window: {self.window:.3f} s, step: {self.step:.3f} s'
        )

    def _load_logs(self, directory):
        files = sorted(glob(join(directory, 'primary-*.log')))
        if not files:
            files = sorted(glob(join(directory, 'logs', 'primary-*.log')))
        if not files:
            raise RecoveryError(f'No primary logs found in {directory}')

        logs = []
        for filename in files:
            with open(filename, 'r') as f:
                logs.append(f.read())
        return logs

    def _to_posix(self, value):
        return datetime.timestamp(datetime.fromisoformat(value.replace('Z', '+00:00')))

    def _transaction_size(self, logs):
        for log in logs:
            match = search(r'Transaction size .* (\d+)', log)
            if match:
                return int(match.group(1))
        raise RecoveryError('Could not find transaction size in primary logs')

    def _parse_proposals(self, logs):
        timestamps = []
        for log in logs:
            timestamps.extend(
                self._to_posix(t) for t in findall(r'\[(.*Z) .* Created [^ ]+', log)
            )
        return timestamps

    def _parse_commits(self, logs):
        commits = {}
        for log in logs:
            for timestamp, digest in findall(r'\[(.*Z) .* Committed ([^ ]+)', log):
                commits.setdefault(digest, []).append(self._to_posix(timestamp))
        return commits

    def _parse_sizes(self, logs):
        sizes = {}
        for log in logs:
            for digest, size in findall(r'Header ([^ ]+) contains (\d+) B', log):
                sizes[digest] = int(size)
        return sizes

    def _parse_fault_time(self, logs):
        faults = []
        for log in logs:
            for timestamp in findall(
                r'\[(.*Z) .* BENCH event=(?:crash|crash_time|proposal_skipped) ', log
            ):
                faults.append(self._to_posix(timestamp))
        return min(faults) if faults else None

    def _half_commit_events(self, commits_by_digest, sizes, tx_size, primary_count):
        half_index = max(0, (primary_count + 1) // 2 - 1)
        events = []
        for digest, timestamps in commits_by_digest.items():
            timestamps = sorted(timestamps)
            if len(timestamps) <= half_index:
                continue
            size = sizes.get(digest)
            if size is None:
                continue
            events.append((timestamps[half_index], size / tx_size))
        return sorted(events)

    def _sliding_tps(self, commit_events, start_time):
        end_offset = self.duration
        if end_offset <= 0:
            end_offset = max(t - start_time for t, _ in commit_events)

        times = [t for t, _ in commit_events]
        prefix = [0.0]
        for _, txns in commit_events:
            prefix.append(prefix[-1] + txns)

        points = []
        t = 0.0
        while t <= end_offset + 1e-9:
            left_time = start_time + max(0.0, t - self.window)
            right_time = start_time + t
            left = bisect_right(times, left_time)
            right = bisect_right(times, right_time)
            txns = prefix[right] - prefix[left]
            points.append((t, txns / self.window))
            t += self.step
        return points

    def _write_csv(self, points, crash_offset):
        makedirs(PathMaker.plots_path(), exist_ok=True)
        filename = PathMaker.plot_file('recovery-tps', 'csv')
        with open(filename, 'w', newline='') as f:
            out = writer(f)
            out.writerow(['time_s', 'throughput_tps', 'throughput_ktps', 'crash_time_s'])
            for t, tps in points:
                out.writerow([f'{t:.3f}', f'{tps:.6f}', f'{tps / 1000:.6f}', crash_offset])
        return filename

    def _plot(self, points, crash_offset):
        makedirs(PathMaker.plots_path(), exist_ok=True)

        xs = [t for t, _ in points]
        ys = [tps / 1000 for _, tps in points]

        plt.figure(figsize=(10, 6))
        plt.rcParams['font.weight'] = 'bold'
        plt.rcParams['axes.labelweight'] = 'bold'
        plt.rcParams['axes.titleweight'] = 'bold'
        plt.rcParams['figure.titleweight'] = 'bold'
        plt.rcParams['font.family'] = 'sans-serif'

        plt.plot(xs, ys, label=self.label, linewidth=4, color=self.color)
        if crash_offset is not None:
            plt.axvline(
                crash_offset,
                color='black',
                linestyle='--',
                linewidth=3,
                label='Skipped Proposal',
            )

        plt.xlabel('Time (s)', fontsize=26, fontweight='bold')
        plt.ylabel('Throughput (KTps)', fontsize=26, fontweight='bold')
        plt.xticks(fontweight='bold')
        plt.yticks(fontweight='bold')
        plt.tick_params(axis='both', which='major', labelsize=24)
        plt.xlim(left=0, right=max(xs) if xs else self.duration)
        plt.ylim(bottom=0)
        plt.grid(True, linestyle='--')
        plt.legend(loc='best', prop={'weight': 'bold', 'size': 24})
        plt.tight_layout()

        pdf_file = PathMaker.plot_file('recovery-tps', 'pdf')
        png_file = PathMaker.plot_file('recovery-tps', 'png')
        plt.savefig(pdf_file, format='pdf', bbox_inches='tight')
        plt.savefig(png_file, format='png', bbox_inches='tight')
        plt.close()
        return pdf_file, png_file
