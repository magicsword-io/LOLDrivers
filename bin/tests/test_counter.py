"""Exercise badge publishing against isolated local Git remotes, never GitHub."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


BIN = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('counter', BIN / 'gen-counter.py')
counter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(counter)


def readme(count):
    return f'# LOLDrivers\n\n![Drivers](https://img.shields.io/badge/Drivers-{count}-flat.svg)\n\nKeep this documentation.\n'


class CounterGenerationTests(unittest.TestCase):
    def test_counts_samples_and_preserves_github_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'one.yaml').write_text('KnownVulnerableSamples: [{}, {}]\n')
            (root / 'two.yaml').write_text('KnownVulnerableSamples: [{}]\n')
            (root / 'empty.yaml').write_text('')
            (root / 'other.yaml').write_text('Tags: [example]\n')
            output = root / 'output.txt'
            result = subprocess.run(
                [sys.executable, str(BIN / 'gen-counter.py'), '-f', folder],
                env={**os.environ, 'GITHUB_OUTPUT': str(output)},
                text=True, capture_output=True, check=True,
            )
            self.assertEqual(result.stdout.strip(), counter.badge_url(folder))
            self.assertEqual(output.read_text(), f'result={counter.badge_url(folder)}\n')
            self.assertIn('Drivers-3-flat.svg', result.stdout)

    def test_readme_update_preserves_other_text_and_rejects_missing_badge(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'README.md'
            path.write_text(readme(1))
            counter.update_readme(path, 'https://img.shields.io/badge/Drivers-2-flat.svg')
            self.assertEqual(path.read_text(), readme(2))
            path.write_text('# Missing badge\n')
            with self.assertRaises(ValueError):
                counter.update_readme(path, 'https://img.shields.io/badge/Drivers-2-flat.svg')
            self.assertEqual(path.read_text(), '# Missing badge\n')


class CounterPublishingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='counter tests ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / 'origin.git'
        self.writer = self.root / 'writer'
        self.worker = self.root / 'worker'
        self.env = {
            **os.environ,
            'PATH': f'{Path(sys.executable).parent}{os.pathsep}{os.environ["PATH"]}',
            'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_CONFIG_NOSYSTEM': '1',
            'RUNNER_TEMP': str(self.root),
        }
        self.env.pop('GITHUB_OUTPUT', None)
        self.git(self.root, 'init', '--bare', '--initial-branch=main', str(self.remote))
        self.git(self.root, 'clone', str(self.remote), str(self.writer))
        self.git(self.writer, 'config', 'user.name', 'Test writer')
        self.git(self.writer, 'config', 'user.email', 'test@example.invalid')
        (self.writer / 'yaml').mkdir()
        self.write_samples(2)
        (self.writer / 'README.md').write_text(readme(0))
        self.commit_writer('Initial catalog')
        self.git(self.writer, 'push', 'origin', 'main')
        # Match actions/checkout's shallow checkout, including worktree use.
        self.git(self.root, 'clone', '--depth=1', self.remote.as_uri(), str(self.worker))

    def git(self, cwd, *args):
        return subprocess.run(
            ['git', '-C', str(cwd), *args], env=self.env,
            text=True, capture_output=True, check=True,
        ).stdout.strip()

    def write_samples(self, count):
        (self.writer / 'yaml/driver.yaml').write_text(
            yaml.safe_dump({'KnownVulnerableSamples': [{} for _ in range(count)]})
        )

    def commit_writer(self, message):
        self.git(self.writer, 'add', '.')
        self.git(self.writer, 'commit', '-m', message)

    def publish(self, success=True):
        result = subprocess.run(
            ['bash', str(BIN / 'publish-counter.sh')], cwd=self.worker,
            env=self.env, text=True, capture_output=True, timeout=60,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.root.glob('loldrivers-counter.*')), [])
        self.assertEqual(self.git(self.worker, 'worktree', 'list', '--porcelain').count('worktree '), 1)
        return result

    def install_race(self, repeat=False):
        # Advance the remote after the counter has committed but before it pushes.
        # Git's hook environment must not leak into the competing clone.
        hook = self.worker / '.git/hooks/pre-push'
        hook.write_text(f'''#!{sys.executable}
import os
from pathlib import Path
import subprocess
marker = Path({str(self.root / 'raced')!r})
if {repeat!r} or not marker.exists():
    marker.touch()
    local = subprocess.check_output(['git', 'rev-parse', '--local-env-vars'], text=True).split()
    env = {{key: value for key, value in os.environ.items() if key not in local}}
    command = ['git', '-C', {str(self.writer)!r}]
    if {repeat!r}:
        subprocess.run(command + ['commit', '--allow-empty', '-m', 'Concurrent writer'], env=env, check=True)
    subprocess.run(command + ['push', 'origin', 'main'], env=env, check=True)
''')
        hook.chmod(0o755)

    def test_publishes_only_readme_and_keeps_the_callers_checkout(self):
        local_head = self.git(self.worker, 'rev-parse', 'HEAD')
        (self.worker / 'README.md').write_text('Local work in progress\n')
        (self.worker / 'notes.txt').write_text('Untracked local work\n')
        self.publish()
        self.assertEqual(self.git(self.remote, 'show', 'main:README.md'), readme(2).strip())
        self.assertEqual(self.git(self.remote, 'diff-tree', '--no-commit-id', '--name-only', '-r', 'main'), 'README.md')
        self.assertEqual(self.git(self.worker, 'rev-parse', 'HEAD'), local_head)
        self.assertEqual((self.worker / 'README.md').read_text(), 'Local work in progress\n')
        self.assertEqual((self.worker / 'notes.txt').read_text(), 'Untracked local work\n')

    def test_skips_commit_when_badge_is_current(self):
        (self.writer / 'README.md').write_text(readme(2))
        self.commit_writer('Current badge')
        self.git(self.writer, 'push', 'origin', 'main')
        before = self.git(self.remote, 'rev-parse', 'main')
        self.assertIn('no commit needed', self.publish().stdout)
        self.assertEqual(self.git(self.remote, 'rev-parse', 'main'), before)

    def test_racing_push_recounts_and_preserves_the_new_readme(self):
        self.write_samples(3)
        (self.writer / 'README.md').write_text(readme(0) + '\nConcurrent documentation update.\n')
        self.commit_writer('Add a sample and documentation')
        self.install_race()
        result = self.publish()
        self.assertIn('recounting', result.stdout)
        self.assertEqual(self.git(self.remote, 'show', 'main:README.md'), (readme(3) + '\nConcurrent documentation update.\n').strip())
        self.assertEqual(self.git(self.remote, 'rev-list', '--count', 'main'), '3')

    def test_concurrent_counter_winner_needs_no_extra_commit(self):
        (self.writer / 'README.md').write_text(readme(2))
        self.commit_writer('Another counter publishes first')
        winner = self.git(self.writer, 'rev-parse', 'HEAD')
        self.install_race()
        self.assertIn('no commit needed', self.publish().stdout)
        self.assertEqual(self.git(self.remote, 'rev-parse', 'main'), winner)

    def test_unrelated_push_rejection_is_not_reported_as_success(self):
        hook = self.remote / 'hooks/pre-receive'
        hook.write_text('#!/bin/sh\nexit 1\n')
        hook.chmod(0o755)
        result = self.publish(success=False)
        self.assertIn('without a concurrent main update', result.stderr)
        self.assertEqual(self.git(self.remote, 'rev-list', '--count', 'main'), '1')

    def test_retries_are_bounded_when_main_keeps_changing(self):
        self.install_race(repeat=True)
        result = self.publish(success=False)
        self.assertIn('after five concurrent main updates', result.stderr)
        self.assertEqual(self.git(self.remote, 'rev-list', '--count', 'main'), '6')
        self.assertEqual(self.git(self.remote, 'show', 'main:README.md'), readme(0).strip())


if __name__ == '__main__':
    unittest.main()
