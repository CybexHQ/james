"""Compiler reuse never reuses public-closure execution or private acceptance."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'
QUALIFIER = 'Qualify signed public closure through the candidate downloader'
FAKE_CARGO = r'''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
arguments = sys.argv[1:]
assert arguments[:5] == ['run', '--release', '--locked', '--bin', 'tiaris-nest-qualify-public-closure']
target = pathlib.Path(os.environ['CARGO_TARGET_DIR'])
target.mkdir(parents=True, exist_ok=True)
compiler = target / 'compiled-dependencies'
key = pathlib.Path(arguments[arguments.index('--trusted-public-key') + 1])
assert stat.S_IMODE(key.stat().st_mode) == 0o600
output = pathlib.Path(arguments[arguments.index('--output') + 1])
source = arguments[arguments.index('--source') + 1]
entry = {'compilerOutputReused': compiler.exists(), 'output': str(output), 'source': source}
with open(os.environ['TEST_INVOCATIONS'], 'a') as stream:
    stream.write(json.dumps(entry) + '\n')
compiler.write_text('reusable compiler output, never qualification evidence')
status = int(os.environ.get('TEST_CARGO_STATUS', '0'))
if status:
    raise SystemExit(status)
assert not output.exists()
output.write_text(json.dumps({'freshQualification': True, 'source': source}))
'''


def step_script(body, name):
    step = body.split('      - name: ' + name + '\n', 1)[1].split('\n      - name:', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


class PublicClosureCompilerCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.runner = self.root / 'runner-temp'
        self.runner.mkdir()
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        self.cache = self.root / 'persistent-target'
        binary = self.root / 'bin'
        binary.mkdir()
        (binary / 'cargo').write_text(FAKE_CARGO)
        (binary / 'cargo').chmod(0o755)
        body = WORKFLOW.read_text()
        self.cold = body.split('  release_cold_qualify:\n', 1)[1].split('  release_promote:\n', 1)[0]
        self.qualify = step_script(self.cold, QUALIFIER)
        self.cleanup = step_script(self.cold, 'Remove disposable workspace payloads')
        self.environment = {**os.environ,
            'PATH': str(binary) + os.pathsep + os.environ['PATH'],
            'RUNNER_TEMP': str(self.runner), 'GITHUB_WORKSPACE': str(self.workspace),
            'CARGO_TARGET_DIR': str(self.cache), 'GITHUB_RUN_ID': '42',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40,
            'GITHUB_REF_NAME': 'v0.2.66', 'TRUSTED_KEY': 'dummy-public-key',
            'TEST_INVOCATIONS': str(self.root / 'invocations.jsonl')}

    def run_step(self, script, **changes):
        return subprocess.run(['bash', '-c', script], cwd=self.workspace,
            env={**self.environment, **changes}, capture_output=True, text=True, timeout=10)

    def invocations(self):
        return [json.loads(line) for line in (self.root / 'invocations.jsonl').read_text().splitlines()]

    def test_protected_job_keeps_only_compiler_output_outside_attempt_evidence(self):
        environment = self.cold.split('    env:\n', 1)[1].split('    steps:\n', 1)[0]
        targets = re.findall(r'^      CARGO_TARGET_DIR: (.+)$', environment, re.MULTILINE)
        self.assertEqual(targets, ['/home/john/.local/state/tiaris-nest-ci-target/public-closure'])
        self.assertIn('environment: production-release-qualification', self.cold)
        self.assertIn('group: nest-nixos-production-qualification', self.cold)
        self.assertNotIn('CARGO_TARGET_DIR=', self.qualify)
        self.assertIn('tools/local-candidate.py published', self.cold)
        self.assertIn('release_acceptance.py', self.cold)

    def test_two_attempts_reuse_compiler_output_and_execute_new_qualification_each_time(self):
        first = self.run_step(self.qualify)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_output = self.runner / 'tiaris-nest-public-closure-42-1/tiaris-nest-public-closure-qualification.json'
        self.assertEqual(json.loads(first_output.read_text())['source'], 'a' * 40)
        self.assertFalse(first_output.with_name('release-public-key').exists())
        cleaned = self.run_step(self.cleanup)
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertFalse(first_output.parent.exists())
        self.assertTrue((self.cache / 'compiled-dependencies').is_file())
        second = self.run_step(self.qualify, GITHUB_RUN_ATTEMPT='2', GITHUB_SHA='b' * 40)
        self.assertEqual(second.returncode, 0, second.stderr)
        second_output = self.runner / 'tiaris-nest-public-closure-42-2/tiaris-nest-public-closure-qualification.json'
        self.assertEqual(json.loads(second_output.read_text())['source'], 'b' * 40)
        entries = self.invocations()
        self.assertEqual(len(entries), 2)
        self.assertEqual([entry['compilerOutputReused'] for entry in entries], [False, True])
        self.assertNotEqual(entries[0]['output'], entries[1]['output'])
        self.assertFalse(list(self.cache.glob('*qualification*')))

    def test_qualifier_failure_stops_even_with_populated_compiler_cache(self):
        first = self.run_step(self.qualify)
        self.assertEqual(first.returncode, 0, first.stderr)
        failed = self.run_step(self.qualify, GITHUB_RUN_ATTEMPT='2', TEST_CARGO_STATUS='17')
        self.assertEqual(failed.returncode, 17, failed.stderr)
        attempt = self.runner / 'tiaris-nest-public-closure-42-2'
        self.assertFalse((attempt / 'release-public-key').exists())
        self.assertFalse((attempt / 'tiaris-nest-public-closure-qualification.json').exists())
        self.assertTrue(self.invocations()[-1]['compilerOutputReused'])

    def test_existing_attempt_directory_cannot_supply_reused_acceptance(self):
        first = self.run_step(self.qualify)
        self.assertEqual(first.returncode, 0, first.stderr)
        replay = self.run_step(self.qualify)
        self.assertNotEqual(replay.returncode, 0)
        self.assertEqual(len(self.invocations()), 1)


if __name__ == '__main__':
    unittest.main()
