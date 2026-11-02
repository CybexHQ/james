"""Execute the release's syntax gate against disposable shell helpers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPERS = ('release/beast/preflight.sh', 'release/beast/second.sh',
           'nixos-appliance/build-closure.sh', 'nixos-appliance/runtime/network-guard')


@unittest.skipUnless(shutil.which('rg'), 'rg is required by the release syntax gate')
class ReleaseShellSyntaxTests(unittest.TestCase):
    def check_helpers(self, broken=None):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        step = workflow.split('      - name: Bash syntax\n', 1)[1].split('      - name:', 1)[0]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in HELPERS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                # A syntax check must never execute any helper.
                path.write_text('#!/usr/bin/env bash\nexit 99\n' +
                                ('if true; then\n' if name == broken else ''))
            result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                    cwd=root, text=True, capture_output=True, timeout=10)
        return result

    def test_valid_helpers_are_only_parsed(self):
        result = self.check_helpers()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_helper_can_fail_the_syntax_gate(self):
        for name in HELPERS:
            with self.subTest(helper=name):
                result = self.check_helpers(broken=name)
                self.assertNotEqual(result.returncode, 0, f'syntax gate silently ignored {name}')
                self.assertIn(name, result.stderr)


if __name__ == '__main__':
    unittest.main()
