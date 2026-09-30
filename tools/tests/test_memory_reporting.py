import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / 'incus-memory-reporting.py'
SPEC = importlib.util.spec_from_file_location('incus_memory_reporting', MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OWNER = '00000000-0000-4000-8000-000000000001'


class MemoryReportingTests(unittest.TestCase):
    def test_enable_restore_preserves_inherited_override(self):
        data = {'type': 'virtual-machine', 'status': 'Stopped',
                'config': {'user.tiaris-memory-owner': OWNER},
                'expanded_config': {'raw.qemu.conf': '[machine]\nusb = "off"\n'}}
        calls = []

        def incus(*args):
            calls.append(args)
            if args[0] == 'query': return json.dumps(data)
            if args[1] == 'set': data['config']['raw.qemu.conf'] = args[4]
            return ''

        with tempfile.TemporaryDirectory() as directory:
            receipt = str(Path(directory) / 'receipt.json')
            argv = ['tool', 'enable', 'memory-fixture', '--owner', OWNER, '--receipt', receipt]
            with patch.object(MODULE, 'incus', incus), patch('sys.argv', argv): MODULE.main()
            self.assertIn('usb = "off"', data['config']['raw.qemu.conf'])
            self.assertIn('free-page-reporting = "on"', data['config']['raw.qemu.conf'])
            argv[1] = 'restore'
            with patch.object(MODULE, 'incus', incus), patch('sys.argv', argv): MODULE.main()
            self.assertEqual(calls[-1], ('config', 'unset', 'memory-fixture', 'raw.qemu.conf'))

    def test_unowned_and_running_instances_are_rejected_before_mutation(self):
        for status, owner in [('Running', OWNER), ('Stopped', 'different')]:
            data = dict(type='virtual-machine', status=status,
                        config={'user.tiaris-memory-owner': owner})
            with patch.object(MODULE, 'incus', return_value=json.dumps(data)) as incus:
                with patch('sys.argv', ['tool', 'enable', 'fixture', '--owner', OWNER, '--receipt', '/unused']):
                    with self.assertRaises(RuntimeError): MODULE.main()
                self.assertEqual(incus.call_count, 1)
