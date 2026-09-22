"""Observe certificate acceptance across bounded isolated-guest clock skew."""
import argparse
import subprocess
import sys
import time


def login(command, valid_before, *, run=subprocess.run, clock=time.monotonic,
          wall=time.time, sleep=time.sleep):
    # Fresh QEMU guests have no public NTP access and can lag the issuer by a
    # couple of seconds. OpenSSH still checks the exact certificate interval:
    # poll acceptance, never backdate the certificate or relax authentication.
    deadline = clock() + 10
    # One spaced retry also stays below OpenSSH's per-source authentication
    # penalty threshold. Fast repeated denials would block the negative tests.
    for attempt in range(2):
        remaining = min(deadline - clock(), valid_before - wall())
        if remaining <= 0:
            raise ValueError('SSH certificate was not accepted within its bounded validity check')
        result = run(command, capture_output=True, timeout=remaining)
        if result.returncode == 0:
            if wall() >= valid_before:
                raise ValueError('SSH certificate expired during its acceptance check')
            return result
        if result.returncode != 255 or b'Permission denied (publickey).' not in result.stderr:
            raise ValueError('SSH login failed for a reason other than certificate acceptance')
        remaining = min(deadline - clock(), valid_before - wall())
        if attempt == 0 and remaining > 0:
            sleep(min(3, remaining))
    raise ValueError('SSH certificate remained rejected after its clock-skew retry')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--valid-before', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('an SSH command is required')
    result = login(command, args.valid_before)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
