"""Private whole-process timing with signal forwarding and bounded cleanup wait."""
import datetime
import os
import signal
import subprocess
import time

import release_speed_io as io


class RunFailed(Exception):
    def __init__(self, code):
        self.code = code


def measure(command, output, phase, context, timeout, grace=180, accept=None, facts=None):
    if phase not in {'warm', 'cold', 'cache'}:
        raise ValueError('Unknown timing phase')
    import re
    if set(context) not in ({'source_sha256', 'manifest_sha256', 'profile_sha256'},
                            {'source_sha256', 'manifest_sha256', 'profile_sha256', 'run_sha256'}) or any(
            not re.fullmatch('[0-9a-f]{64}', v) for v in context.values()):
        raise ValueError('Invalid public context')
    io.directory(output.parent)
    output.mkdir(mode=0o700)  # exclusive: never reuse stale logs/results
    started = time.monotonic()
    utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    child, received, deadline, forced = None, [], None, False
    code, reason = 70, 'wrapper_error'
    details = {}
    def forward(number, _frame):
        nonlocal deadline
        if not received:
            received.append(number)
            deadline = time.monotonic() + grace
            if child is not None and child.poll() is None:
                child.send_signal(signal.SIGTERM if number == signal.SIGHUP else number)
    old = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        io.write(output / 'stdout.log', b'')
        io.write(output / 'stderr.log', b'')
        with io.append(output / 'stdout.log') as stdout, io.append(output / 'stderr.log') as stderr:
            child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            if received:
                child.send_signal(signal.SIGTERM if received[0] == signal.SIGHUP else received[0])
            while child.poll() is None:
                now = time.monotonic()
                if not received and now - started >= timeout:
                    forward(signal.SIGTERM, None)
                    reason = 'deadline'
                if deadline is not None and now >= deadline:
                    # Only the captured child; escaped sessions remain owner work.
                    child.kill()
                    forced = True
                    break
                time.sleep(0.05)
            code = child.wait()
            if received:
                code = -received[0]
                if reason != 'deadline':
                    reason = 'signal'
            else:
                reason = 'completed' if code == 0 else 'child_failure'
            if code == 0 and facts is not None:
                try:
                    details = facts()
                    if (set(details) != {'cache', 'bytes'} or details['cache'] not in {'hit', 'miss'}
                            or type(details['bytes']) is not int or not 0 <= details['bytes'] <= 32 * 1024**3):
                        raise ValueError('Invalid cache facts')
                except Exception:
                    details = {}
                    code, reason = 65, 'acceptance_failure'
            if code == 0 and accept is not None:
                try:
                    accept(stdout, stderr)
                except Exception:
                    code, reason = 65, 'acceptance_failure'
            if received:
                code = -received[0]
                if reason != 'deadline':
                    reason = 'signal'
    except Exception:
        code, reason = 70, 'wrapper_error'
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                forced = True
        for sig, handler in old.items():
            signal.signal(sig, handler)
        io.write(output / 'timing.json', io.canonical({
            'schema': 'cybex.james.qualification-timing.v1', 'phase': phase,
            'status': 'completed' if code == 0 else 'failed', 'reason': reason,
            'exit_code': code, 'duration_seconds': round(time.monotonic() - started, 3),
            'started_utc': utc, 'ended_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'cleanup': ('not_applicable' if phase == 'cache' else 'runner_returned') if code == 0 else 'unproven',
            'forced': forced, **context, **details}))
    if code:
        raise RunFailed(code)
    return code


def exit_status(code):
    if code < 0:
        number = -code
        signal.signal(number, signal.SIG_DFL)
        os.kill(os.getpid(), number)
    raise SystemExit(code)
