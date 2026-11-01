"""Explicit database setup for the exact owned disposable Manage fixture."""
from pathlib import Path
import re


READY = '/var/lib/tiaris/database-provisioned'
APP_START = f'''if [ ! -f {READY} ]; then
  TIARIS_MIGRATE_ONLY=1 TIARIS_DATABASE_VERIFY_ONLY=0 /opt/tiaris/bin/tiaris
  exit 0
fi
TIARIS_MIGRATE_ONLY=0 TIARIS_DATABASE_VERIFY_ONLY=1 /opt/tiaris/bin/tiaris
exec /opt/tiaris/bin/tiaris
'''


# Manage accepts its first administrator only with a locally issued, 30-minute
# setup token. The operator mode exits before opening a listener; the token
# lives only in the app's private tmpfs and is removed even on failure.
SETUP_TOKEN_FILE = '/tmp/tiaris-setup-token'
SETUP_TOKEN = f'''set -eu
set -a
. /run/fixture/environment
set +a
trap 'rm -f {SETUP_TOKEN_FILE}' EXIT
rm -f {SETUP_TOKEN_FILE}
TIARIS_MIGRATE_ONLY=0 TIARIS_DATABASE_VERIFY_ONLY=0 TIARIS_CREATE_SETUP_TOKEN={SETUP_TOKEN_FILE} /opt/tiaris/bin/tiaris >&2
cat {SETUP_TOKEN_FILE}
'''
SETUP_TOKEN_SHAPE = re.compile(r'tiaris_setup_[A-Za-z0-9_-]{43}')


def setup_token(owner, receipt):
    """Issue the first-administrator proof inside the exact running app."""
    docker = owner.docker(receipt)
    spec = receipt['containers']['app']
    docker.verify_container('app', spec['id'], spec['image'], spec['uid'],
        receipt['context']['network_id'], spec['mounts'],
        dns=receipt['peer_ipv4'], peer=spec['peer'])
    # Same cleared environment as launch.sh: only the owned fixture file.
    value = docker.call('container', 'exec', spec['id'], '/usr/bin/env', '-i',
                        'PATH=/usr/bin:/bin', '/bin/sh', '-c', SETUP_TOKEN)
    token = value.decode('ascii', 'replace').strip()
    if not SETUP_TOKEN_SHAPE.fullmatch(token):
        raise ValueError('fresh fixture Manage did not issue a valid setup token')
    return token


def initialize(owner, receipt, config, resources):
    """Migrate, provision committed roles, then admit normal API startup."""
    docker = owner.docker(receipt)

    def verify(role):
        spec = receipt['containers'][role]
        docker.verify_container(role, spec['id'], spec['image'], spec['uid'],
            receipt['context']['network_id'], spec['mounts'],
            dns=receipt['peer_ipv4'], peer=spec['peer'], created=role == 'app')
        return spec['id']

    app = verify('app')
    if docker.call('container', 'wait', app).strip() != b'0':
        raise ValueError('fresh fixture database migration failed')
    owner.guard(receipt)
    verify('app')
    database = verify('db')
    # Read the same committed development revision used by the verified image.
    # Expand psql's relative includes in memory; no copied or fallback role SQL.
    files = {}
    for name in ('provision.sql', 'roles.sql', 'privileges.sql'):
        files[name] = owner.run(['git', '-c', 'safe.directory=' + config['manage_checkout'],
            '-C', config['manage_checkout'], 'show',
            config['manage_revision'] + ':deploy/manage/database-isolation/' + name])
    sql = files['provision.sql']
    for name in ('roles.sql', 'privileges.sql'):
        include = ('\\ir ' + name + '\n').encode()
        if sql.count(include) != 1 or not files[name].strip():
            raise ValueError('invalid committed fixture database provisioning scripts')
        sql = sql.replace(include, files[name] + b'\n')
    # The fixture's fresh administrator is also its explicitly selected service
    # login. Manage constrains every runtime connection through SET ROLE.
    # SQL travels through stdin; credentials never enter Docker arguments.
    docker.call('container', 'exec', '-i', database, '/usr/bin/psql', '-Xq',
        '-v', 'ON_ERROR_STOP=1', '-v', 'runtime_login=fixture',
        '-U', 'fixture', '-d', 'fixture', data=sql)
    owner.guard(receipt)
    verify('app')
    verify('db')
    resources.write(owner.directory / 'app-data' / Path(READY).name,
                    b'provisioned\n', uid=10001)
    # APP_START verifies the installed schema and actual runtime role boundary
    # before it can open an API listener. Subsequent starts never migrate.
    docker.call('container', 'start', app)
