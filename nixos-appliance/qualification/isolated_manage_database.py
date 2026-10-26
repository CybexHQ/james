"""Explicit database setup for the exact owned disposable Manage fixture."""
from pathlib import Path


READY = '/var/lib/tiaris/database-provisioned'
APP_START = f'''if [ ! -f {READY} ]; then
  TIARIS_MIGRATE_ONLY=1 TIARIS_DATABASE_VERIFY_ONLY=0 /opt/tiaris/bin/tiaris
  exit 0
fi
TIARIS_MIGRATE_ONLY=0 TIARIS_DATABASE_VERIFY_ONLY=1 /opt/tiaris/bin/tiaris
exec /opt/tiaris/bin/tiaris
'''


def initialize(owner, receipt, config, resources):
    """Migrate, provision committed roles, then admit normal API startup."""
    docker = owner.docker(receipt)

    def verify(role):
        spec = receipt['containers'][role]
        docker.verify_container(role, spec['id'], spec['image'], spec['uid'],
            receipt['context']['network_id'], spec['mounts'],
            dns=receipt['peer_ipv4'], peer=spec['peer'])
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
