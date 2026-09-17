#!/usr/bin/env python3
"""Exact operator repair of a known predecessor daemon; no ledger edits/restores."""
import argparse, fcntl, grp, hashlib, json, os, shutil, sqlite3, stat, subprocess, tempfile, time
from pathlib import Path
import tomllib

VARIANTS = {'19': {'source_revision': '0762443360e56e25cc1bcf1476081d81bb0a5397', 'base_revision': '8bd6a04cef8624de2e354d2140e5e875293d1866', 'sha256': '1262e01060c81e478e69aa0f06b62dc8d545dd17e63d70e459261b821bbdbad9', 'behavior': 'predecessor daemon plus exact additive wake_on_lan migration; no missing/checksum bypass'}, '21': {'source_revision': '02084d383a5eedf0cd12384a2cb3a44dca221d12', 'base_revision': 'b1d6a5542b766f45bb9200a0f0b25905d25a5d94', 'sha256': 'f2eeb14ff20db2cde00c16deda95dac2619e4bea9d8877d5b3d9c2da074d0a37', 'behavior': 'predecessor daemon plus exact additive wake_on_lan migration; no missing/checksum bypass'}}
OLD = {'19': '77a85982f5110d92db96785706343f26f0dba9666bc53241a2cce0dc85a08b6b',
       '21': '0e3a82f56f87efa899640821d6e9dc5129eb46ace10b807fdb9b1007b46a29c6'}

def sha(p):
    with p.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def safe(p, uids=(0,)):
    s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid in uids and not s.st_mode & 0o022 and s.st_nlink == 1

def run(*a): return subprocess.check_output(a, text=True).strip()

def sync(p):
    fd=os.open(p,os.O_RDONLY); os.fsync(fd); os.close(fd)

def main():
    assert os.geteuid()==0
    parser=argparse.ArgumentParser(); parser.add_argument('--variant', choices=['19','21'],required=True); parser.add_argument('--binary',type=Path,required=True)
    a=parser.parse_args(); safe(a.binary); assert sha(a.binary)==VARIANTS[a.variant]['sha256']
    override=Path('/etc/systemd/system/cybex-james.service.d/90-verification-fix.conf'); safe(override)
    assert sha(override) in ['6fe76ff5a1295f7b7352b3cfbb65251cc66c129120fc254fe2673a4953110037','810378844749f04248bc5b241ce73bc4ad36907495ec0e10e1337158f6cb51f1']
    paths=[line.removeprefix('ExecStart=').split()[0] for line in override.read_text().splitlines() if line.startswith('ExecStart=/')]
    assert len(paths)==1
    binary=Path(paths[0]); safe(binary, (0,1000)); before=sha(binary)
    if before==VARIANTS[a.variant]['sha256']:
        print(json.dumps({'already_repaired':True,'sha256':before}));return
    assert before==OLD[a.variant]
    lock=Path('/run/lock/cybex-james/appliance-update.lock')
    lock.parent.mkdir(mode=0o750,exist_ok=True)
    lockfd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o640)
    os.fchown(lockfd,0,grp.getgrnam('cybex-james').gr_gid);os.close(lockfd);safe(lock)
    with lock.open('r+') as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert not Path('/var/lib/cybex-james/control/pending-root-generation.json').exists()
        assert subprocess.run(['pgrep','-f','[n]ix.*build'],stdout=subprocess.DEVNULL).returncode == 1, 'Active Nix build must finish before maintenance'
        config=tomllib.loads(Path('/etc/cybex-james/config.toml').read_text())
        db=Path(config['paths']['database_path']); assert str(db)=='/var/lib/cybex-james/state/agent/cybex-james.sqlite'
        backup=Path('/var/lib/cybex-james/control/maintenance-repairs/database-compat-v1'); backup.mkdir(mode=0o700)
        plan=Path('/var/lib/cybex-james/control/install-plan.json'); identity=Path('/var/lib/cybex-james/state/agent/manage-state.json')
        identity_data=json.loads(identity.read_text()); identity_hash=hashlib.sha256(json.dumps({k:identity_data[k] for k in ['device_id','private_key_b64','public_key_b64','public_key_fingerprint']},sort_keys=True).encode()).hexdigest()
        receipt={'variant':a.variant,'before_sha256':before,'after':VARIANTS[a.variant],'plan_sha256':sha(plan),'identity_sha256':identity_hash,'database_restored':False,'migration_ledger_rewritten':False}
        subprocess.run(['systemctl','stop','cybex-james.service'],check=True)
        assert run('systemctl','show','-p','MainPID','--value','cybex-james.service')=='0'
        for p in [binary,db,Path(str(db)+'-wal'),Path(str(db)+'-shm')]:
            if p.exists():
                shutil.copyfile(p,backup/(p.name+'.before')); (backup/(p.name+'.before')).chmod(0o600);sync(backup/(p.name+'.before'))
        with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True) as c:
            assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            active=c.execute("SELECT COUNT(*) FROM james_build_jobs WHERE status IN ('running','building')").fetchone()[0] if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='james_build_jobs'").fetchone() else 0
            assert active==0, 'Active build must finish before maintenance'
            receipt['migration_versions_before']=[r[0] for r in c.execute('SELECT version FROM _sqlx_migrations ORDER BY version')]
        f,name=tempfile.mkstemp(dir=binary.parent,prefix='.dbcompat-')
        with os.fdopen(f,'wb') as out, a.binary.open('rb') as source:
            shutil.copyfileobj(source,out);os.fchmod(out.fileno(),0o755);out.flush();os.fsync(out.fileno())
        assert sha(binary)==before
        os.replace(name,binary);sync(binary.parent)
        (backup/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');(backup/'receipt.json').chmod(0o600);sync(backup/'receipt.json');sync(backup)
        subprocess.run(['systemctl','reset-failed','cybex-james.service'],check=True)
        subprocess.run(['systemctl','start','cybex-james.service'],check=True)
        time.sleep(3)
        assert run('systemctl','is-active','cybex-james.service')=='active'
        pid=run('systemctl','show','-p','MainPID','--value','cybex-james.service')
        assert sha(Path('/proc')/pid/'exe')==VARIANTS[a.variant]['sha256']
        assert sha(plan)==receipt['plan_sha256']
        receipt['service_started']=True
        print(json.dumps(receipt))

if __name__=='__main__': main()
