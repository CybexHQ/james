#!/usr/bin/env python3
"""Real dnsmasq + OVMF/iPXE qualification in disposable network namespaces.
No host VLAN, DHCP options, disks, or existing VM configuration are modified.
Run as root; requires dnsmasq-base, QEMU, OVMF and an x86-64 iPXE EFI loader.
"""
import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('pxe', str(ROOT / 'ubuntu-appliance/rootfs/usr/lib/cybex-james/cybex-james-pxe'))
spec = importlib.util.spec_from_loader(loader.name, loader)
pxe = importlib.util.module_from_spec(spec)
loader.exec_module(pxe)

CLIENT = r'''
import json,socket,struct,time,sys,random
mac=bytes.fromhex(sys.argv[1].replace(':',''));arch=int(sys.argv[2]);xid=random.randrange(1,2**32)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('',68));s.settimeout(.3)
packet=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0x8000,b'\0'*4,b'\0'*4,b'\0'*4,b'\0'*4,mac+b'\0'*10,b'\0'*64,b'\0'*128)+b'\x63\x82\x53\x63'+bytes([53,1,1,55,4,1,3,6,67])
if arch>=0:
 vendor=b'PXEClient:Arch:%05d:UNDI:003000'%arch
 packet+=bytes([60,len(vendor)])+vendor+bytes([93,2])+struct.pack('!H',arch)
packet+=b'\xff';s.sendto(packet,('255.255.255.255',67));end=time.monotonic()+5;offers=[]
while time.monotonic()<end:
 try:data,remote=s.recvfrom(4096)
 except socket.timeout:continue
 if len(data)<240 or struct.unpack_from('!I',data,4)[0]!=xid:continue
 opts={};i=240
 while i<len(data):
  tag=data[i];i+=1
  if tag==255:break
  if tag==0:continue
  length=data[i];i+=1;opts[tag]=data[i:i+length];i+=length
 if opts.get(53)!=b'\x02':continue
 offers.append({'server':socket.inet_ntoa(opts.get(54,b'\0'*4)),'address':socket.inet_ntoa(data[16:20]),'next_server':socket.inet_ntoa(data[20:24]),'filename':data[108:236].split(b'\0')[0].decode(errors='replace'),'option67':opts.get(67,b'').decode(errors='replace')})
print(json.dumps(offers))
'''

HTTP = r'''
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
import sys
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path.startswith('/boot/'):
   Path(sys.argv[1]).write_text(sys.argv[2] + self.path)
   body=b'#!ipxe\necho Cybex PXE qualification passed\nsleep 2\npoweroff\n'
   self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  else:self.send_error(404)
 def log_message(self,*args):pass
HTTPServer((sys.argv[2],80),Handler).serve_forever()
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootloader', type=Path, default=Path('/usr/lib/ipxe/snponly.efi'))
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('run as root')
    if not args.bootloader.is_file(): parser.error('provide the appliance snponly.efi with --bootloader')
    namespaces, processes = [], []
    label = f'cybex-pxe-{os.getpid()}'
    hub, server, client = label+'-lan', label+'-james', label+'-client'
    def run(command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode: raise RuntimeError(result.stderr)
        return result
    def ns(name, *command): return run(['ip','netns','exec',name,*command])
    def start(name, command, log):
        stream = open(log, 'w')
        process = subprocess.Popen(['ip','netns','exec',name,*command], stdout=stream, stderr=subprocess.STDOUT)
        stream.close(); processes.append(process); return process
    with tempfile.TemporaryDirectory(prefix='cybex-pxe-qualification-') as directory:
        work = Path(directory); work.chmod(0o755)
        try:
            for name in (hub, server, client):
                run(['ip','netns','add',name]);namespaces.append(name)
                ns(name,'ip','link','set','lo','up')
            ns(hub,'ip','link','add','br0','type','bridge');ns(hub,'ip','link','set','br0','up')
            ns(hub,'ip','address','add','192.0.2.1/24','dev','br0')
            for index, name in enumerate((server,client),2):
                port = f'p{index}'
                ns(hub,'ip','link','add',port,'type','veth','peer','name',f'v{index}')
                ns(hub,'ip','link','set',f'v{index}','netns',name)
                ns(hub,'ip','link','set',port,'master','br0');ns(hub,'ip','link','set',port,'up')
                ns(name,'ip','link','set',f'v{index}','name','eth0');ns(name,'ip','link','set','eth0','up')
                ns(name,'ip','address','add',f'192.0.2.{index}/24','dev','eth0')
                ns(name,'ip','route','add','default','via','192.0.2.1')
            ns(server,'ip','address','add','192.0.2.4/24','dev','eth0')
            main_config=work/'dhcp.conf'
            main_config.write_text(f'port=0\nno-ping\nbind-interfaces\ninterface=br0\ndhcp-range=192.0.2.100,192.0.2.120,255.255.255.0,1h\ndhcp-leasefile={work}/leases\nlog-facility=-\npid-file=\n')
            start(hub,['/usr/sbin/dnsmasq','--keep-in-foreground',f'--conf-file={main_config}'],work/'dhcp.log')
            target={'address':'192.0.2.2','bootloader_filename':'snponly.efi'}
            owner={'address':'192.0.2.4','bootloader_filename':'snponly.efi'}
            config=pxe.dnsmasq_config({'interface':'eth0','cidr':'192.0.2.0/24'},target,{'james':target,'owner':owner},[{'mac':'02:00:00:00:10:ff','server_device_id':None},{'mac':'02:00:00:00:20:02','server_device_id':'owner'}])
            proxy_config=work/'proxy.conf';proxy_config.write_text(config)
            proxy = start(server,['/usr/sbin/dnsmasq','--keep-in-foreground',f'--conf-file={proxy_config}'],work/'proxy.log')
            time.sleep(1)
            assert proxy.poll() is None, (work/'proxy.log').read_text()
            checks={}
            for case, mac, arch, expected in [('uefi_7','02:00:00:00:10:07',7,True),('uefi_9','02:00:00:00:10:09',9,True),('ordinary_dhcp','02:00:00:00:10:01',-1,False),('legacy_bios','02:00:00:00:10:00',0,False),('conflicting_assignment','02:00:00:00:10:ff',7,False)]:
                offers=json.loads(ns(client,sys.executable,'-c',CLIENT,mac,str(arch)).stdout)
                dhcp=[o for o in offers if o['server']=='192.0.2.1']
                proxies=[o for o in offers if o['server']=='192.0.2.2']
                assert dhcp and all(o['address']!='0.0.0.0' and not o['filename'] and not o['option67'] for o in dhcp), (case,offers)
                assert bool(proxies)==expected and all(o['address']=='0.0.0.0' for o in proxies), (case,offers)
                checks[case]=True
                print(f'PASS: {case}',flush=True)
            tftp=work/'tftp';tftp.mkdir(mode=0o755);tftp.chmod(0o755)
            shutil.copyfile(args.bootloader,tftp/'snponly.efi');(tftp/'snponly.efi').chmod(0o644)
            shutil.copyfile(ROOT/'ubuntu-appliance/rootfs/usr/share/cybex-james/autoexec.ipxe',tftp/'autoexec.ipxe');(tftp/'autoexec.ipxe').chmod(0o644)
            tftp_config=work/'tftp.conf';tftp_config.write_text(f'port=0\nbind-interfaces\ninterface=eth0\nenable-tftp\ntftp-root={tftp}\nlog-facility=-\npid-file=\n')
            start(server,['/usr/sbin/dnsmasq','--keep-in-foreground',f'--conf-file={tftp_config}'],work/'tftp.log')
            boot_receipt=work/'http-boot-receipt'
            start(server,[sys.executable,'-c',HTTP,str(boot_receipt),'192.0.2.2'],work/'http.log')
            owner_receipt=work/'owner-boot-receipt'
            start(server,[sys.executable,'-c',HTTP,str(owner_receipt),'192.0.2.4'],work/'owner-http.log')
            ns(hub,'ip','tuntap','add','tap0','mode','tap');ns(hub,'ip','link','set','tap0','master','br0');ns(hub,'ip','link','set','tap0','up')
            for case, boot_mac, target_ip, boot_receipt in [('ovmf_ipxe_http_handoff','02:00:00:00:20:01','192.0.2.2',boot_receipt),('assigned_owner_http_handoff','02:00:00:00:20:02','192.0.2.4',owner_receipt)]:
                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',work/'vars.fd')
                command=['qemu-system-x86_64','-machine','q35,accel=kvm,smm=on','-cpu','host','-device','virtio-rng-pci','-m','512','-nodefaults','-nographic','-serial','stdio',
                    '-drive','if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
                    '-drive',f'if=pflash,format=raw,file={work}/vars.fd',
                    '-netdev','tap,id=net0,ifname=tap0,script=no,downscript=no',
                    '-device','virtio-net-pci,netdev=net0,mac='+boot_mac+',bootindex=1','-no-reboot']
                vm=start(hub,command,work/'qemu.log')
                deadline=time.monotonic()+100
                while time.monotonic()<deadline and not boot_receipt.exists() and vm.poll() is None:
                    time.sleep(1)
                assert boot_receipt.exists(), 'UEFI handoff failed:\n'+(work/'qemu.log').read_text()[-6000:]+'\nTFTP:\n'+(work/'tftp.log').read_text()[-3000:]
                assert boot_receipt.read_text()==target_ip+'/boot/'+boot_mac.replace(':','-'), boot_receipt.read_text()
                checks[case]=True
                print(f'PASS: {case}: OVMF → ProxyDHCP → TFTP iPXE → HTTP {target_ip}',flush=True)
                vm.terminate(); vm.wait(timeout=5)
            receipt={'schema':'cybex.james.pxe-qualification.v1','checks':checks,'dhcp_boot_options':False}
            if args.receipt:
                args.receipt.parent.mkdir(parents=True,exist_ok=True)
                args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
        except Exception:
            for log in ('dhcp.log','proxy.log','tftp.log','qemu.log'):
                if (work/log).exists(): print(log+':\n'+(work/log).read_text()[-5000:],file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=3)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            for name in reversed(namespaces):
                subprocess.run(['ip','netns','delete',name],capture_output=True)

if __name__=='__main__': main()
