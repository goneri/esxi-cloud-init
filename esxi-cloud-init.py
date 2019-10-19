#!/bin/python
import crypt
import re
import subprocess
import json
import glob
import time
import select
import os
import fcntl


def run_cmd(args, ignore_failure=False):
    print('run: %s' % args)
    try:
        return subprocess.check_output(args)
    except subprocess.CalledProcessError:
        if not ignore_failure:
            raise

def find_cdrom_dev():
    mpath_b = run_cmd(['esxcfg-mpath', '-b'])
    for line in mpath_b.decode().split('\n'):
        m = re.match(r'^(\S*).*\sCD-ROM\s.*', line)
        if m:
            return m.group(1)

def mount_cdrom(cdrom_dev):
    run_cmd(['vsish', '-e', 'set', '/vmkModules/iso9660/mount', cdrom_dev])

def umount_cdrom(cdrom_dev):
    run_cmd(['vsish', '-e', 'set', '/vmkModules/iso9660/umount', cdrom_dev])

def load_network_data():
    # Should be openstack/latest/network_data.json
    with open('/vmfs/volumes/config-2/OPENSTAC/LATEST/NETWORK_.JSO', 'r') as fd:
        return json.loads(fd.read())

def load_meta_data():
    # Should be openstack/latest/meta_data.json
    with open('/vmfs/volumes/config-2/OPENSTAC/LATEST/META_DAT.JSO', 'r') as fd:
        data = json.loads(fd.read())
        return data

def load_user_data():
    # Should be openstack/latest/user-data
    user_data = {}
    with open('/vmfs/volumes/config-2/OPENSTAC/LATEST/USER_DAT', 'r') as fd:
        for line in fd.readlines():
            if line.startswith('#'):
                continue
            if not re.match(r'.*:.+', line):
                continue

            k, v = line.split(': ', 1)
            user_data[k] = v.rstrip()
        return user_data

def set_hostname(meta_data):
    host = meta_data['hostname']
    run_cmd(['esxcli', 'system', 'hostname', 'set', '--host=%s' % host])

def set_network(network_data):
    run_cmd(['esxcfg-vmknic', '-d', 'VM Network'], ignore_failure=True)
    run_cmd(['esxcfg-vmknic', '-d', 'Management Network'], ignore_failure=True)
    run_cmd(['esxcfg-vswitch', '-d', 'vSwitch0'])
    run_cmd(['esxcfg-vswitch', '-a', 'vSwitch0'])
    run_cmd(['esxcfg-vswitch', '-L', 'vmnic0', 'vSwitch0'])
    run_cmd(['esxcfg-vswitch', '-A', 'VM Network', 'vSwitch0'])
    run_cmd(['esxcfg-vswitch', '-A', 'Management Network', 'vSwitch0'])
    run_cmd(['esxcli', 'network', 'ip', 'interface', 'add', '-i', 'vmk0', '-p', 'Management Network'])
    run_cmd(['esxcli', 'network', 'ip', 'set', '--ipv6-enabled=0'])

    # ESX's switch has no learning mode and enforce the MAC/port by default
    # With this line, we ensure a nested ESXi can contact the outside world
    run_cmd(['esxcli', 'network', 'vswitch', 'standard', 'policy', 'security', 'set', '--allow-promiscuous=1', '--allow-forged-transmits=1', '--allow-mac-change=1', '--vswitch-name=vSwitch0'])
    open('/etc/resolv.conf', 'w').close()
    # Assuming one network per interface and interfaces are in the good order
    for i in range(len(network_data['networks'])):
        ifdef = network_data['networks'][i]
        if ifdef['type'] == 'ipv4':
            run_cmd(['esxcli', 'network', 'ip', 'interface', 'ipv4', 'set', '-i', 'vmk%i' % i, '-I', ifdef['ip_address'], '-N', ifdef['netmask'], '-t', 'static'])
        else:
            run_cmd(['esxcli', 'network', 'ip', 'interface', 'ipv4', 'set', '-i', 'vmk%i' % i, '-t', 'dhcp'])

        for r in ifdef.get('routes', []):
            if r['network'] == '0.0.0.0':
                network = 'default'
            else:
                network = r['network']
        run_cmd(['esxcli', 'network', 'ip', 'route', 'ipv4', 'add', '-g', r['gateway'], '-n', network])

    for s in network_data.get('services', []):
        if s['type'] == 'dns':
            run_cmd(['esxcli', 'network', 'ip', 'dns', 'server', 'add', '--server', s['address']])

def set_ssh_keys(meta_data):
    # A bit hackish because PyYAML because ESXi's Python does not provide PyYAML
    add_keys = meta_data['public_keys'].values()
    current_keys = []

    with open('/etc/ssh/keys-root/authorized_keys', 'r') as fd:
        for line in fd.readlines():
            m = re.match(r'[^#].*(ssh-rsa\s\S+).*', line)
            if m:
                current_keys.append = fd.group(1)

    with open('/etc/ssh/keys-root/authorized_keys', 'w+') as fd:
        for key in set(add_keys):
            if key not in current_keys:
                fd.write(key + '\n')

def allow_nested_vm():
    with open('/etc/vmware/config', 'r') as fd:
        for line in fd.readlines():
            m = re.match(r'^vmx.allowNested', line)
            if m:
                return
    with open('/etc/vmware/config', 'w+') as fd:
        fd.write('\nvmx.allowNested = "TRUE"\n')

def set_root_pw(user_data):
    hashed_pw = crypt.crypt(user_data['password'], crypt.mksalt(crypt.METHOD_SHA512))
    current = open('/etc/shadow', 'r').readlines()
    with open('/etc/shadow', 'w') as fd:
        for line in current:
            s = line.split(':')
            if s[0] == 'root':
                s[1] = hashed_pw
            fd.write(':'.join(s))

def turn_off_firewall():
    run_cmd(['esxcli', 'network', 'firewall', 'set', '--enabled', 'false'])

def restart_service(service_name):
    run_cmd(['/etc/init.d/%s' % service_name , 'restart'])

def enable_ssh():
    run_cmd(['vim-cmd', 'hostsvc/enable_ssh'])
    run_cmd(['vim-cmd', 'hostsvc/start_ssh'])

def create_local_datastore():
    root_disk = glob.glob('/vmfs/devices/disks/t10*:1')[0].split(':')[0]  # TODO: probably kvm specific

    proc = subprocess.Popen(['partedUtil', 'fixGpt', root_disk], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    fd = proc.stdout.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    while True:
        time.sleep(.5)
        if len(select.select([proc.stdout, proc.stderr], [], [], 0)[0]) == 0:
            continue
        out = ''
        try:
            out = proc.stdout.read()
        except TypeError as e:
            continue
        if 'Are you sure you want to continue' in out.decode():
            proc.stdin.write('Y\n'.encode())
            proc.stdin.flush()
        elif 'The backup GPT table is not' in out.decode():
            proc.stdin.write('Fix\n'.encode())
            proc.stdin.flush()

        if proc.poll() is not None:
            break

    getptbl_output = subprocess.check_output(['partedUtil', 'getptbl', root_disk]).decode().split('\n')
    geometry = getptbl_output[1]
    last_partition = getptbl_output[-2]
    last_sector_in_use = int(last_partition.split()[2])
    quantity_of_cylinders = int(geometry.split()[3])
    new_partition_partnum = max([int(i.split()[0]) for i in getptbl_output[2:-1]]) + 1
    new_partition_first_sector = last_sector_in_use + 4096
    new_partition_last_sector = quantity_of_cylinders - 4096

    if new_partition_last_sector - new_partition_first_sector > 4096 * 1024:
        print(subprocess.check_output(["partedUtil", "add", root_disk, "gpt", "%s %s %s AA31E02A400F11DB9590000C2911D1B8 0" % (new_partition_partnum, new_partition_first_sector, new_partition_last_sector)]))
        print(subprocess.check_output(["vmkfstools", "-C", "vmfs6", "-S", "local", "%s:%s" % (root_disk, new_partition_partnum)]))

cdrom_dev = find_cdrom_dev()
try:
    run_cmd(['vmkload_mod', 'iso9660'])
    mount_cdrom(cdrom_dev)
    network_data = load_network_data()
    set_network(network_data)
    meta_data = load_meta_data()
    set_hostname(meta_data)
    set_ssh_keys(meta_data)
    user_data = load_user_data()
    set_root_pw(user_data)
    if user_data.get('ssh_pwauth'):
        enable_ssh()

    allow_nested_vm()
    restart_service('hostd')
    restart_service('vpxa')
    create_local_datastore()
finally:
    umount_cdrom(cdrom_dev)
    run_cmd(['vmkload_mod', '-u', 'iso9660'])
