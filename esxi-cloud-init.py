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
import urllib.request


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
    with open('/vmfs/volumes/config-2/openstack/latest/network_data.json', 'r') as fd:
        return json.loads(fd.read())

def load_meta_data():
    if os.path.exists('/vmfs/volumes/config-2/openstack/latest/meta_data.json'):
        fd = open('/vmfs/volumes/config-2/openstack/latest/meta_data.json', 'r')
        raw_content = fd.read()
    else:
        try:
            fd = urllib.request.urlopen('http://169.254.169.254/openstack/latest/meta_data.json')
            raw_content = fd.read().decode()
        except urllib.error.URLError:
            return {}
    data = json.loads(raw_content)
    return data

def load_user_data():
    # Should be openstack/latest/user-data
    content = None
    try:
        content = open('/vmfs/volumes/config-2/openstack/latest/user_data', 'r').read()
    except FileNotFoundError:
        pass
    try:
        if not content:
            content = urllib.request.urlopen('http://169.254.169.254/openstack/latest/user_data').read().decode()
    except urllib.error.URLError:
        pass

    if not content:
        return {}

    user_data = {}
    for line in content.split("\n"):
        if line.startswith('#'):
            continue
        if not re.match(r'.*:.+', line):
            continue

        k, v = line.split(': ', 1)
        v = v.rstrip()
        if v.startswith("'") and v.endswith("'"):
            v = v[1:-1]
        user_data[k] = v.rstrip()
    return user_data

def set_hostname(fqdn):
    if fqdn:
        run_cmd(['esxcli', 'system', 'hostname', 'set', '--fqdn=%s' % fqdn])

def set_network(network_data):
    run_cmd(['esxcfg-vmknic', '-d', 'Management Network'], ignore_failure=True)
    run_cmd(['esxcli', 'network', 'ip', 'set', '--ipv6-enabled=0'])

    # ESX's switch has no learning mode and enforce the MAC/port by default
    # With this line, we ensure a nested ESXi can contact the outside world
    run_cmd(['esxcli', 'network', 'vswitch', 'standard', 'policy', 'security', 'set', '--allow-promiscuous=1', '--allow-forged-transmits=1', '--allow-mac-change=1', '--vswitch-name=vSwitch0'])
    link_by_id = {i['id']: i for i in network_data['links']}
    open('/etc/resolv.conf', 'w').close()
    # Assuming one network per interface and interfaces are in the good order
    # and only set the first interface
    ifdef = network_data['networks'][0]
    link = link_by_id[ifdef['link']]
    if ifdef['type'] == 'ipv4':
        run_cmd(['esxcfg-vmknic', '-a', '-i', ifdef['ip_address'], '-n', ifdef['netmask'], '-m', str(link.get('mtu', '1500')), '-M', link['ethernet_mac_address'], '-p', 'Management Network'])
    else:
        run_cmd(['esxcfg-vmknic', '-a', '-i', 'DHCP', '-m', str(link.get('mtu', '1500')), '-M', link['ethernet_mac_address'], '-p', 'Management Network'])

    r = {}
    for r in ifdef.get('routes', []):
        if r['network'] == '0.0.0.0':
            network = 'default'
        else:
            network = r['network']
    if 'gateway' in r:
            run_cmd(['esxcli', 'network', 'ip', 'route', 'ipv4', 'add', '-g', r['gateway'], '-n', network])

    for s in network_data.get('services', []):
        if s['type'] == 'dns':
            run_cmd(['esxcli', 'network', 'ip', 'dns', 'server', 'add', '--server', s['address']])

def set_ssh_keys(public_keys):
    if not public_keys:
        return
    # A bit hackish because PyYAML because ESXi's Python does not provide PyYAML
    add_keys = public_keys.values()
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
    with open('/etc/vmware/config', 'a+') as fd:
        fd.write('\nvmx.allowNested = "TRUE"\n')

def set_root_pw(password):
    hashed_pw = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
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

def get_nic_mac_address(vmnic):
    # Name    PCI Device    Driver  Admin Status  Link Status  Speed  Duplex  MAC Address         MTU  Description
    # ------  ------------  ------  ------------  -----------  -----  ------  -----------------  ----  -----------------------------------------------------
    # vmnic0  0000:00:03.0  e1000   Up            Up            1000  Full    fa:16:3e:25:bd:9f  1500  Intel Corporation 82540EM Gigabit Ethernet Controller
    # vmnic1  0000:00:04.0  e1000   Up            Up            1000  Full    fa:16:3e:a3:d8:34  1500  Intel Corporation 82540EM Gigabit Ethernet Controller
    raw = run_cmd(["esxcli", "network", "nic", "list"]).decode()
    nic_list_lines = raw.split('\n')[2:]
    print(nic_list_lines)
    for line in nic_list_lines:
        cur_vmnic, _, _, _, _, _, _, mac = line.split()[0:8]
        if cur_vmnic == vmnic:
            return mac

def default_network_data():
    # "esxcli network nic list" fails time to time...
    for _ in range(60):
        try:
            mac_address = get_nic_mac_address("vmnic0")
            break
        except subprocess.CalledProcessError:
            pass
    return {
        "links": [
            {
            "ethernet_mac_address": mac_address,
            "id": "mylink",
            "mtu": "1500",
        }
        ],
        "networks": [
            {
            "id": "network0",
            "link": "mylink",
            "type": "ipv4_dhcp"
            }
        ],
    }


cdrom_dev = find_cdrom_dev()
if cdrom_dev:
    run_cmd(['vmkload_mod', 'iso9660'])
    mount_cdrom(cdrom_dev)
    network_data = load_network_data()
    meta_data = load_meta_data()
    user_data = load_user_data()
    umount_cdrom(cdrom_dev)
    run_cmd(['vmkload_mod', '-u', 'iso9660'])
    set_network(network_data)
else:
    network_data = default_network_data()
    set_network(network_data)
    meta_data = load_meta_data()
    user_data = load_user_data()

set_hostname(meta_data.get('hostname'))
set_ssh_keys(meta_data.get('public_keys'))
if 'admin_pass' in meta_data:
    set_root_pw(meta_data['admin_pass'])
if 'password' in user_data:
    set_root_pw(user_data['password'])
enable_ssh()

allow_nested_vm()
restart_service('hostd')
restart_service('vpxa')
create_local_datastore()
