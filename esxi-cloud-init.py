#!/bin/python

import crypt
import re
import subprocess
import json

def find_cdrom_dev():
    mpath_b = subprocess.check_output(['esxcfg-mpath', '-b'])
    for line in mpath_b.decode().split('\n'):
        m = re.match(r'^(\S*).*\sCD-ROM\s.*', line)
        if m:
            return m.group(1)

def mount_cdrom(cdrom_dev):
    subprocess.call(['vsish', '-e', 'set', '/vmkModules/iso9660/mount', cdrom_dev])

def umount_cdrom(cdrom_dev):
    subprocess.call(['vsish', '-e', 'set', '/vmkModules/iso9660/umount', cdrom_dev])

def load_network_data():
    # Should be openstack/latest/network_data.json
    with open('/vmfs/volumes/cidata/OPENSTAC/LATEST/NETWORK_.JSO', 'r') as fd:
        return json.loads(fd.read())

def load_meta_data():
    # Should be openstack/latest/meta_data.json
    with open('/vmfs/volumes/cidata/OPENSTAC/LATEST/META_DAT.JSO', 'r') as fd:
        data = json.loads(fd.read())
        return data

def load_user_data():
    # Should be openstack/latest/user-data
    user_data = {}
    with open('/vmfs/volumes/cidata/OPENSTAC/LATEST/USER_DAT', 'r') as fd:
        for line in fd.readlines():
            if line.startswith('#'):
                continue
            k, v = line.split(': ', 1)
            user_data[k] = v
        return user_data

def set_hostname(meta_data):
    host = meta_data['hostname']
    subprocess.call(['esxcli', 'system', 'hostname', 'set', '--host=%s' % host])

def set_network(network_data):
    subprocess.call(['esxcli', 'network', 'ip', 'dns', 'server', 'remove', '--all'])
    # Assuming one network per interface and interfaces are in the good order
    for i in range(len(network_data['networks'])):
        ifdef = network_data['networks'][i]
        if ifdef['type'] == 'ipv4':
            subprocess.call(['esxcli', 'network', 'ip', 'interface', 'ipv4', 'set', '-i', 'vmk%i' % i, '-g', ifdef['routes'][0]['gateway'], '-I', ifdef['ip_address'], '-N', ifdef['netmask'], '-t', 'static'])
            for r in ifdef['routes']:
                subprocess.call(['esxcli', 'network', 'ip', 'route', 'ipv4', 'add', '-g', r['gateway'], '-n', r['network']])
        else:
            subprocess.call(['esxcli', 'network', 'ip', 'interface', 'ipv4', 'set', '-i', 'vmk%i' % i, '-t', 'dhcp'])

    for s in network_data['services']:
        if s['type'] == 'dns':
            subprocess.call(['esxcli', 'network', 'ip', 'dns', 'server', 'add', '--server', s['address']])

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


try:
    subprocess.call(['vmkload_mod', 'iso9660'])
    cdrom_dev = find_cdrom_dev()
    mount_cdrom(cdrom_dev)
    network_data = load_network_data()
    set_network(network_data)
    meta_data = load_meta_data()
    set_hostname(meta_data)
    set_ssh_keys(meta_data)
    user_data = load_user_data()
    set_root_pw(user_data)
    allow_nested_vm()
finally:
    umount_cdrom(cdrom_dev)
    subprocess.call(['vmkload_mod', '-u', 'iso9660'])
