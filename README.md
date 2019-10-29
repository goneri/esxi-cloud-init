# Poor boy's Cloud-Init for ESXi

This project provide a cloud-init for ESXi. It only covers a subset of the
feature of the real cloud-init.

- hostname
- network (Only the first interface)
- root password
- SSH key
- enable SSH server
- enable the ability to start Nested ESXI VM
- create a datatore called 'local' with the space left on the root disk

It reads the configuration from a metadata disk in the OpenStack format.
So you can use to deploy ESXi on baremetal with OpenStack Ironic.
