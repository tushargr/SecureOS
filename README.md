## Installation Instructions


#### Creating Virtual Machine
1. Download ubuntu server iso from official site.
2. ```qemu-img create -f qcow2 ubuntu_guest.img 30G```   
3. ```sudo qemu-system-x86_64 -m 4000 -hda ubuntu_guest.img -cdrom  ~/ubuntu_server.iso -boot d -enable-kvm```

#### Creating shared ivshmem file
1. ```dd if=/dev/zero of=/dev/shm/ivshmem count=1024 bs=1024```

#### Starting virtual machine
```sudo qemu-system-x86_64 -enable-kvm -m 4000 -boot c -hda ubuntu_guest.img -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/ivshmem,id=hostmem -device ivshmem-plain,memdev=hostmem```     
  
#### SSH into the virtual machine
```ssh -p 5555 tushargr@127.0.0.1```

#### Installing linux kernel 4.20.6 in virtual machine
1. Download linux kernel 4.20.6 and transfer to vm.
2. Copy the files from ```src/kernel/guest/``` to the downloaded linux kernel on vm replacing original source code files.  
2. Compile the kernel and reboot the vm.

#### Inserting NetSandBox module in host
1. ```chdir modules/host/``` and ```make```
2. ```sudo insmod host_module.ko```

#### Inserting NetSandBox module in vm
1. Transfer the ```guest``` dir present in  ```modules/``` to vm.
2. ```chdir guest``` on vm.
3. ```make```
3. ```sudo insmod uio_module.ko```
4. ```sudo insmod vm_module.ko```

#### Starting the Netsandbox agent on vm
```sudo ./agent```

#### Testing
1. Run ```sudo ssh xyz``` on host.

#### Debugging
1. Check dmesg logs.


