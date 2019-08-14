Secure OS 

## A SandBox for SSH Client

A Kernel module which causes SSH client to operate completely inside a Virtual Machine, but behave on User Side as if operating on host machine as usual. 


### Instruction   
start vm as follows:  
sudo qemu-system-x86_64 -enable-kvm -m 4000 -boot c -hda ubuntu_guest.img -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/ivshmem,id=hostmem -device ivshmem-plain,memdev=hostmem     
  
ssh from host   
ssh -p 5555 tushargr@127.0.0.1   

### PCI passthrough instructions     
1. Unbinding any driver attached to the host device- (use lspci)   
  echo -n 0000:03:00.1 | sudo tee -a /sys/bus/pci/devices/0000:03:00:1/driver/unbind  

2. Can also remove driver from modules using-  
    rmmod <device driver>      Eg: r8169  
    or modprobe -rf <device driver>  
    check using lspci -nnk,  

3. load vfio-pci module using  
    modprobe vfio-pci  

4.  go to cd /sys/bus/pci/drivers/vfio-pci/ and add unbinded devices  
    echo "10ec 5287" | sudo tee -a new_id  

5. Make sure to passthrough all devices in an iommu group.  
 
6. Add hardware <host device> from virt-manager ui.   
    if running using qemu - sudo qemu-system-x86_64 -m 2048 -boot c -net none -hda ubuntu.img -device vfio-pci,host=03:00.0   

7. boot into VM and check ifconfig.   
8. https://www.tecmint.com/configure-network-static-ip-address-in-ubuntu/  

### args  
LC_ALL=C PATH=/bin HOME=/home/vinayakt USER=vinayakt \   
LOGNAME=vinayakt /usr/bin/qemu-system-x86_64 \   
-m 2048 -boot c -net none -hda /home/vinayakt/Desktop/6thSem/UGP/ubuntu.img -device   
vfio-pci,host=03:00.0 \   
-object memory-backend-file,size=1M,share,mem-path=/dev/shm/ivshmem,id=hostmem \  
-device ivshmem-plain,memdev=hostmem  

### Using chardevice for communication   

 sudo qemu-system-x86_64 -m 2048 -boot c -net none -hda ubuntu.img -device vfio-pci,host=03:00.1 -device virtio-serial -chardev socket,path=/tmp/foo,server,nowait,id=foo -device virtserialport,chardev=foo,name=org.fedoraproject.port.0   

 To send data from host to guest  
 socat /tmp/foo - on host and sudo cat /dev/vport0p1 on guest  
 
 To send data from guest to host  
 sudo nc -U /tmp/foo on host and echo "hello" | sudo tee -a /dev/vport0p1   


