Secure OS 

#A SandBox for SSH Client

A Kernel module which causes SSH client to operate completely inside a Virtual Machine, but behave on User Side as if operating on host machine as usual. 


#Instruction   
start vm as follows:  
sudo qemu-system-x86_64 -enable-kvm -m 4000 -boot c -hda ubuntu_guest.img -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -object memory-backend-file,size=1M,share,mem-path=/dev/shm/ivshmem,id=hostmem -device ivshmem-plain,memdev=hostmem     
  
ssh from host   
ssh -p 5555 tushargr@127.0.0.1   
