make
sudo rmmod host_module
sudo insmod host_module.ko
sudo dmesg -c &> /dev/null

