#!/bin/bash 
#
cd $HOME
sudo apt-get -y update
sudo apt-get -y upgrade
sudo pip3 install ropper
apt-get install libssl1.0.0 libssl1.0.0:i386
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
sudo apt-get -y install binutils nasm
sudo apt-get -y install gcc-multilib g++-multilib
sudo apt-get -y install libc6-dev-i386
sudo apt-get -y install git
sudo apt-get -y install libc6-dbg libc6-dbg:i386
sudo apt-get -y install nmap
sudo apt-get -y install python-pip libssl-dev
sudo apt-get -y install gdb
sudo pip install --upgrade pip
sudo pip install --upgrade capstone
apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
pip install --upgrade pip
pip install --upgrade pwntools
sudo pip install ropgadget
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/
git clone https://github.com/JonathanSalwan/ROPgadget
cd ~/
git clone https://github.com/BinaryAnalysisPlatform/qira.git
cd qira/
./install.sh
sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper
mkdir ~/.environments
sudo find / -name "virtualenvwrapper.sh"
/usr/share/virtualenvwrapper/virtualenvwrapper.sh
echo source /usr/share/virtualenvwrapper/virtualenvwrapper.sh >> ~/.bashrc
echo export WORKON_HOME="~/.environments" >> ~/.bashrc
source ~/.bashrc
mkvirtualenv angr && pip install angr
apt-get -y install ruby
apt-get -y install gem
sudo apt-get install ruby-dev
gem install one_gadget
gem install seccomp-tools
sudo apt-get -y install vim
sudo apt-get -y install ctags
sudo apt-get install volatility pintool binwalk
git clone https://github.com/Z3Prover/z3.git
cd z3
python scripts/mk_make.py
cd build
make
make install
