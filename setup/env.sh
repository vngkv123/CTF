#!/bin/bash 
#
cd $HOME
sudo apt-get -y update
sudo apt-get -y upgrade
sudo pip3 install ropper
apt-get -y install libssl1.0.0 libssl1.0.0:i386
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
apt-get -y install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
pip install --upgrade pip
pip install --upgrade pwntools
sudo pip install ropgadget
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/
git clone https://github.com/vngkv123/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
git clone https://github.com/JonathanSalwan/ROPgadget
cd ~/
git clone https://github.com/BinaryAnalysisPlatform/qira.git
cd qira/
./install.sh
sudo apt-get -y install python-dev libffi-dev build-essential virtualenvwrapper
mkdir ~/.environments
sudo find / -name "virtualenvwrapper.sh"
/usr/share/virtualenvwrapper/virtualenvwrapper.sh
echo source /usr/share/virtualenvwrapper/virtualenvwrapper.sh >> ~/.bashrc
echo export WORKON_HOME="~/.environments" >> ~/.bashrc
source ~/.bashrc
mkvirtualenv angr && pip install angr
apt-get -y install ruby
apt-get -y install gem
sudo apt-get -y install ruby-dev
gem install one_gadget
gem install seccomp-tools
sudo apt-get -y install vim
sudo apt-get -y install ctags

# vim setting
sudo apt-get install git curl -y
sudo apt-get install build-essential cmake python-dev silversearcher-ag -y
wget http://tamacom.com/global/global-6.3.3.tar.gz
tar -xvf global-6.3.3.tar.gz
cd global-6.3.3
sudo ./configure && make 
sudo make install && cd
git clone https://github.com/gmarik/vundle.git ~/.vim/bundle/vundle
git clone https://github.com/scwuaptx/vimrc

cd vimrc
cp .vimrc ~/.vimrc
vim +PluginInstall +qall
cd ~/.vim/bundle/vimproc.vim/ 
make
cd vimrc
sudo apt-get install python-fontforge -y
wget https://github.com/Lokaltog/powerline-fonts/raw/master/UbuntuMono/Ubuntu%20Mono%20derivative%20Powerline.ttf
~/.vim/bundle/vim-powerline/fontpatcher/fontpatcher Ubuntu\ Mono\ derivative\ Powerline.ttf
cd
mkdir ~/.fonts
cp vimrc/*Powerline-Powerline.ttf ~/.fonts/
sudo fc-cache -vf
vim +PowerlineClearCache +qall
cp -rf vimrc/snippets ~/.vim/
