# Vim setting

**OS X**
- https://raw.githubusercontent.com/scwuaptx/vimrc/master/install-mac.sh
```
#!/bin/bash
#
sudo brew update
sudo brew install curl
sudo brew install global
git clone https://github.com/gmarik/vundle.git ~/.vim/bundle/vundle
git clone https://github.com/scwuaptx/vimrc

cd vimrc
cp .vimrc-mac ~/.vimrc
vim +PluginInstall +qall
cd ~/.vim/bundle/vimproc.vim/ 
make
cd vimrc
cp -rf vimrc/snippets ~/.vim/
```

**Ubuntu**
- https://raw.githubusercontent.com/scwuaptx/vimrc/master/install.sh
```
#!/bin/bash
#
sudo apt-get update
sudo apt-get upgrade -y 
sudo apt-get install git curl -y
sudo apt-get install build-essential cmake python-dev silversearcher-ag -y
wget http://tamacom.com/global/global-6.3.3.tar.gz
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
```
