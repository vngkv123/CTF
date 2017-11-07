# my env setting

**env.sh script**
- copy to your env.sh file
- chmod to exec this script
- ./env.sh

```
gef option
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

```
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
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
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
gem install one_gadget
sudo apt-get -y install vim
sudo apt-get -y install ctags
sudo apt-get install volatility pintool binwalk
git clone https://github.com/Z3Prover/z3.git
cd z3
virtualenv venv
source venv/bin/activate
python scripts/mk_make.py --python
cd build
make
make install
```

**if can't install z3**
```
virtualenv venv
source venv/bin/activate
python scripts/mk_make.py --python
cd build
make
make install
```

# vim setting
**git clone**
- `git clone https://github.com/VundleVim/Vundle.vim.git ~/.vim/bundle/Vundle.vim`
- write below script via `sudo vi ~/.vimrc`
**main script in .vimrc**
```
syntax on
set nocompatible
" set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
" alternatively, pass a path where Vundle should install plugins
"call vundle#begin('~/some/path/here')
" let Vundle manage Vundle, required
Plugin 'gmarik/Vundle.vim'
" The following are examples of different formats supported.
" Keep Plugin commands between vundle#begin/end.
" plugin on GitHub repo
Plugin 'tpope/vim-fugitive'
" plugin from http://vim-scripts.org/vim/scripts.html
Plugin 'L9'
" Git plugin not hosted on GitHub
Plugin 'git://git.wincent.com/command-t.git'
" git repos on your local machine (i.e. when working on your own plugin)
Plugin 'file:///home/gmarik/path/to/plugin'
" The sparkup vim script is in a subdirectory of this repo called vim.
" Pass the path to set the runtimepath properly.
Plugin 'rstacruz/sparkup', {'rtp': 'vim/'}
 
" All of your Plugins must be added before the following line
call vundle#end()            " required
filetype plugin indent on    " required
" To ignore plugin indent changes, instead use:
"filetype plugin on
"
" Brief help
" :PluginList       - lists configured plugins
" :PluginInstall    - installs plugins; append `!` to update or just
" :PluginUpdate
" :PluginSearch foo - searches for foo; append `!` to refresh local cache
" :PluginClean      - confirms removal of unused plugins; append `!` to auto-approve removal
"
" see :h vundle for more details or wiki for FAQ
 
Plugin 'The-NERD-tree'
Plugin 'AutoComplPop'
let NERDTreeWinPos = "left"
nmap <F7> :NERDTree<CR>
nmap <F8> :TlistToggle<CR>
filetype on
 
let Tlist_Ctags_Cmd = "/usr/bin/ctags"
let Tlist_Inc_Winwidth = 0
let Tlist_Exit_OnlyWindow = 0
let Tlist_Auto_Open = 0
let Tlist_Use_Right_Window = 1
 
set tabstop=4
set shiftwidth=4
set smartindent
set hlsearch
set ignorecase
set nu
```

**run this on your terminal**
- `vim +PluginInstall +qall`
