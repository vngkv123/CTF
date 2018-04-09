" Install vim-plug
set nocompatible
call plug#begin()

" UI
Plug 'vim-airline/vim-airline'
let g:airline_powerline_fonts = 1
Plug 'tomasr/molokai'
let g:molokai_original = 1
let g:rehash256 = 1

" Feature
Plug 'Shougo/vimproc.vim', {'do' : 'make'}
Plug 'Shougo/denite.nvim', {'do' : ':UpdateRemotePlugins'}
Plug 'majutsushi/tagbar'
let g:tagbar_show_linenumbers = 1
Plug 'mbbill/undotree'
if has("persistent_undo")
    set undodir=~/.undodir/
    set undofile
endif
Plug 'w0rp/ale'
set statusline+=%{ALEGetStatusLine()}

" Autocomplete
Plug 'SirVer/ultisnips'
let g:UltiSnipsJumpForwardTrigger="<Tab>"
Plug 'honza/vim-snippets'
Plug 'Shougo/deoplete.nvim', {'do' : ':UpdateRemotePlugins'}
let g:deoplete#enable_at_startup = 1

" Hotkey
Plug 'vim-scripts/auto-pairs'
Plug 'scrooloose/nerdcommenter'
let g:NERDSpaceDelims = 1
Plug 'michaeljsmith/vim-indent-object'
Plug 'ervandew/supertab'
let SuperTabMappingForward="<S-Tab>"
Plug 'easymotion/vim-easymotion'
let g:EasyMotion_smartcase = 1

" Python
Plug 'hdima/python-syntax',{'for': ['python']}
let python_highlight_all = 1
Plug 'zchee/deoplete-jedi',{'for': ['python']}

call plug#end()

filetype plugin indent on

" Hotkey
map  /       <Plug>(easymotion-sn)
omap /       <Plug>(easymotion-tn)
nmap ;       :
vmap ;       :
nmap \       zR
map  n       <Plug>(easymotion-next)
map  N       <Plug>(easymotion-prev)
nmap <C-/>   :Denite grep:.<cr>
nmap <C-a>   ggVG
nmap <C-k>   H<Plug>(easymotion-w)
nmap <C-l>   :nohl<CR>
nmap <C-p>   :Denite file_rec<cr>
"Hot key edit C-t
nmap <C-r>   :TagbarToggle<CR><C-w>l
nmap <C-y>   :set paste!<CR>
nmap <C-5>   :set fileencoding=big5<CR>
nmap <C-8>   :set fileencoding=utf8<CR>
nmap <Enter> za
vmap <Enter> <Plug>(EasyAlign)

" Evil shift!
cab Q   q
cab Qa  qa
cab W   w
cab X   x
cab WQ  wq
cab Wq  wq
cab wQ  wq
cab Set set

" Setting
let mapleader=" "                      " leader key
syntax on                              " Color syntax
color molokai                          " Theme
set backspace=start,eol,indent         " Backspcae
set clipboard=unnamed                  " Clipboard
set cursorline                         " height corrent line
set encoding=utf-8                     " Necessary to show Unicode glyphs
set fileencodings=utf8,big5,gbk,latin1 " set fileopentype
set hls                                " search heightlight
set ignorecase                         " ignore case in search
set incsearch                          " search back
set laststatus=2                       " Always show the statusline
set mouse=a                            " Use mouse
set number                             " Line number
set ruler                              " show line info
set scrolloff=5                        " scroll while close under
set showcmd                            " show command
set smartindent                        " Autoindent
set t_Co=256                           " Explicitly tell Vim that the terminal supports 256 colors
set timeoutlen=300                     " escape delay
set wildmenu                           " Autocomplete menu

" Tab
set expandtab
set shiftwidth=4
set softtabstop=4
set tabstop=4

" Folding
set foldenable
set foldmethod=indent
set foldcolumn=1
set foldlevel=4

" Filetype Related
autocmd FileType python setlocal et sta  sw=4 sts=4 cc=80 completeopt-=preview
autocmd FileType html   setlocal et sw=2 sts=2
autocmd FileType ruby   setlocal et sw=2 sts=2

" Run File
autocmd filetype ruby       nnoremap <C-c> :w <bar> exec '!ruby '.shellescape('%')<CR>
autocmd filetype javascript nnoremap <C-c> :w <bar> exec '!node '.shellescape('%')<CR>
autocmd filetype shell      nnoremap <C-c> :w <bar> exec '!bash '.shellescape('%')<CR>
autocmd filetype php        nnoremap <C-c> :w <bar> exec '!php  -f '.shellescape('%')<CR>
autocmd filetype python     nnoremap <C-c> :w <bar> exec 'term  python '.shellescape('%')<CR>
autocmd filetype c          nnoremap <C-c> :w <bar> exec '!gcc  -o %:r '.shellescape('%').' -std=c11 -Ofast -Wall && ./%:r'<CR>
autocmd filetype cpp        nnoremap <C-c> :w <bar> exec '!g++  -o %:r '.shellescape('%').' -std=c++14 -Ofast -Wall && ./%:r'<CR>

"set tags=/shared/web/v8/tags
set tags=/shared/linux-4.14.11/tags
