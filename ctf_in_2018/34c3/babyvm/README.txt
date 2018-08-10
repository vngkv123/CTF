We are giving you access to a box created via vagrant + VirtualBox.
The flag is in the file /flag on the host.

How to create base box (babyvm):

  cd basebox
  ./build.sh

How to spawn a VM locally:

  cd victimbox
  vagrant up
  vagrant ssh

You can solve the challenge offline and then exploit it remotely once.
To get access to a remote VM:

  socat tcp4:178.63.8.31:1337 -,raw,echo=0
