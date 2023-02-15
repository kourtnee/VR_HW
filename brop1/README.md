# BROP1:Solution

This is the output from connecting the the remote server, since there's no binary to analyze:
```
--------------------------------------------------------------------------------
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNXK0OOOOOO0KXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWWXOxoc:;;,,,,,,;;:coxOXWMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWXOo:;,,,,,,,,,,,,,,,,,,;:oOXWMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMWXxc;,,,,,,,,,,,,,,,,,,,,,,,,;cxXWMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMWNkc,,,,,,,,,,,,,,,,,,,,;clddc,,,;ckNWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWXd;,,,,,,,,,,,,,,;:cloxOKXWWWk;,,,,;dXWMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMXo;,,,,,,,,,,,,;lk0XNNWMMMMMMWk;,,,,,;oXMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMNx;,,,,,,,,,,,,,;kWWMMMMMMMMMMWk;,,,,,,;xNMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMW0c,,,,,,,,,,,,,,:kWMMMMMMWWNXNNk;,,,,,,,c0WMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWx;,,,,,,,,,,,,,,:kWWNXX0kxoccxNk;,,,,,,,;xWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,,,,,,,,,,,,,,,;kXklc:;,,,,;xXk;,,,,,,,,dNMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd;,,,,,,,,,,,,,,:kKd,,,,;ldxkKNk;,,,,,,,;dNMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWk:,,,,,,,,,,,,,,;kKd,,;o0NWMMMNx;,,,,,,,:kWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWKl,,,,,,,,,,;cldxKXd,,lKWMMMWNOl,,,,,,,,lKMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWOc,,,,,,,;oOXWWMWXd,,:d0KKOxo:,,,,,,,,cOWMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWOc,,,,,,dXWMMMMNOc,,,,;;;,,,,,,,,,,,cOWMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMW0l;,,,,lOKXX0ko:,,,,,,,,,,,,,,,,,;l0WMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXxc,,,,;:::;,,,,,,,,,,,,,,,,,,,cxXWMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWKxl;,,,,,,,,,,,,,,,,,,,,,,;lkKWMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWN0xo:;,,,,,,,,,,,,,,;:ox0NWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWX0kxdollllllodxk0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
--------------------------------------------------------------------------------
                             address of printf() 0x7f8d59fb5700 
                              address of puts() 0x7f8d59fdc9e0 
--------------------------------------------------------------------------------
                        I was young, but I wasn't naive
                I watched helpless as you turned around to leave
                   And still I have the pain I have to carry
                              - Blind, Lifehouse 
--------------------------------------------------------------------------------
```

Since one of the addresses given is the puts() function, it seems like this should be a ret2puts/ret2libc exploit. 

Resources:
* Class slides 
* Louie
* Chandler
* 
