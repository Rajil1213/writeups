# Writeup for Bandit Labs on [OverTheWire](http://www.overthewire.org/)

## 1 Level 0

### Problem Statement

The goal of this level is for you to log into the game using SSH. The host to which you need to connect is [bandit.labs.overthewire.org](http://bandit.labs.overthewire.org/), on port 2220. The username is bandit0 and the password is bandit0. Once logged in, go to the Level 1 page to find out how to beat Level 1.

Relevant commands: `ssh`

### Solution

```bash
$ ssh -p 2220 bandit0@bandit.labs.overthewire.org
password: bandit0 ## won't be visible while typing
```

### Explanation

The output shown above is overly simplified. But the only part of the output that matters is the prompt for the password where we type in the password: bandit0. The `-p` flag allows us to access the server on a specific port (the default is port 22).

## 2 Level 0 → Level 1

### Problem Statement

The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

Relevant Commands: `ls` , `cat`

### Solution

```bash
$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
$ ssh bandit1@bandit.labs.overthewire.org
```

### Explanation

The `cat` command outputs the content of a file to the standard output (when the output is not piped or redirected). Thus, we can view the contents of the file in the terminal itself.

## 3 Level 1 → Level 2

### Problem Statement

The password for the next level is stored in a file called - located in the home directory

Relevant Commands: `ls` , `cd` , `cat` , `file`

### Solution

```bash
$ cat ~/-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
$ ssh bandit2@localhost ## localhost => this computer => bandit.labs.overthewire.org
```

### Explanation

As `-` is a special character, we have to mention the full path to let the command-line know that we are referring to the file named `-` .

## 4 Level 2 → Level 3

### Problem Statement

The password for the next level is stored in a file called *spaces in this filename* located in the home directory

Relevant Commands: `ls` , `cd` , `cat` , `file`

### Solution

```bash
$ cat "spaces in this filename"
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
$ ssh bandit3@localhost
```

### Explanation

As the file name contains spaces, the name of the file must be enclosed within quotation marks so that the `cat` command views spaces as a part of the filename.

## 5 Level 3 → Level 4

### Problem Statement

The password for the next level is stored in a hidden file in the *inhere* directory.

Relevant Commands: `ls` , `cd` , `cat` , `file`

### Solution

```bash
$ cd inhere
$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

### Explanation

As the file is hidden, `ls` does not display it directly. We must use the the flag `-a` to view *all* the files (even the hidden files *a.k.a.* files prefixed with a period). In this case, we list the all the files within the `inhere` directory and `cat` the hidden file.

## 6 Level 4 → Level 5

### Problem Statement

The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

Relevant Commands: `ls` , `cd` , `cat` , `file` , `du`

### Solution

```bash
$ cd inhere
$ file ./* ## only part of the output is shown below
...
./-file06: data
./-file07: ASCII text
./-file08: data
...
$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

### Explanation

We first investigate the file types of each file in the `inhere` directory using the `file` command. As the filenames contain a hyphen, we specify the full path and a wildcard character `*` which is a placeholder for any number of characters, thus denoting all files in the current directory. We see that `./-file07` is the only human readable i.e., ASCII text file. So, we `cat` this file to get the password for the next level.

## 7 Level 5 → Level 6

### Problem Statement

The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:

- human-readable
- 1033 bytes in size
- not executable

Relevant Commands: `ls` , `cd` , `cat` , `file`, `find`

### Solution

```bash
$ cd inhere
$ find . -type f -size 1033c
./maybehere07/.file2
$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

### Explanation

We have to find a human readable file with a size of 1033 bytes that is not executable. Luckily, in this case, there's only file with an exact size of 1033 bytes is present in the `inhere` directory which is the file that we need.  

## 8 Level 6 → Level 7

### Problem Statement

The password for the next level is stored **somewhere on the server** and has all of the following properties:

- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

Relevant Commands: `ls` , `cd` , `cat` , `file`, `find` , `grep`

### Solution

```bash
$ cd ../.. ## going from /home/bandit6 to /
$ find . -type f -size 33c -user bandit7 -group bandit6 2> ./dev/null
./var/lib/dpkg/info/bandit7.password
$ cat ./var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

### Explanation

As before, we find a file with the size of 33 bytes (here, `c` stands for bytes), owned by `bandit7` and with the group `bandit6` using appropriate flags with the `find` command in the root directory. The `2` towards the end of the command refers to any errors in the preceding command's output that get redirected (`>`) to the `./dev/null` directory where they essentially disappear.

## 9 Level 7 → Level 8

### Problem Statement

The password for the next level is stored in the file **data.txt** next to the word **millionth**

Relevant Commands: `grep` , `sort`, `find`

### Solution

```bash
$ cat data.txt | grep millionth -n
37262:millionth cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

### Explanation

We pipe the result of `cat` -ing `data.txt` to the `grep` command that finds within the supplied text the line containing the word `millionth` and also its line number with the flag `-n` (not mandatory to include this flag).

## 10 Level 8 → Level 9

### Problem Statement

The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

Relevant Commands: `grep` , `sort`, `find` , `uniq`

### Solution

```bash
$ sort data.txt | uniq -c ## only part of the output shown below
...
10 U0NYdD3wHZKpfEg9qGQOLJimAJy6qxhS
10 UASW6CQwD6MRzftu6FAfyXBK0cVvnBLP
10 UJiCNvDNfgb3fcCj8PjjnAXHqUM63Uyj
10 UjsVbcqKeJqdCZQCDMkzv6A9X7hLbNE4
1 UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
10 UVnZvhiVQECraz5jl8U14sMVZQhjuXia
10 V2d9umHiuPLYLIDsuHj0frOEmreCZMaA
10 v9zaxkVAOdIOlITZY2uoCtB1fX2gmly9
10 VkBAEWyIibVkeURZV5mowiGg6i3m7Be0
...
```

### Explanation

We display the unique lines present in the given text and also the number of times they occur in the said text using the `uniq` command with the flag `c` . However, this command only counts contiguous groups of duplicate lines. What this means is that if a file contains four lines, namely `a`, `a` , `b` , `a` , the output of running `uniq -c` on this file would be:

```bash
2 a
1 b
1 a
```

Thus, we see that this command considers the fourth `a` unique because there is no `a` adjacent to it, while the two adjacent `a` 's at the beginning are displayed once with a count of 2.

So, we must first sort the `data.txt` file so that all the duplicates become adjacent to each other and the `uniq` command shows them only once with the correct count. Without the sort statement, this command will show an output count of 1 for each line as none of these duplicates are adjacent to each other.

## 11 Level 9 → Level 10

### Problem Statement

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

Relevant Commands: `find` , `grep` @Rajil Bajracharya also checkout `strings`

### Solution

```bash
$ cat data.txt | grep -a =
...
����W�x��Ǖ========== password�b���;�##6�����Q�c�a��##|-l�G}`:�(��g
                                                               ��3���T��t���ѿn��u��.�##���!6�t�6IM*�5�/�`D�   mL���a���TS�˖��*��x��������S�y�LN��
go'�
����SI���▒�"##?�s��F[[�p �s)욱�<�4���x�Xz���4�����y�&^���ͱ��/1��▒ԅ�����(�[�      R�                                                                             L����D��d5�N�\�H1�Kt�.��1��H�,
Ȃ&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```

### Explanation

As the file contains non-human readable text, we must tell `grep` to read the binary file as a text file and then search for instances of the equal sign `=` . This is done by using the flag `-a`.

## 12 Level 10 → Level 11

### Problem Statement

The password for the next level is stored in the file data.txt, which contains base64 encoded data

Relevant Commands: `base64`

### Solution

```bash
$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIElGdWt3S0dzRlc4TU9xM0lSRnFyeEUxaHhUTkViVVBSCg==
$ base64 -d data.txt
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

### Explanation

We decode the base-64 encoded text using the `-d` flag on the `base64` command.

## 13 Level 11 → Level 12

### Problem Statement

The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

Relevant Material: `tr` , `ROT13`

### Solution

```bash
$ cat data.txt | tr  'N-ZA-Mn-za-m' 'A-Za-z'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EU
```

### Explanation

As each letter in the file is rotated by 13 positions, the letter 'A' becomes 'N', 'B' becomes 'O' and so on cycling back to 'A' when the 13 rotations results in the letter exceeding the 'Z' position (i.e., 'N' becomes 'A'). So, to decode this text, we rotate each letter in the text back by 13 positions using the `tr` command along with the appropriate transformation rule.

## 14 Level 12 → Level 13

### Problem Statement

The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!)

Relevant Commands: `xxd` , `gzip` , `bzip` , `tar`

### Solution

```bash
## only part of the output shown below
$ cd /tmp
$ xxd -r data.txt > level0 ## reverse hex dump
$ file level0
level0: gzip compressed data...
$ mv level0 level0.gz
$ gzip -d level0.gz
$ file level0
level0: bzip2 compressed data...
$ mv level0 level1.bzip2
$ bzip2 -d level1.bzip2
$ file level1.bzip2.out
level1.bzip2.out: gzip compressed data...
$ mv level1.bzip2.out level2.gz
$ gzip -d level2.gz
$ file level2
level2: POSIX tar archive (GNU)
$ mv level2 level3.tar
$ tar -xvf level3.tar ## extract(x) verbose(v) file(f)
...
level8: ASCII text
$ cat level8
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

### Explanation

As we don't have permission to write anything to the home directory, we must first 'change' into the `/tmp` directory. Then, as the file is the hexdump of a multiply compressed file, we first perform a reverse hexdump on the file and then redirect the output to another file. As we do not know what kind of compressed file this produces, we perform `file` operation on it. Then, we change its extension to reflect its type and decompress it using the appropriate command. We repeat this until we obtain an ASCII text file.

*Spoiler Alert*: The file has been compressed EIGHT times using three different tools: `bzip2`, `gzip` and `tar`.

## 15 Level 13 → Level 14

### Problem Statement

The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on

Relevant Commands: `ssh`

### Solution

```bash
bandit13@bandit: ~$ ssh -i sshkey.private bandit14@localhost
```

### Explanation

The `-i` flag allows us to use an RSA key file to access the relevant server.

## 16 Level 14 → Level 15

### Problem Statement

The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

Relevant Commands: `nc`

### Solution

```bash
bandit14@bandit: ~$ cat /etc/bandit_pass/bandit14 | nc localhost 30000
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

### Explanation

The `netcat` or `nc` command allows us to `cat` to a specified IP address and port number. Here, we cat the password for the current level i.e., bandit14 to the [localhost](http://localhost) (bandit.labs.overthewire.org) at the port 30000.

## 17 Level 15 → Level 16

### Problem Statement

The password for the next level can be retrieved by submitting the password of the current level to **port 30001 on localhost** using SSL encryption.

**Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…**

Relevant Commands: `openssl` , `s_client`

### Solution

```bash
$ openssl s_client -connect localhost:30001
CONNECTED(00000003)
depth=0 CN = localhost
...
---
BfMYroe26WYalil77FoDi9qh59eK5xNr ## paste current password here
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd
```

### Explanation

As the port is encrypted with SSL this time, we use the `openssl` command with the `s_client` on [localhost](http://localhost) at the port 30000. These commands in conjunction allow us to communicate with a remote server speaking SSL. Then, we paste the password to the current level which then returns the password to the next level.

## 18 Level 16 → Level 17

### Problem Statement

The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

Relevant Commands: `openssl`, `s_client` , `nmap`

### Solution

```bash
$ nmap -sC -sV -p31000-32000 localhost
31691/tcp open  echo
31790/tcp open  ssl/unknown
| fingerprint-strings: 
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq: 
|_    Wrong! Please enter the correct current password
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2020-05-14T12:03:38
|_Not valid after:  2021-05-14T12:03:38
|_ssl-date: TLS randomness does not represent time
31960/tcp open  echo
1 service unrecognized despite returning data.

$ openssl s_client -connect localhost:31790
BfMYroe26WYalil77FoDi9qh59eK5xNr ## paste password here
===BEGIN RSA KEY=== ## returns RSA private key to next level; not shown here; copy this key including the 'BEGIN' and 'END' lines
$ cd /tmp
$ touch key.txt
$ nano key.txt ## opens file for editing, paste the RSA key here
$ chmod -c 600 key.txt ## as key must be secure, make it only readable and executable, that too by the owner only
$ ssh -i key.txt bandit17@localhost
```

### Explanation

In this level, we don't know which port is open and is configured for SSL communication. We can obtain this information using the `nmap` command with the flag `-sC` to run the default set of scripts (written in Lua) and `-sV` to determine the service type and the version of the *open* ports, within the range of 31000 and 32000 using the `-p` flag. We see that the port `31790` is the port that meets the specification. We run `openssl` here just like in the previous level on this port and paste the current password. This time, this action returns the private RSA key to the next level. As we can only submit a sshkey file using the `ssh` command, we copy this key (including the BEGIN and END lines) to a new file we create in `/tmp`. Then, as this file needs to be secure, we change the permissions on this file so that only the owner can access it and even then, can only read and execute it. Then, we submit this file over `ssh` to the next level's server. 

## 19 Level 17 → Level 18

### Problem Statement

There are 2 files in the homedirectory: **passwords.old and passwords.new**. The password for the next level is in **passwords.new** and is the only line that has been changed between **passwords.old and passwords.new**

**NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19**

Relevant Commands: `cat` , `grep` , `diff`

### Solution

```bash
$ diff --supress-common-lines passwords.new passwords.old
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
$ ssh bandit18@localhost
```

### Explanation

We can find the lines that are different between the specified files using the `diff` command using the `--suppress-common-lines` flag to only show the different lines. In the output `<` refers to the file used as the left command line argument and `>` refers to the one on the right. We copy the one referring to the file `[passwords.new](http://passwords.new)` and use it to login to the next level. However, we immediately get logged out and a 'Bye bye!' is displayed in the terminal, along with the login information for the next level.

## 20 Level 18 → Level 19

### Problem Statement

The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

Relevant Commands: `ssh`, `cat`

### Solution

```bash
bandit17@bandit: ~$ ssh bandit18@localhost "cat ~/readme"
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

### Explanation

As any attempt to login to `level 18` logs us out immediately. We chain a `cat` command to the `ssh` command from the next level so that even if we are logged out, we can still view the contents of the `readme` file in `bandit 19`'s home directory which contains the password to the next level. (notice that we run the command from `bandit17` in the above section and *not* from `bandit18`)

## 21 Level 19 → Level 20

### Problem Statement

To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

### Solution

```bash
$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```

### Explanation

The `setuid` sets the user id for `bandit19` to be that of `bandit20` so that for all intents and purposes, bash thinks that we are `bandit20` allowing us to do everything `bandit20` can including accessing its password in the `/etc/bandit_pass/bandit20` file.

## 22 Level 20 → Level 21

### Problem Statement

There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

**NOTE:** Try connecting to your own network daemon to see if it works as you think

Relevant Commands: `nmap`, `nc`

### Solution

```bash
$ nmap localhost
Starting Nmap 7.40 ( https://nmap.org ) at 2020-06-05 06:40 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00031s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
113/tcp   open  ident
30000/tcp open  ndmps
Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
$ echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -lv -p 60000 & ## l => configure host device to listen on the specified port
[1] 16136
bandit20@bandit:~$ listening on [any] 60000 ...
./suconnect 60000
connect to [127.0.0.1] from localhost [127.0.0.1] 56312
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
[1]+  Done    echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -lv -p 60000 
```

### Explanation

To complete this level, we first setup a client-server connection on an unused port. On using the `nmap` command, we see that only 3 ports have been opened. Barring these three, we select a random port (here, `60000`) and configure to listen for a connection using `nc` . On this port, we `echo` the password for the current level. The `&` runs this command in the background providing us access to the terminal for further commands to be typed. Once set up, we then, run the `suconnect` binary in the home directory on this port which reads the previously `echo`'d password and then, returns the password for the next level.

## 23 Level 21 → Level 22

### Problem Statement

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

Relevant Material: `cron`, `crontab` , `bash`

### Solution

```bash
$ cd /etc/cron.d
$ cat cronjob_bandit22
***** bandit 22 /usr/bin/cronjob_bandit22.sh &> /dev/null
$ cat /usr/bin/cronjob_bandit22.sh
##!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgvcat
/etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
$ cat t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
$ Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

### Explanation

We first change into the `/etc/cron.d` directory and `cat` the `cronjob_bandit22` file. We see that its contents of the file `/usr/bin/cronjob_bandit22.sh` file. When we open this file, it reveals a bash file that redirects the contents of `bandit22`'s password file to the file `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` the contents of which reveals the password for the next level.

## 24 Level 22 → Level 23

### Problem Statement

A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

**NOTE:** Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

Relevant Material: `cron` , `crontab` , `crontab(5)` (use " man 5 crontab"), `bash` 

### Solution

```bash
$ cat /etc/cron.job/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
$ cat /usr/bin/cronjob_bandit23.sh
##!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1

8ca319486bfbbc3663ea0fbe81326349
$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n 
```

### Explanation

As before, we investigate the contents of the file referenced by the file `/etc/cron.job/cronjob_bandit23`, in this case `/usr/bin/cronjob_bandit23.sh`. This reveals another shell script  that copies the password of the next level to the `$mytarget` defined by the line `$(echo I am user $myname | md5sum | cut -d ' ' -f 1)`. If unaware of the syntactical details, we can run this line on the terminal to see what it yields so that we know where the password file is located, as done above. It is, however, useful to know the meaning of this command. This command pipes the text `I am user bandit23` to `md5sum` that computes an MD5 checksum for this text. The resulting output is then piped to the `cut` command that uses a space ' ' as the delimiter (`-d`) to split the text and extracts the first (`1`) segment from the resulting split. We then cat the corresponding file in `tmp` to get the password to the next level.  

## 25 Level 23 → Level 24

### Problem Statement

A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

**NOTE:** This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!

**NOTE 2:** Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

Relevant Material: `cron` , `crontab` , `crontab(5)` (use " man 5 crontab"), `bash` 

### Solution

```bash
$ cat /etc/cron.d/cronjob_bandit24
$ cat /usr/bin/cronjob_bandit24.sh
##!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done

$ cd tmp
$ mkdir rb
$ touch bandit24key
$ touch bandit24key.sh
$ nano bandit24key.sh

##!/bin/bash

cat /etc/bandit_pass/bandit24 >> /tmp/rb/bandit24key

$ chmod -c 777 bandit24key.sh
$ chmod -c 777 bandit24key
$ cp /tmp/rb/bandit24key.sh /var/spool/bandit24/
$ cat /tmp/rb/bandit24key
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

### Explanation

The job file in `bandit24` references a bash script that is run by `bandit24` every minute. The script basically executes and then, deletes every script in the `/var/spool/bandit24` directory one at a time. So, the trick is to include a bash script within this directory that copies the password for `bandit24` into an accessible file in `/tmp`. The script in `[bandit24key.sh](http://bandit24key.sh)` shown above does this. However, we must allow `bandit24` to execute the script created by us (`bandit23`). We thus change the permissions on this script. Now, we check if the file exists in the `/var/spool/bandit24` directory and wait for it to be deleted by `bandit24` upon execution. After this, we should be able to access the password to the next level.

## 26 Level 24 → Level 25

### Problem Statement

A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

Relevant Material: `for` , `do` , `nc` , `bash` , `while`

### Solution

```bash
$ for i in {0000..9999}; do echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i >> /tmp/passpin24; done;

nc localhost 30002 < /tmp/passpin24
...
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG 
```

### Explanation

To evaluate the 10000 possibilities for the password-pin pairs, we create a file which contains all these possibilities written on it using a `for` loop to automate the process. The `for` loop variable `i` takes on each value from `0000` to `9999` which is then prefixed with the password for the current level and then written into a file in `/tmp` where we have write-access. We then send this file as an input to the port `30002` on `[localhost](http://localhost)` that takes each line from this file tries it and displays the corresponding output. 

## 27 Level 25 → Level 26 → Level 27

### Problem Statement

**25 → 26**

Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not `/bin/bash`, but something else. Find out what it is, how it works and how to break out of it.

**26 → 27**

Good job getting a shell! Now hurry and grab the password for bandit27!

Relevant Material: `ssh` , `bash` , `sh` , `vi`

### Solution

```bash
$ ssh -i bandit26.sshkey bandit26@localhost ## logs you in and then immediately logs you out
$ cat /etc/passwd ## investigate the shell for bandit26
...
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
...
$ cat /usr/bin/showtext
##!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
## now minimize the terminal to the point that the content of text.txt i.e.,
## 'bandit26' graphic is not completely displayed
## and a (more) option is shown
## then, type 'v' to open a vim editor
## then type:
:set shell=/bin/bash
:shell
$ ls ## shows a binary bandit27-do
## use this setuid binary to access password for bandit27
$ bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```

### Explanation

Logging into level 26 is easy as it is similar to [Level 13 → Level 14](##15-Level-13-→-Level-14). But the shell for `bandit26` is not the usual `/bin/bash`. So, we have to access it indirectly! First, we investigate what the shell script is by accessing the contents of `/etc/passwd` which reveals that the shell for `bandit26` is actually a text file which displays the graphic `bandit26`. Now, to access the normal shell we must get the *more* option that allows us to access the `vim` editor where we can run *shell commands.* To access this, we minimize the window to a size where the graphic isn't fully displayed. Then, once that graphic does appear, we get the (more) option. Then, we type `v` to access the vim editor. In the editor, we go to the command mode (if not already there) using the `ESC` key and type the following commands

```bash
:set shell=/bin/bash
:shell
## to exit vim, type ESC to go to the command mode (if not already there)
## then type the following:
## :q!
## this means quit without saving any changes made
```

This opens up the normal shell when we can run commands. We see that there is a setuid binary called `bandit27-do` in the home directory which we can use to run commands as `bandit27`. Thus, we can access the password for `bandit27`.

## 28 Level 27 → Level 28

### Problem Statement

There is a git repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo`. The password for the user `bandit27-git` is the same as for the user `bandit27`.

Clone the repository and find the password for the next level.

Relevant Commands: `git`, `clone`

### Solution

```bash
$ cd /tmp
$ mkdir rb
$ cd rb
$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo
$ mv repo repo28 ## helps to rename for more cloning in subsequent levels
$ cd repo28
$ cat README
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2
```

### Explanation

As before, we don't have write-permission on the `home` directory. So, we change into the `/tmp` directory. Here, it is advisable to create a new directory wherein we can store our repos. This helps in the event that there is already a directory called `repo` in the `/tmp` directory (which we cannot see using the `ls` command because we do not have permission to do so in the `/tmp` directory). Now, we clone the git repo using the `clone` command which creates a new directory called `repo`. It is also advisable to rename this directory as subsequent levels require us to clone more repos which all result in the creation of a directory named `repo`. The password is located in the only file present in the `repo` directory, named README.

## 29 Level 28 → Level 29

### Problem Statement

There is a git repository at `ssh://bandit28-git@localhost/home/bandit28-git/repo`. The password for the user `bandit28-git` is the same as for the user `bandit28`.

Clone the repository and find the password for the next level.

Relevant Commands: `git` , `log`

### Solution

```bash
$ cd /tmp/rb
$ git clone ssh://banidt28-git@localhost/home/bandit28-git/repo
$ mv repo repo29
$ cd repo29
$ cat REAMDE.md
### credentials

username: bandit29
password: xxxxxxxxxx
$ git log -p -2 ## display first two commit logs
commit edd935d60906b33f0619605abd1689808ccdd5ee
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    fix info leak

diff --git a/README.md b/README.md
index 3f7cee8..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ### credentials

 - username: bandit29
-- password: bbc96594b4e001778eee9975372716b2
+- password: xxxxxxxxxx


commit c086d11a00c0648d095d04c089786efef5e01264
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    add missing data

diff --git a/README.md b/README.md
index 7ba2d2f..3f7cee8 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ### credentials

 - username: bandit29
-- password: <TBD>
```

### Explanation

As opposed to the previous level, the README file in this repo is a markdown file where the password is mentioned using a series of x's. As there are no other files to investigate, we look at the commit log to see if the file contained the plaintext password in its edit history using the `log` command. This reveals the password.

## 30 Level 29 → Level 30

### Problem Statement

There is a git repository at `ssh://bandit29-git@localhost/home/bandit29-git/repo`. The password for the user `bandit29-git` is the same as for the user `bandit29`.

Clone the repository and find the password for the next level.

Relevant Commands: `git` , `branch` , `checkout`

### Solution

```bash
$ git clone git clone ssh://banidt29-git@localhost/home/bandit29-git/repo
$ mv repo repo30
$ cd repo30
$ git branch -a
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
$ git checkout origin/dev
$ cat README.md

Bandit Notes
Some notes for bandit30 of bandit.

### credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
```

### Explanation

When we clone the repo for this level and investigate, all the steps involved in the previous levels fail to recover the password. So, we investigate other branches that may be present in this repo using `branch` command. However, this doesn't reveal all the branches. To reveal all the branches, we use the flag `-a`. We can then switch to these branches using the `chekout` command. On further investigation, we find that the password is available in the `README.md` file in the `origin/dev` branch.

## 31 Level 30 → Level 31

### Problem Statement

There is a git repository at `ssh://bandit30-git@localhost/home/bandit30-git/repo`. The password for the user `bandit30-git` is the same as for the user `bandit30`.

Clone the repository and find the password for the next level.

Relevant Material: `git` , `tag`

### Solution

```bash
$ cd /tmp/rb
$ git clone ssh://bandit30-git@localhost/home/bandit30-git/repo
$ mv repo repo31
$ cd repo31
$ git tag
secret
$ git cat-file -p secret ## pretty-print the contents of the tag object 'secret'
47e603bb428404d265f59c42920d81e5
```

### Explanation

In the repo for this level, the README file is basically empty, there is no mention of a password in its edit history and there is just one branch, the master branch. Thus, we investigate the `tag` objects associated with this repo using the `tag` command. We see that there is a single tag object called `secret`. On printing the contents of this `tag` object, we obtain the password for the next level.

## 33 Level 31 → Level 32

### Problem Statement

There is a git repository at `ssh://bandit31-git@localhost/home/bandit31-git/repo`. The password for the user `bandit31-git` is the same as for the user `bandit31`.

Clone the repository and find the password for the next level.

Relevant Commands: `git` , `push`

### Solution

```bash
$ cd /tmp/rb
$ git clone ssh://bandit31-git@localhost/home/bandit31-git/repo
$ mv repo repo32
$ cd repo
$ cat README.md
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
$ cat .gitignore
*.txt
$ rm .gitignore
$ touch key.txt
$ nano key.txt
May I come in?
$ git add key.txt
$ git commit -m "First commit to create key.txt"
$ git push origin master
...
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
...
```

### Explanation

The README for the repo in this level tells us that we ought to push a file called `key.txt` containing the text `May I come in?`. When looking at the contents of the file `.gitignore` we see that it contains a single line of text `*.txt` which basically tells git to not track changes in any file with the extension `.txt`. This is not ideal for us as we need to push a text file. So, we remove the `.gitignore` file. Then. we create the file using the `touch` command inside the repo and then, edit it using the `nano` command (using `CTRL+X` to exit after adding the required text and then, typing `Y` when prompted to save the changes). We then tell git to 'stage' the changes in `key.txt` using the `add` command, commit the staged changes along with a commit-message (`-m`) and then, push these changes to the master branch of the remote repo referenced by `origin`. The resulting message returns the password for the next level.

## 34 Level 32 → Level 33

### Problem Statement

After all this git stuff its time for another escape. Good luck!

Relevant Material: `sh`

### Solution

```bash
>> $0
$ whoami
bandit33
$ cat /etc/bandit_pass/bandit33
c9c3199ddf4121b10cf581a98d51caee
$ exit
>> ^C
```

### Explanation

Logging into the shell for `bandit32`, we see that we are greeted by an unfamiliar shell (the UPPERCASE shell) where every command we type is first converted to uppercase and then interpreted (`ls` becomes `LS`). As shell commands are case-sensitive, the shell doesn't recognize these uppercase commands and so we cannot type any command that involves alphabets. On reading the `man` page for `sh`, we see a section called *Special Parameters*. Of those mentioned, the character `$` and the number `0` are of interest. `$` invokes a sub-shell specified and `0` refers to the name of the shell. Thus, `$0` returns a subshell within the uppercase shell where we can type in the normal commands without them being converted to uppercase. When we run `whoami` on this shell, we see that we are actually running commands as `bandit33`. So, we can easily access the password for `bandit33` in the `/etc/bandit_pass/bandit33` directory.
