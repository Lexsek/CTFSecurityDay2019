# SecurityDay2019

## Informations :<br><br>
**Challenge** : Human.old<br>
**Description** : M0th3r > Bravo, grâce à toi, on a enfin sauvé Duke. C'est le moment de voir sa BaseLine. Qui se cachait réellement derrière Duke-083<br>
**Points** : 500<br>
**Solves** : 1<br>
**Contributeur** : Lexsek<br>

## Solutions :<br><br>

### Premiers pas :
On obtient un executable windows de type PE32 :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/file_pe32.png "file ReverseHub.exe")<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/icone.png "icone ReverseHub.exe")<br><br>

Lorsqu'on le charge dans IDA, un message apparait concernant l'IAT (Import Address Table) :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/packed_iat.png "iat ReverseHub.exe")<br><br>
IDA n'arrive dont pas à trouver la table des imports, ce qui veut dire que notre executable est vraisemblablement packé.<br>
Celui ci n'est rien d'autre que UPX, mais les signatures sembles avoir été supprimés à la main afin de nous empêcher d'utiliser la commande upx -d afin de le dépacker.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/hexedit.png "hexedit ReverseHub.exe")<br><br>
**Comment fonctionne un packer et plus particulièrement UPX ?**<br><br>
Les packers sont des utilitaires dont le travail consiste à compresser un programme executable et à le chiffrer afin d'en générer un nouveau. Ce nouvel executable contiendra en fait l'original comme de la donnée, ainsi qu'une routine d'unpacking qui sera appelée. Ils sont principalement utilisés dans les cas de protection logicielle ou de malwares afin d'en complexifier l'analyse.<br><br>
Lorsque l'on est face à un programme packé, le routine d'unpack effectue les actions suivantes :<br>
* Déchiffrer et décompresser l'executable original en mémoire<br>
* Résoudre la table des *imports* de l'executable original<br>
* Transferer l'execution du program vers le point d'entre original<br>
La table des imports correspond en fait sorte d'index qui va indiquer les DLL et les fonctions qui sont importés ainsi que leurs adresses.<br>

**Etudions donc le comportement d'unpack d'UPX :**<br><br>
Executable original, toutes les sections et les entêtes PE sont visibles et le point d'entré commence à l'original entry point <br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/upx1.png "upx1 ReverseHub.exe")<br><br>
Executable packé, la routine d'unpack est ajouté, et le point d'entré pointe maintenant sur la routine d'unpack<br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/upx2.png "upx2 ReverseHub.exe")<br><br>
Après le chargement en mémoire, la routine d'unpack déchiffre et décompresse le programme original<br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/upx3.png "upx3 ReverseHub.exe")<br><br>
Après l'unpack total, la table des imports est maintenant résolue, le point d'entrée pointe maintenant vers l'orginial entry point du program original.<br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/upx4.png "upx4 ReverseHub.exe")<br><br>
### Unpacking

Dans IDA, nous allons le faire rapidement en dynamique:

**Phase 1:**<br>
Breaker sur l'instruction de jmp du block rouge en bas du graph<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/1stunapckred.png "unpack1 ReverseHub.exe")<br><br>
**Phase 2:**<br>
Breaker sur la nouvelle instruction de jmp après le nouveau block apparu<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2ndunpack.png "unpack2 ReverseHub.exe")<br><br>
**Phase 3:**<br>
Aller jusqu'au bloc vert<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/3rdpack.png "unpack3 ReverseHub.exe")<br><br>
**Phase 4:**<br>
Breaker sur le call dans le block vert, juste après le push de \[esi\]<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/b3rd.png "unpack4 ReverseHub.exe")<br><br>
Ce call correspond en fait a l'entry point de l'executable original, nous allons donc dumper le disque afin de faire une analyse statique du reste du programme.<br>
Notre binaire commence à l'adresse **0x011F3710**, cette adresse est situé dans le segment 20. Nous allons donc dumper proprement ce segment à l'aide d'un script python IDA, mais il faudra au préalable calculer sa taille.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/segment.png "segment ReverseHub.exe")<br><br>
* Fin du segment : **0x1247000**<br>
* Début du segment : **0x11F1000**<br>
* Taille du segment : **0x56000**<br><br>
Voici à quoi ressemble notre script :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/reverhubunpack.png "pythonida ReverseHub.exe")<br><br>

### Analyse statique du binaire:
Une fois dumpé on met le dump dans IDA.<br>
Il va falloir retrouver l'adresse de notre fonction main avec ce calcul :<br>
* Début de fonction : **0x11F3710**<br>
* Début de segment : **0x11F1000**<br>
* Base adress du main : **0x2710**<br><br>

Notre fonction main correspond donc au **sub_2710**<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/sub2710_dump.png "sub_2710 ReverseHub.exe")<br><br>
Bref survol du main :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/main.png "ida ReverseHub.exe")<br><br>
On a :<br>
* Plusieurs appels de fonctions<br>
* Une comparaison qui peut nous faire jumper ou non plus bas dans le binaire<br>
* De multiples comparaison de var_2C avec des integers<br><br>

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/comparaison_var_2c.png "var_2C ReverseHub.exe")<br><br>

Les apppels de fonctions correspondent pour la plupart à des antidebugs et antivm et antisandbox, ou du trolling :<br>
* Changement de fond d'écran après avoir chargé une image depuis les ressources<br>
* Vérification du chargement de DBGHELP.DLL<br>
* Appel de IsDebuggerPresent<br>
* Comparaison avec VBOX, VMWARE et autres solutions de la clé de registre SystemBiosVersion<br>
* Vérification des informations des structures du TEB/PEB NTGlobalFlags<br>
* Vérification des informations des structures du TEB/PEB BeingDebugged<br>
* Comparaison avec GuestAdditions, Procmon, Wireshark et autres solutions des processus chargés en mémoire<br>
* Création d'un fichier troll avec de la base64 inutile<br>
* Vérification du mouvement de la souris<br><br>

Un système d'allocation mémoire, de déchiffrement de chaines de caractères via rot1 est également implémenté avant plusieurs actions et de se faire shredder.<br>

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/prog1.png "antistuff ReverseHub.exe")<br><br>

La variable var_2C servait en fait de compteur pour vérifier si l'on s'était fait detecter par les fonctions d'anti VM / DEBUG / SANDBOX, et elle était incrémentée de 1 juste avant d'arriver sur les comparaisons avec les integers.<br><br>

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/prog2.png "antistuff2 ReverseHub.exe")<br><br>

Le programme vérifier ensuite si argc était > à 1, si ce n'était pas le cas, il récupérait son chemin de lancement, et en fonction du compteur var_2C, il se relançait avec une option.<br><br>

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/prog3.png "antistuff3 ReverseHub.exe")<br><br>

Certaines de ces options étaient destructrices, le programme faisait un CALL $5, POP EBX afin de récupérer l'eip dans EBX, et il xorait EBX avec une valeur en dur avant de sauter dessus, evidemment l'adresse obtenue n'était pas valide.<br>
Pour les autres options, si l'on suit la logique de notre programme, **notre compteur si l'on est pas détecter doit valoir 1** pendant les comparaisons, le **bon argument est donc --3333**.

Si l'on regarde donc ce qu'il se passe avec les comparaisons d'arguments, c'est comme pour les comparaisons du compteur, une vérification se produit et une fonction est appelée que j'ai renommé "CreateCalcAndInject**Right|Wrong**Shellcode.<br>
En effet, le seul est unique bon paramètre étant --3333, les autres appels font une destructions de l'EIP, où injecte un shellcode ou une routine invalide dans calc.exe.

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/prog4.png "antistuff4 ReverseHub.exe")<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/prog5.png "antistuff5 ReverseHub.exe")<br><br>

### Analyse de l'injection

La bonne fonction d'injection était donc celle que j'ai renommée en "CreateCalcAndInjectRIGHTShellcode".<br>
Voici son graph :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2019-04-06-223859_151x786_scrot.png "inject1 ReverseHub.exe")<br><br>

Un calc.exe en 32bits est crée via CreateProcessA<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2019-04-06-223919_522x738_scrot.png "inject2 ReverseHub.exe")<br><br>

Le programme va ensuite retrouver son PID après un parcours de la structure des processus en mémoire<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2019-04-06-223952_336x517_scrot.png "inject2 ReverseHub.exe")<br><br>


Un appel à OpenProcess est effectué afin d'obtenir un handle sur le processus calc.exe précèdemment lancé, ainsi qu'une allocation dans le processus distant calc.exe. Une suite d'opcode et de data va être déplacé à différentes adresses.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2019-04-06-224043_410x511_scrot.png "inject2 ReverseHub.exe")<br><br>


3 appels à WriteProcessMemory vont être effectués pour écrire dans la mémoire du processus distant calc.exe, la data écrite est la suivante dans le cas de --3333 :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2019-04-06-224207_300x364_scrot.png "inject2 ReverseHub.exe")<br><br>

```
\x76\x60\x74\x7a\x48\x79\x03\x5b\x7d\x6c\x77\x03\x76\x4e\xe8
\x5B\x31\xC0\xB0\x33\x31\xC9\x31\xD2\x31\xFF\x31\xF6\xB9\x0E
\x31\x44\x13\xED\x42\xE2\xF9
```

Et un appel à CreateRemoteThread va être effectué à partir du 0xe8<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images/2019-04-06-224523_330x582_scrot.png "injectthread ReverseHub.exe")<br><br>


### Analyse du shellcode 

La data injectée était la suivante dans le cas du --3333:<br>

```
seg029:0120235C db  76h ; V
seg028:0120235D db  60h ; \`
seg028:0120235E db  74h ; t
seg028:0120235F db  7Ah ; z
seg028:01202360 db  48h ; H
seg028:01202361 db  79h ; y
seg028:01202362 db    3
seg028:01202363 db  5Bh ; \[
seg028:01202364 db  7Dh ; }
seg028:01202365 db  6Ch ; l
seg028:01202366 db  77h ; w
seg028:01202367 db    3
seg028:01202368 db  76h ; v
seg028:01202369 db  4Eh ; N
... suite du shellcode ...
```

Le Shellcode en inline assembly serait le suivant :<br>
	
```assembly
__asm
	{
		; "data encrypted : \x76\x60\x74\x7a\x48\x79\x03\x5b\x7d\x6c\x77\x03\x76\x4e"
		CALL $+5  ; <= start of injected thread
		POP EBX
		XOR EAX, EAX
		MOV AL, 0x33
		XOR ECX, ECX
		XOR EDX, EDX
		XOR EDI, EDI
		XOR ESI, ESI
		MOV ECX, 14
		L1:
			xor [EBX-15+EDX], EAX
			inc EDX
			loop L1
	}
```

Ce shellcode permet en fait de déchiffrer la donner au dessus via un xor d'une clé de 0x33 !<br>
Réimplémentation de l'algorithme en python :<br>

```python
encrypted_flag = [0x76, 0x60, 0x74, 0x7a, 0x48, 0x79, 0x03, 0x5b, 0x7d, 0x6c, 0x77, 0x03, 0x76, 0x4e]
flag = ''.join([chr(byte ^ 0x33) for byte in encrypted_flag])
print(flag)
```

python shellcode_decrypt_flag.py<br>
> ESGI{J0hN_D0E}

La véritable identité de Duke-083 était donc J0hN_D0E... et aussi le flag validant les 500 points était donc :<br>

ESGI{J0hN_D0E}<br>
