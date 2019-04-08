# SecurityDay2019

## Informations :<br><br>
**Challenge** : BadPunk - 1 0ld Spirit<br>
**Description** : M0the3r> Duke aurait survécu…. Mais qu’en reste t il ? J’ai retrouvé ici un programme qui comporte son empreinte… donc généré par son IA. C’est la seule piste que l’on a pour l’instant. Fait gaffe, il semble malveillant. Il semble effectuer des échanges louches sur le réseau, vous devriez regarder par là... /!\ N'EXECUTEZ SURTOUT PAS LE PROGRAMME EN DEHORS D'UNE MACHINE VIRTUELLE /! Mot de passe de l'archive: very_infected<br>
**Points** : 200<br>
**Solves** : 4<br>
**Contributeur** : Maxou56800<br>

## Solutions :<br><br>

### Premiers pas :
On obtient un executable windows de type PE32:<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/file_badpunk.png "file BadPunk.exe")<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/badpunk_ico.png "fileico BadPunk.exe")<br><br>

Lorsqu'on le charge dans IDA, on obtient ce graph ci pour le main:<br><br>

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/graphmain.png "graphmain BadPunk.exe")<br><br>

Si on regarde quelques API utilisées dans le main on a:<br>
* GetTempPathA (Recupère le chemin du dossier pour les fichiers temporaires)<br>
* LoadLibraryW et GetProcAddress (Pour la résolution d'imports)<br>
* GetDesktopWindow (Récupère un handle vers la fenêtre du bureau)<br>
* CreateFileW (Creation ou Acces à un fichier)<br>
* WinHttpSendRequest (Envoie de requête réseau)<br><br>

Et des fonctions d'anti debug:<br>
* CheckRemoteDebuggerPresent<br>
* GetSystemTime<br>
* GetTickCount<br>
* IsDebuggerPresent<br>

On remarque également dans le dernier block du WinMain une string "success" et une phrase concernant un "TODO pour le developpeur" ainsi qu'un hash:<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/tododev.png "tododev BadPunk.exe")<br><br>

Mais également d'autre hashs dans les strings, des informations de requête réseau, et un petit SeShutdownPrivilege (privileges windows pour faire des actions concernant le shutdown ou le reboot de la machine):<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/stringsmd5.png "str BadPunk.exe")<br><br>

Et aussi des strings en .rkr, qui font penser au rot13 de .exe :<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/stringsrot13.png "str13 BadPunk.exe")<br><br>

On va donc les déchiffrer et commenter les strings avec un script IDAPython:<br>
```python
import idautils 
import idaapi
import codecs

def decrypt_and_comment(string, ea):
    decrypted = codecs.encode(string, 'rot_13')
    set_cmt(ea, decrypted, 0)
    return decrypted
    
def get_string(ea):
    out = ""
    while True:
        if Byte(ea) != 0:
            out += chr(Byte(ea))
            ea += 1
        else:
            ea += 1
            break
    return out, ea
    
def parse_all_rkr_data(ea):
    r13strs = []
    while True:
        r13str, ea = get_string(ea)
        if r13str != "%08x%08x%08x%08x":
            if r13str != '':
                r13strs.append({"string":r13str, "ea":ea})
        else:
            break
    return r13strs

for elt in parse_all_rkr_data(0x0041E264):
    print(decrypt_and_comment(elt['string'], elt['ea']))
```

Output :<br>
```
wireshark.exe
procmon.exe  
ollydbg.exe
idag.exe
ImmunityDebugger.exe
idaq.exe
idaq64.exe
idaw.exe
idaw64.exe
windbg.exe
lordpe.exe
x32dbg.exe
x64dbg.exe
tshark.exe
ida.exe
```
Ces strings seront surement utilisées pour de l'anti debug !<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/ida_cmt.png "strcmt BadPunk.exe")<br><br>

### Analyse Statique

Les premières fonctions du malwares consistent à inverser et à rot13 certains chemins de DLL Windows, et celle d'après d'en importer sous forme de listes chainées leurs fonctions.<br><br>

![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/resolve_dll_and_import.png "imp BadPunk.exe")<br><br>

S'en suivra ensuite une fonction que j'appelle screenshot_desktop_anti_debug_ntthread, elle servira à faire un screenshot et à utiliser un antidebug.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/callscreen.png "screen BadPunk.exe")<br><br>

Un appel à GetTempPathA sera effectué afin de récupéré le dossier temporaire de l'utilisateur courant:<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/incallscreen.png "screen BadPunk.exe")<br><br>

Pour l'anti débug, il se situe dans le blocs en bleu. Precedemment le malware cherche l'adresse de NtSetInformationThread puis l'appel avec l'option "ThreadHideFromDebugger" qui permet dans le cas ou l'on debug le malware, de masquer le mainthread (récupéré par GetCurrentThread) auprès du debugger.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/antidebugthread.png "screen BadPunk.exe")<br><br>

La suite va concaténer le dossier AppData\\Local\\Temp de l'utilisateur avec "s", et y écrire le screenshot dans le fichier 's' via cette fonction : WriteScreenShotAppDataFileS_AntiDebugRTDSC_INTO_WriteMBR_REBOOT<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/main_write_screenshot.png "screen BadPunk.exe")<br><br>

Ici un appel à CreateFile pour crée le fichier "s".<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/creatfiles.png "screen BadPunk.exe")<br><br>

Deux variables sont initialisées, elles serviront à stocker le résultat des instructions RTDSC (ReaD TimeStamp Counter). Elle retourne dans le couple de registre EDX:EAX le nombre de ticks écoulés depuis la dernière mise à zéro du processeur.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/rtdsc_1.png "screen BadPunk.exe")<br><br>

Après avoir écrit dans le fichier "s", le malware vérifie le temps écoulé entre les deux appels à RTDSC via une soustration, si la différence est supérieure à 15000 ticks, le malware appelle deux fonctions, WriteMbr et Reboot !<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/writefile_andrtdsc.png "screen BadPunk.exe")<br><br>

Regardons d'un peu plus près le write MBR:<br><br>
Cette fonction va s'occuper de faire un CreateFile sur \\.\PhysicalDrive0 (correspond au MBR), et d'écraser son contenu avec un WriteFile.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/mbr1.png "screen BadPunk.exe")<br><br>
...<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/mbr2.png "screen BadPunk.exe")<br><br>
Et pour le reboot :<br><br>
Ici, le malware appelle OpenProcessToken, vérifie qu'il à les droit SeShutdownPrivileges, et si c'est le cas, redémarre la machine.
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/reboot.png "screen BadPunk.exe")<br><br>
Et voici à quoi ressemble la machine après que le MBR soit écrasé et que la machine reboot, une jolie animation !<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/reboot2.png "screen BadPunk.exe")<br><br>

Après avoir passé ces étapes, le malware crée un deuxième fichier dans le répertoire temporaire sous le nom de "ss", et appelle la fonction que j'ai renommée en Write_SS_File_Xor42_Of_S_File_And_Being_Debugged_WriteMBR_INTO_REBOOT. Cette fonction s'occupe principalement de lire notre premier fichier "s" écrit correspondant au screenshot de la machine au format image BMP, de le xorer avec la clé 0x42 et de l'écrire dans le fichier "ss"<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/ssfile_wrap.png "screen BadPunk.exe")<br><br>

Un anti debug est encore présent, il s'agit du champ BeingDebugged dans la structure du PEB (process environnement block). Si on est detecté, le malware écrase le MBR et Reboot la machine.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/peb_dbg.png "screen BadPunk.exe")<br><br>

Voici la boucle de chiffrement du fichier BMP et s'en suis l'écriture dans le fichier "ss".<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/xor42.png "screen BadPunk.exe")<br><br>

Ensuite, une string va etre inversée et rot 13, il s'agit du domaine .ctf.hacklab-esgi.org. Cette chaine va être concaténé avec b4dpunk42 pour former au final b4dpunk42.ctf.hacklab-esgi.org<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/rot_domain.png "screen BadPunk.exe")<br><br>

Une fois tout ça passé, l'appel d'une fonction importante sera "FirstNetworkCall", elle prend en paramètre (null, le chemin du fichier ss, null, et le nom de domaine).<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/firstnetcall.png "screen BadPunk.exe")<br><br>

Un nouvel appel à create file sur le fichier "ss" va etre effectué afin de récupérer un handle valide sur le fichier, un appel à GetFileSize afin de récupérer sa taille, puis l'appel classique des API réseaux de winhttp. Un user-agent spécifique est utilisé "BadPunk".<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/1net_open_readf.png "screen BadPunk.exe")<br><br>
Nous allons ensuite nous connecter au domaine.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/1stconnect.png "screen BadPunk.exe")<br><br>
Une requête va être préparée pour aller envoyer en méthode POST sur la page getCnCSeed.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/1stopenreq.png "screen BadPunk.exe")<br><br>
Le fichier BMP xoré va ensuite être lu<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/1stnetreadfile.png "screen BadPunk.exe")<br><br>
Après l'ajout de quelques headers, la requête POST avec le fichier va être envoyée.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/1stsendreq.png "screen BadPunk.exe")<br><br>
Pour la réponse, il suffit de passer le WinHttpReadData<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/1streceiverespreadata.png "screen BadPunk.exe")<br><br>
Et nous recevrons le flag, précédé d'un "token" !<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/flag1.png "screen BadPunk.exe")<br><br>

Un autre moyen de résoudre le challenge, et ... de bourrer l'espace disque du serveur aurait été le suivant:
Prendre une image au format bmp (image de l'image)
Faire un script qui xor l'image python script ici
Xorer l'image 
xxd image sortie
Lancer un curl avec le bon user agent et les bons params !
(image retour)
Puis, on aurait pu while true...
! (script xor42 un bmp, et send via curl et user agent !)(image aussi)
// TODO !

## Informations :<br><br>

**Challenge** : BadPunk - 2 N0 Recall<br>
**Description** : M0th3r > Bad punk ? Incoryable. Même effacé dans les abysses, Duke-083 continu de se prendre pour un pirate cybernétique. Il semblait en effet, doté d’une certaine émotion… que reste-il de lui ? Il avait l’air de nous demander un service… Continue ta recherche, il semblerait qu'il y ai quelque chose qui se prépare... /!\ N'EXECUTEZ SURTOUT PAS LE PROGRAMME EN DEHORS D'UNE MACHINE VIRTUELLE /! Mot de passe de l'archive: very_infected<br>
**Points** : 550<br>
**Solves** : 0<br>
**Contributeur** : Maxou56800<br>

## Solutions :<br><br>
    
Etant la suite du BadPunk 1, il suffit de suivre le flow d'éxecution, nous avons déjà contacté un nom de domaine en envoyant une image bmp xoré et en utilisant un user-agent spécifique "BadPunk". Nous avons un flag, et une sorte de token juste avant le flag. Le malware va récupérer le token et le déplacer en mémoire. Par la suite, il sera rot13 et inversé pour donner "imsBs1Rs2jNk".<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/gettoken.png "screen BadPunk.exe")<br><br>
Et supprimer le fichier xoré "ss" via DeleteFileW<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/deletess.png "screen BadPunk.exe")<br><br>

De nouveaux anti-debugs vont essayer de nous barrer la route, une fonction permettant de parcourir les processus en mémoire, et une fonction vérifiant si un debugger est attaché. Encore une fois, si nous nous faisons détecter, le MBR se fait écraser et la machine reboot<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/crawlprocwrp_checkremote.png "screen BadPunk.exe")<br><br>

Les process seront crawlés par Process32Next, et un appel à decrypt_all_rkr_process_to_find_comp qui s'occupera de déchiffrer les strings finissant par .rkr (les .exe rot13 du début) et de comparer avec le processus actuellement crawlé.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/crawlproc.png "screen BadPunk.exe")<br><br>


Une fois ces épreuves passées, nous arrivons sur un GetSystemTime, le malware va récupérer l'heure et la minute du système, en générer un hash, et le concatener avec le token précedemment obtenu ainsi que le nom de domaine afin d'obtenir quelquechose sous la forme : \<token\>\<hash_du_temps_systeme\>\<.ctf.hacklab-esgi.org\><br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/before_2nd_gen_time.png "screen BadPunk.exe")<br><br>

Ceci ressemble fortement à un algorithme de DGA (Domain Generation Algorithm) ! Un DGA est un algorithme permettant de générer un large panel de nom de domaines, dont seulement un, ou quelques un seront valide et serviront de C&C contactable pour le malware. Le but du DGA est donc de produire beaucoup d'appels réseaux vers des noms de domaines invalides pour masquer celui ou ceux qui seront valides et de brouiller les pistes pour l'analyste.<br><br>

Nous allons maintenant passer dans la fonction AntiDebugFindWindow_SecondNetworkCall<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/recall2nd.png "screen BadPunk.exe")<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/wrpcall2ndnet.png "screen BadPunk.exe")<br><br>

Ici, on remarque qu'en fait le malware va faire une requête GET sur le nom de domaine généré au préalable par le DGA.<br>
Puis le malware boucle si il n'a pas reçu de réponse du C&C, et recommence.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/sleep_repeat2ndnet.png "screen BadPunk.exe")<br><br>

Si par contre on reçoit de la donnée, le malware vérifie encore une fois si un débugger est attaché, puis si c'est le cas, écrase le MBR et reboot la machine. Sinon, une pop up apparait avec le message : "Success, TODO for the developper..."<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/endisdbgpresnt.png "screen BadPunk.exe")<br><br>

Pour résoudre ce challenge, il va donc falloir générer les noms de domaines possibles.
Nous allons devoir regarder plus en détail la fonction de hashage. On peut remarquer certaines constantes, et on sait que c'est très important pour identifier les algorithmes cryptographiques.<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/murmur3_0.png "screen BadPunk.exe")<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/murmur3_1.png "screen BadPunk.exe")<br><br>
On va donc google les constantes et tomber sur du "murmurhash3"<br><br>
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/murmur3_2.png "screen BadPunk.exe")<br><br>
Je vais m'appuyer sur ce github https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp, et sur la fonction MurmurHash3_x64_128 étant sur une machine x64. Je vais faire un code en C, appelant cette fonction avec les mêmes paramètres et retour que la fonction du malware:<br>
* Entrée : <chaine heure format %d%d (heure_minutes)>, taille de la chaine, seed (42), tableau de hash\[4\];
* Sortie : <%d%d> de hash\[1\] et hash\[3\]

```c
#include "pch.h"
#include <iostream>

#if defined(_MSC_VER)

#define FORCE_INLINE	__forceinline

#include <stdlib.h>

#define ROTL32(x,y)	_rotl(x,y)
#define ROTL64(x,y)	_rotl64(x,y)

#define BIG_CONSTANT(x) (x)

#else	// defined(_MSC_VER)

#define	FORCE_INLINE inline __attribute__((always_inline))

inline uint32_t rotl32(uint32_t x, int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

inline uint64_t rotl64(uint64_t x, int8_t r)
{
	return (x << r) | (x >> (64 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)
#define ROTL64(x,y)	rotl64(x,y)

#define BIG_CONSTANT(x) (x##LLU)

#endif // !defined(_MSC_VER)

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

FORCE_INLINE uint32_t getblock32(const uint32_t * p, int i)
{
	return p[i];
}

FORCE_INLINE uint64_t getblock64(const uint64_t * p, int i)
{
	return p[i];
}

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche

FORCE_INLINE uint32_t fmix32(uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

//----------

FORCE_INLINE uint64_t fmix64(uint64_t k)
{
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xff51afd7ed558ccd);
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
	k ^= k >> 33;

	return k;
}

void MurmurHash3_x64_128(const void * key, const int len,
	const uint32_t seed, void * out)
{
	const uint8_t * data = (const uint8_t*)key;
	const int nblocks = len / 16;

	uint64_t h1 = seed;
	uint64_t h2 = seed;

	const uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	const uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	//----------
	// body

	const uint64_t * blocks = (const uint64_t *)(data);

	for (int i = 0; i < nblocks; i++)
	{
		uint64_t k1 = getblock64(blocks, i * 2 + 0);
		uint64_t k2 = getblock64(blocks, i * 2 + 1);

		k1 *= c1; k1 = ROTL64(k1, 31); k1 *= c2; h1 ^= k1;

		h1 = ROTL64(h1, 27); h1 += h2; h1 = h1 * 5 + 0x52dce729;

		k2 *= c2; k2 = ROTL64(k2, 33); k2 *= c1; h2 ^= k2;

		h2 = ROTL64(h2, 31); h2 += h1; h2 = h2 * 5 + 0x38495ab5;
	}

	//----------
	// tail

	const uint8_t * tail = (const uint8_t*)(data + nblocks * 16);

	uint64_t k1 = 0;
	uint64_t k2 = 0;

	switch (len & 15)
	{
	case 15: k2 ^= ((uint64_t)tail[14]) << 48;
	case 14: k2 ^= ((uint64_t)tail[13]) << 40;
	case 13: k2 ^= ((uint64_t)tail[12]) << 32;
	case 12: k2 ^= ((uint64_t)tail[11]) << 24;
	case 11: k2 ^= ((uint64_t)tail[10]) << 16;
	case 10: k2 ^= ((uint64_t)tail[9]) << 8;
	case  9: k2 ^= ((uint64_t)tail[8]) << 0;
		k2 *= c2; k2 = ROTL64(k2, 33); k2 *= c1; h2 ^= k2;

	case  8: k1 ^= ((uint64_t)tail[7]) << 56;
	case  7: k1 ^= ((uint64_t)tail[6]) << 48;
	case  6: k1 ^= ((uint64_t)tail[5]) << 40;
	case  5: k1 ^= ((uint64_t)tail[4]) << 32;
	case  4: k1 ^= ((uint64_t)tail[3]) << 24;
	case  3: k1 ^= ((uint64_t)tail[2]) << 16;
	case  2: k1 ^= ((uint64_t)tail[1]) << 8;
	case  1: k1 ^= ((uint64_t)tail[0]) << 0;
		k1 *= c1; k1 = ROTL64(k1, 31); k1 *= c2; h1 ^= k1;
	};

	//----------
	// finalization

	h1 ^= len; h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = fmix64(h1);
	h2 = fmix64(h2);

	h1 += h2;
	h2 += h1;

	((uint64_t*)out)[0] = h1;
	((uint64_t*)out)[1] = h2;
}

#include <inttypes.h>
#include <string.h>

int main()
{
	char currentTime[10] = { '\0' };
	const uint32_t seed = 42;
	uint32_t hash[4];
	for (int i = 0; i < 9999; i++) {
		memset(currentTime, '\0', sizeof(currentTime));
		sprintf_s(currentTime, "%d", i);
		MurmurHash3_x64_128(currentTime, strlen(currentTime), seed, hash);
		printf("date : %d | hash : %08x%08x\n", i, hash[1], hash[3]);
	}
}
```

Je lance maintenant le script et obtient toutes les sorties possibles. Il ne reste plus qu'a faire un script python qui génère le domaine et le requête en GET pour voir si on récupère un code 200.

Je vais découper le fichier avant cela :
```bash
awk '{print $7}' generated_dga.txt > hash_mmh3.txt
```

```python
import requests
import time


with open("hash_mmh3.txt", "r") as f:
    mmh3s = f.readlines()

token = "imsBs1Rs2jNk"
esgi = ".ctf.hacklab-esgi.org"

headers = {"User-Agent":"BadPunk"}

for mmh3 in mmh3s:
    domain = "https://{}{}{}/imsBs1Rs2jNk".format(token, mmh3.replace('\n',''), esgi)
    try:
        r = requests.get(domain, headers=headers, verify=False, timeout=2)
        if r.status_code == 200:
            print("Valid domain {} returned data {}".format(domain, r.text))
            break
    except:
        pass
```

Il s'avère que le domaine himsBs1Rs2jNkdf2f17018871f197.ctf.hacklab-esgi.org match, et il était généré avec le nombre 1337. La bonne heure du système était donc 13h37 !<br><br>

On obtient le flag via le script python !
Ici un petit curl solvant le challenge :
```bash
curl -A "BadPunk" -X GET "https://imsbs1rs2jnkdf2f17018871f197.ctf.hacklab-esgi.org/imsBs1Rs2jNk" -k
```
You got it: ESGI{I_m-No_0ne_PLZ_k1LL-ME}

Si on fait via IDA en modifiant l'heure du système, le flag apparait via le WinHttpReadData
![alt text](https://github.com/Lexsek/CTFSecurityDay2019/blob/master/images_badpunk/flag2.png  "screen BadPunk.exe")<br><br>
