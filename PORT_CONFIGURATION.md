# 🔧 Configuration du Port de Seeding

## ⚠️ Problème Courant: Port Non Accessible

Si tu vois beaucoup de trafic entrant dans `tcpdump` mais que ton **ratio ne monte pas**, c'est probablement parce que **ton port n'est pas accessible**.

### Symptômes

Dans `tcpdump`, tu verras:
```
IP xxx.xxx.xxx.xxx > ton-serveur.filenet-powsrm: Flags [S] ← Connexion entrante
IP ton-serveur > xxx.xxx.xxx.xxx: Flags [R] ← REJETÉ !
```

Le flag `[R]` (RST - Reset) signifie que **aucune application n'écoute** sur ce port.

## 🔍 Diagnostic

### 1. Vérifier quel port écoute TorrentUI

```bash
# Voir les logs au démarrage
podman logs torrentui | grep "listening on port"
```

Tu devrais voir:
```
Torrent client listening on port 42069 for incoming connections
```

### 2. Vérifier que le port est ouvert

```bash
# Vérifier que l'application écoute
ss -tlnp | grep :42069

# Vérifier le firewall
sudo firewall-cmd --list-ports
```

### 3. Tester depuis l'extérieur

```bash
# Depuis un autre serveur
telnet ton-serveur.com 42069
```

## 🧪 Comment Tester le Port BitTorrent

### ⚠️ ATTENTION: curl Ne Fonctionne PAS !

Si tu essaies:
```bash
curl ton-serveur:42069
# Résultat: Connection reset by peer
```

**C'est NORMAL ! Ça ne veut PAS dire que le port est fermé !**

Le serveur BitTorrent **rejette** la requête HTTP de curl parce que:
- BitTorrent utilise un **protocole binaire** spécifique
- curl envoie du **HTTP** (`GET / HTTP/1.1`)
- Le serveur voit que ce n'est pas un handshake BitTorrent valide
- Il ferme la connexion immédiatement (RST)

**Si tu vois "Connected" avant le "reset", ton port EST OUVERT ! ✅**

### ✅ Tests Corrects

#### Méthode 1: Script Python (recommandé)

```bash
# Télécharger le script de test
wget https://raw.githubusercontent.com/fjcloud/torrentui/main/test-bt-handshake.py

# Tester ton port
python3 test-bt-handshake.py ton-serveur.com 42069
```

Le script envoie un vrai handshake BitTorrent et vérifie la réponse.

#### Méthode 2: Vérifier la Connexion TCP Basique

```bash
# Test avec timeout (si ça se connecte = port ouvert)
timeout 3 bash -c "cat < /dev/null > /dev/tcp/ton-serveur.com/42069"
echo $?  # 0 = succès, port ouvert !
```

#### Méthode 3: Utiliser netcat

```bash
# Envoyer des données et voir si ça se connecte
echo "test" | nc -w 1 ton-serveur.com 42069
# Si ça se connecte (même sans réponse) = port ouvert !
```

#### Méthode 4: Vérifier avec tcpdump

```bash
# Sur le serveur
sudo tcpdump -i any port 42069 -n

# Depuis l'extérieur, faire un simple telnet
telnet ton-serveur.com 42069
```

Si tu vois dans tcpdump:
```
IP peer > serveur:42069: Flags [S]    ← SYN (demande connexion)
IP serveur:42069 > peer: Flags [S.]   ← SYN-ACK (accepté ✅)
IP peer > serveur:42069: Flags [.]    ← ACK (connexion établie ✅)
```

**Ton port est OUVERT et ACCESSIBLE ! ✅**

Si tu vois:
```
IP peer > serveur:42069: Flags [S]    ← SYN
(pas de réponse ou timeout)           ← Port fermé/filtré ❌
```

**Ton port est FERMÉ ou FIREWALL bloque. ❌**

### 🎯 Test Ultime: Ajouter un Vrai Torrent

La meilleure façon de tester:

1. Ajouter un torrent **populaire** (beaucoup de peers/seeders)
2. Attendre qu'il soit complet (100%)
3. Activer le seeding
4. Attendre **5-10 minutes** (le tracker doit réannoncer)
5. Vérifier les logs:

```bash
podman logs torrentui | grep "Upload Stats"
```

Tu devrais voir:
```
📤 Upload Stats [nom-torrent]: 1234567 bytes uploaded, 8 active conns, 25 peers total
```

Si `active conns > 0` → **Ton port fonctionne ! 🎉**

Si `active conns = 0` après 10 minutes → Problème de port/firewall

## ✅ Configuration Correcte

### Docker/Podman

```bash
podman run -d \
  --name torrentui \
  -p 8080:8080 \
  -p 42069:42069 \    # ← PORT DE SEEDING !
  -e TORRENT_LISTEN_PORT=42069 \
  -e PUBLIC_IP=ton.ip.public.ici \
  -v ./downloads:/app/downloads \
  -v ./data:/app/data \
  quay.io/torrentui:latest
```

**IMPORTANT:** Les 2 doivent correspondre:
- `-p 42069:42069` (mapping du port)
- `-e TORRENT_LISTEN_PORT=42069` (config du client)

### Firewall

```bash
# Firewalld (Fedora/RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=42069/tcp
sudo firewall-cmd --reload

# UFW (Ubuntu/Debian)
sudo ufw allow 42069/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 42069 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

### Routeur/Box

Si tu es derrière un routeur, tu dois configurer le **Port Forwarding**:
- Port externe: `42069`
- Port interne: `42069`
- Protocole: `TCP`
- IP de destination: IP de ton serveur

## 📊 Vérifier que ça Fonctionne

### Dans les logs

Tu devrais voir:
```
📤 Upload Stats [nom-du-torrent]: 1234567 bytes uploaded, 5 active conns, 12 peers total
```

Si tu vois toujours `0 active conns`, c'est que le port n'est **toujours pas accessible**.

### Dans l'UI

- La **vitesse d'upload** doit être > 0 B/s quand tu seeds
- Le **total uploadé** doit augmenter
- Le **ratio** doit monter

### Avec tcpdump

```bash
sudo tcpdump -i any port 42069 -n
```

Tu devrais voir des échanges **bidirectionnels**:
```
IP peer > ton-serveur:42069: Flags [S] ← Connexion entrante
IP ton-serveur:42069 > peer: Flags [S.] ← ACCEPTÉE !
IP peer > ton-serveur:42069: Flags [.] ← Connexion établie
IP ton-serveur:42069 > peer: Flags [P.] ← Données envoyées !
```

## 🎯 Ports Recommandés

- **42069** (BitTorrent standard alternatif)
- **51413** (BitTorrent standard)
- **6881-6889** (Range BitTorrent classique)

**Évite:**
- Ports < 1024 (nécessitent root)
- Port 6969 (souvent bloqué)
- Ports bien connus (80, 443, 22, etc.)

## 🔐 IP Publique

Pour maximiser le seeding, configure ton IP publique:

```bash
# Trouver ton IP publique
curl ifconfig.me

# Configurer TorrentUI
-e PUBLIC_IP=xx.xx.xx.xx
```

Sans ça, les trackers peuvent avoir du mal à annoncer ta vraie adresse aux peers.

## 📝 Exemple Complet

```bash
# 1. Trouver ton IP publique
MY_PUBLIC_IP=$(curl -s ifconfig.me)

# 2. Créer les volumes
mkdir -p ~/torrentui/{downloads,data}

# 3. Lancer le container
podman run -d \
  --name torrentui \
  -p 8080:8080 \
  -p 42069:42069 \
  -e TORRENT_LISTEN_PORT=42069 \
  -e PUBLIC_IP=$MY_PUBLIC_IP \
  -e TORRENTUI_USERNAME=admin \
  -e TORRENTUI_PASSWORD=ton-password-ici \
  -v ~/torrentui/downloads:/app/downloads \
  -v ~/torrentui/data:/app/data \
  quay.io/torrentui:latest

# 4. Ouvrir le firewall
sudo firewall-cmd --permanent --add-port=42069/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# 5. Vérifier
podman logs torrentui | grep "listening on port"
ss -tlnp | grep :42069
```

## 🐛 Troubleshooting

### Port déjà utilisé

```bash
# Voir qui utilise le port
sudo lsof -i :42069
sudo ss -tlnp | grep :42069

# Choisir un autre port
-e TORRENT_LISTEN_PORT=51413
-p 51413:51413
```

### SELinux (RHEL/Fedora/CentOS)

```bash
# Autoriser le port
sudo semanage port -a -t container_port_t -p tcp 42069

# Ou désactiver SELinux (non recommandé en prod)
sudo setenforce 0
```

### Pas de connexions entrantes

1. Vérifie que le port est bien mappé (`-p 42069:42069`)
2. Vérifie le firewall (local + cloud provider)
3. Vérifie le routeur/box (port forwarding)
4. Vérifie l'IP publique configurée
5. Attends 5-10 minutes (les trackers ne réannoncent pas immédiatement)

## 📚 Ressources

- [BitTorrent Protocol Specification](http://www.bittorrent.org/beps/bep_0003.html)
- [Port Forwarding Guide](https://portforward.com/)
- [Test Your Port](https://www.yougetsignal.com/tools/open-ports/)
