# Clients desktop Cyclar

Cette première verticale fonctionnelle fournit deux exécutables Rust qui partagent le même moteur :

- `cyclar-host` reçoit uniquement des sessions ;
- `cyclar-desktop` reçoit des sessions et permet `connect <ID>` vers un autre hôte.

Le backend qualifié dans ce dépôt est **Linux avec une session X11 accessible**, un visuel TrueColor 24 bits et, pour le contrôle distant, l’extension XTEST. L’hôte capture le bureau existant, compresse les images en JPEG et les affiche dans une fenêtre X11 du contrôleur. Les mouvements, clics et codes physiques de touches X11 sont relayés seulement si le grant du serveur autorise `input` et si l’hôte n’a pas choisi `--view-only`. Un seul contrôleur à la fois reçoit la capacité d’entrée ; les autres restent en lecture seule. Les touches pressées sont relâchées à la fermeture. Le mappage des touches entre dispositions ou OS différents reste non qualifié.

```sh
cargo run -p cyclar-server -- init --data-dir ./data --admin-user admin
cargo run -p cyclar-server -- serve --data-dir ./data --listen 127.0.0.1:8080 --insecure-cookies
cargo run -p cyclar-desktop --bin cyclar-host -- --server http://127.0.0.1:8080 --listen 127.0.0.1:7420 --state ./data/host.json
cargo run -p cyclar-desktop --bin cyclar-desktop -- --server http://127.0.0.1:8080 --listen 127.0.0.1:7421 --state ./data/controller.json
```

Cet exemple exécute les trois processus sur le même poste. Pour deux machines, donnez à chacun des clients la **même URL HTTPS du serveur central** et annoncez par `--advertise` l’adresse IP et le port TCP réellement joignables du poste hôte. Le client demande le secret à l’invite sans l’inclure dans les arguments de processus. L’identité et le jeton de machine sont conservés dans `~/.local/state/cyclar/host.json` avec permissions 0600 sur Unix ; sauvegardez ce fichier si vous souhaitez garder le même ID. Le secret temporaire n’est écrit que sur le terminal local `/dev/tty`, jamais sur la sortie de service collectable en journaux ; la commande `secret` le réaffiche au besoin. `quit` arrête localement l’hôte et les sessions.

Sur un poste sans port entrant, démarrez l’hôte avec `--relay-only` et une URL centrale HTTPS : son listener TCP est limité à `127.0.0.1` pour le pont interne, et le heartbeat ne publie aucune adresse directe. Le contrôleur tente le TCP direct lorsqu’une adresse est publiée ; en son absence ou sur échec il rejoint `wss://<central>/api/v1/relay/...`. Les deux rôles s’authentifient auprès du relais avec un jeton en en-tête et un défi signé Ed25519 ; le relais transmet seulement des octets Noise opaques. Les messages WSS sont bornés à 64 KiB et pompés par tranches de 16 KiB avec pression de retour.

Les commandes locales `rotate`, `set-password` et `clear-password` régénèrent le secret temporaire ou définissent/suppriment le mot de passe permanent sur le serveur. La saisie du mot de passe permanent est masquée et confirmée deux fois ; le client annonce la réussite uniquement après la réponse du serveur. Après rotation, le nouveau secret temporaire est enregistré dans le fichier d’identité protégé puis affiché sur `/dev/tty`. Aucune rotation n’est tentée sans terminal local pour consulter le nouveau secret.

Pour envoyer un fichier, démarrez l’hôte avec `--allow-files` (désactivé par défaut), puis utilisez `send <ID> <chemin du fichier>` dans `cyclar-desktop` ou `--connect <ID> --send-file <chemin>`. Cela transmet uniquement le nom, la taille et un ID de transfert. Sur le poste hôte, `files` liste les offres ; `approve <ID transfert> <dossier existant>` choisit explicitement la destination. Le contrôleur ouvre et lit le fichier seulement après cette demande. Les blocs de 16 KiB circulent dans Noise avec vérification BLAKE3 par bloc et du fichier complet ; le résultat n’écrase jamais un fichier déjà présent. Le fichier temporaire et sa preuve de reprise restent disponibles jusqu’à une heure pendant que **les deux applications restent ouvertes** : relancer `send` avec le même chemin depuis le même processus réutilise l’ID après reconnexion. Un redémarrage d’application perd cette reprise en mémoire.

La connexion à un serveur non local exige HTTPS. L’hôte vérifie le grant signé par sa propre autorité, l’identité du contrôleur et la possession de sa clé Ed25519. Le contrôleur vérifie la clé de l’hôte fournie par le serveur. Le flux direct utilise `Noise_NN_25519_ChaChaPoly_SHA256` via `snow`, avec le grant comme prologue et les deux messages de handshake liés aux clés Ed25519 des participants. Les images volumineuses sont découpées en blocs chiffrés et réassemblées avec une taille maximale. Les grants rejoués sont refusés et les sessions expirent sans renouvellement valide. L’hôte interroge le central pour appliquer les révocations aux sessions actives.

Noise est un protocole éprouvé ; la liaison applicative entre son handshake, le grant, les identités Ed25519 et les décisions d’autorisation reste propre à Cyclar et doit recevoir une revue de sécurité avant une distribution de production.

**Limites explicites :** ces clients n’implémentent pas encore la traversée NAT UDP/ICE, la migration transparente entre chemin direct et relais pendant une session, les proxys HTTP explicites/CONNECT, l’audio, le presse-papiers natif et son collage différé, le glisser-déposer, l’élévation, l’USB, ni les backends Windows/macOS/Wayland. Un réseau qui exige un proxy explicite ou refuse WebSocket peut donc bloquer le repli WSS ; le client respecte ce refus. Une compilation sur un autre OS ne signifie pas que sa capture ou ses entrées sont supportées ; le binaire refuse de démarrer avec une explication. Les 5 images JPEG par seconde constituent une base de fonctionnement et non une qualification de performance ou de faible latence.
