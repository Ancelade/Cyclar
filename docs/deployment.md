# Déploiement du serveur de développement

Ce guide couvre le binaire `cyclar-server` présent dans le dépôt. Les fonctions futures ne sont pas supposées disponibles ici. Avant une exposition publique, il faut qualifier l'authentification, les droits, les sauvegardes, les limites réseau et la sécurité du panel.

## Initialisation locale

Installez Rust 1.88 ou une version plus récente, puis compilez :

```sh
cargo build -p cyclar-server --release --locked
./target/release/cyclar-server init --data-dir ./data --admin-user admin
./target/release/cyclar-server check --data-dir ./data
./target/release/cyclar-server serve --data-dir ./data --listen 127.0.0.1:8080 --insecure-cookies
```

Sous Windows, utilisez `target\\release\\cyclar-server.exe` et configurez des ACL qui réservent le répertoire, la clé et la base au compte du service ; le programme n'installe pas automatiquement une ACL équivalente à `0600` sur cet OS. `init` masque la saisie du mot de passe dans un terminal interactif ; en automatisation, il lit une seule ligne sur l'entrée standard. Ne passez le mot de passe ni dans les arguments, ni dans un fichier versionné. Sur Linux/macOS, réservez le répertoire de données à l'utilisateur du processus (`0700`) : la clé est créée en `0600` et chaque ouverture de `cyclar.redb` réapplique `0600` à la base. Sur les trois OS, ne partagez pas ces fichiers avec un serveur web statique, un répertoire synchronisé public ou un compte non autorisé.

Le mode ci-dessus écoute seulement en boucle locale. `--insecure-cookies` n'est adapté qu'à cet essai HTTP local. Le serveur ne termine pas lui-même TLS : pour un accès réseau, placez un proxy HTTPS de confiance devant lui et omettez `--insecure-cookies`. Quand le proxy est sur la même machine, gardez `--listen 127.0.0.1:8080`. Le navigateur doit accéder à l'URL **HTTPS** du proxy pour que le cookie de session `Secure` fonctionne. Le proxy doit conserver le chemin, la méthode, les en-têtes de requête et les réponses, et transmettre la mise à niveau WebSocket sur `/api/v1/relay/...` pour le repli WSS. Le test automatisé actuel du relais utilise WebSocket en boucle locale, sans prouver encore cette configuration TLS publique.

Dans un conteneur où le proxy TLS doit joindre une adresse non locale, utilisez par exemple :

```sh
./target/release/cyclar-server serve --data-dir ./data --listen 0.0.0.0:8080 --behind-tls-proxy
```

La présence de `--behind-tls-proxy` confirme la topologie attendue ; elle ne chiffre pas le port interne. Le serveur refuse une écoute non locale sans cette option et refuse `--insecure-cookies` sur cette écoute. Configurez le réseau du conteneur ou le pare-feu pour que **seul** le proxy TLS atteigne le port 8080. Le proxy doit limiter par **IP cliente vérifiée** les routes de connexion web (`/login`), d'inscription des machines (`/api/v1/devices`) et de demande de session (`/api/v1/sessions/request`). En mode proxy, le serveur conserve ses quotas par compte et machine, mais ne peut pas appliquer un quota global par IP cliente à partir de la seule adresse de sa connexion avec le proxy. Il ignore un `X-Forwarded-For` fourni sans chaîne de confiance explicite ; ne laissez pas un client choisir l'IP utilisée par la limite du proxy.

Utilisez l'URL HTTPS publique réellement configurée et vérifiez son certificat avant de considérer l'accès comme actif. Les hôtes et contrôleurs hors de la machine du serveur doivent recevoir cette URL via `--server` ; n'utilisez pas l'adresse HTTP interne pour des secrets réels.

## Conteneur et Compose

Le [Dockerfile](../Dockerfile) compile seulement `cyclar-server` avec Rust 1.88, `Cargo.lock` et des images de base officielles épinglées par digest. L'image finale Alpine exécute le binaire avec l'UID/GID 1000, sans compilateur ni droit root. Son healthcheck interroge `/healthz` sur la boucle locale ; le processus reçoit `SIGINT` à l'arrêt pour laisser le serveur fermer ses connexions. Ces entrées fixées rendent la reconstruction prévisible, sans constituer à elles seules une preuve de binaires bit à bit identiques.

L'[exemple Compose](../compose.yaml) persiste `/var/lib/cyclar` dans un volume nommé et publie le port HTTP **uniquement sur la boucle locale de l'hôte Docker**. Initialisez une fois avant de démarrer le service :

```sh
docker compose build server
docker compose run --rm --no-deps server init --data-dir /var/lib/cyclar --admin-user admin
docker compose up -d server
docker compose exec server wget -q -O /dev/null http://127.0.0.1:8080/healthz
```

La commande `init` masque la saisie sur un terminal interactif. En automatisation, fournissez une seule ligne sur l'entrée standard depuis un gestionnaire de secrets et désactivez le TTY avec `docker compose run -T` ; aucun mot de passe ne doit figurer dans `compose.yaml`, une variable versionnée ou la ligne de commande. Le volume conserve la clé privée, les hachages de mots de passe et la base : protégez l'accès Docker et les sauvegardes. Avec un montage de répertoire hôte à la place du volume nommé, donnez à l'UID 1000 les droits nécessaires avant l'initialisation. La commande `check` ouvre la base redb : exécutez-la quand `serve` est arrêté, car redb verrouille son fichier pendant le service.

Le `CMD` de l'image utilise `--listen 0.0.0.0:8080 --behind-tls-proxy` **à l'intérieur** du conteneur ; cette option n'ajoute pas TLS. L'exemple Compose suppose un proxy HTTPS exécuté sur l'hôte Docker, qui joint `127.0.0.1:8080` et applique la limite par IP cliente vérifiée décrite ci-dessus. Un proxy dans un autre conteneur doit partager un réseau interne avec le serveur sans publier le port HTTP brut. Ne configurez pas une route ou un secret en dur dans l'image.

## Exploitation et restauration

Exécutez le processus sous un compte dédié avec accès minimal au répertoire de données. Pendant qu'il tourne, contrôlez sa disponibilité via `/healthz` et ses journaux, sans y copier de secret. Lancez `cyclar-server check --data-dir PATH` seulement quand `serve` est arrêté pour examiner le schéma et l'identité. Définissez des quotas disque et une politique de conservation conformes aux données réellement stockées par la version utilisée.

`backup` et `restore` sont des opérations **hors ligne** : arrêtez `serve` avant de les lancer. redb verrouille la base ouverte, et une copie pendant des écritures ne serait pas cohérente. L'exemple Unix suivant suppose un répertoire privé **hors du dépôt** ; remplacez le chemin proposé par un emplacement durable et inscriptible par le compte qui exécute le serveur :

```sh
CYCLAR_PRIVATE_DIR=/chemin/prive/cyclar
install -d -m 700 "$CYCLAR_PRIVATE_DIR"
./target/release/cyclar-server backup --data-dir ./data --output "$CYCLAR_PRIVATE_DIR/backup-001"
./target/release/cyclar-server restore --from "$CYCLAR_PRIVATE_DIR/backup-001" --data-dir "$CYCLAR_PRIVATE_DIR/restore-check"
./target/release/cyclar-server check --data-dir "$CYCLAR_PRIVATE_DIR/restore-check"
```

Le parent de chaque nouvelle destination doit déjà exister et, sous Unix, ne doit pas être inscriptible par le groupe ni par d'autres utilisateurs. Les répertoires créés utilisent `0700`, les fichiers `0600`. `backup` inclut `cyclar.redb`, **la clé privée `server-key` en clair**, et `manifest.json` avec version, tailles et SHA-256. Le contenu n'est **pas chiffré** : protégez l'emplacement et chiffrez séparément toute copie externe. Les SHA-256 détectent une corruption accidentelle, sans authentifier un manifeste qu'un attaquant pourrait aussi remplacer. Sous Windows, configurez et vérifiez des ACL équivalentes pour les dossiers et fichiers de sauvegarde.

`restore` refuse une destination existante, vérifie les empreintes avant copie, revérifie la base et un administrateur actif dans un répertoire temporaire, puis publie ce répertoire. `backup` refuse également d'écraser une destination. Ne lancez pas deux opérations vers le même nom : le `rename` standard n'offre pas de garantie `NOREPLACE` portable contre un autre processus du **même compte** qui créerait une destination vide entre le dernier contrôle et la publication. Testez la restauration sur un environnement isolé avant toute utilisation réelle. Pour Compose, arrêtez d'abord le service et montez un volume de sauvegarde privé distinct ; l'exemple Compose fourni ne monte pas ce second volume.

La matrice OS, le packaging signé, la rotation des clés et les mises à jour compatibles avec les migrations restent des travaux à réaliser, pas des garanties de ce prototype. Consultez l'[état des fonctionnalités](status.md).
