# Cyclar

Cyclar est un projet de contrôle distant auto-hébergé écrit en Rust. Sa cible réunit un serveur central d'identité et d'autorisations, un hôte léger, un contrôleur desktop et des contrôleurs mobiles. Le prototype Linux/X11 essaie une connexion directe chiffrée, puis un relais WebSocket opaque si le direct échoue. Le projet est **en développement** : l'[état des fonctionnalités](docs/status.md) distingue ce qui fonctionne déjà de la cible produit.

## Démarrer le prototype serveur

Prérequis : Rust 1.88 ou plus récent, avec Cargo. Le workspace contient `cyclar-server`, une bibliothèque de protocole et deux binaires desktop expérimentaux. Depuis la racine du dépôt :

```sh
cargo build --workspace --locked
cargo run -p cyclar-server -- init --data-dir ./data --admin-user admin
cargo run -p cyclar-server -- check --data-dir ./data
cargo run -p cyclar-server -- serve --data-dir ./data --listen 127.0.0.1:8080 --insecure-cookies
```

La commande `init` demande un mot de passe administrateur masqué dans un terminal interactif, ou lit une ligne sur l'entrée standard en automatisation. Il doit contenir de 16 à 256 caractères. Ne mettez pas ce secret dans les arguments ou l'historique du shell et protégez le répertoire `data`. L'option `--insecure-cookies` sert uniquement aux essais HTTP en boucle locale. Une écoute non locale exige `--behind-tls-proxy`, un proxy HTTPS de confiance et des cookies Secure ; le binaire refuse de la démarrer avec `--insecure-cookies`. Le panel est servi par le serveur ; les routes d'API sont sous `/api/v1`. Voir le [guide de déploiement](docs/deployment.md) pour les contraintes de TLS, de persistance et de sauvegarde.

Le serveur fournit aussi `backup` et `restore` **hors ligne** pour la base et l'identité. Ces commandes exigent l'arrêt de `serve`, une destination nouvelle et un emplacement privé ; la sauvegarde contient la clé de signature non chiffrée. Le [guide de déploiement](docs/deployment.md) détaille les commandes et limites.

## État et portée

Cette première tranche comprend l'initialisation du serveur, son panel, une API d'inscription des machines et des grants de session signés. Sous **Linux/X11 seulement**, `cyclar-host` peut capturer le bureau et `cyclar-desktop` peut ouvrir une fenêtre de contrôle sur une connexion TCP directe chiffrée, avec image JPEG et entrées XTest. C'est un prototype de développement : le parcours n'est pas encore qualifié par des essais matériels et réseau publiés, et l'hôte utilise le terminal au lieu d'une fenêtre dédiée.

Un transfert **manuel** de fichier contrôleur → hôte existe aussi dans le prototype Linux/X11 : il exige la capacité de session `FileTransfer`, l'option locale `--allow-files` et l'approbation explicite d'un dossier de destination sur l'hôte. Un test de 100 Ko sur TCP loopback via Noise a réussi ; aucun essai sur deux machines, gros fichier ou réseau instable n'est encore publié. Le relais a été éprouvé par un test WebSocket local avec un vrai échange Noise, **sans** validation du WSS public, d'un proxy ou d'un réseau externe. La traversée NAT directe/QUIC, l'audio, le presse-papiers natif, le glisser-déposer, l'USB, les clients mobiles et les backends desktop Windows/macOS ne sont pas disponibles. Aucune mesure de latence ou promesse de compatibilité matérielle n'est publiée. Consultez le [guide Linux/X11](docs/desktop-linux-x11.md) pour les commandes et limites. N'exposez pas une installation de développement comme un service de production.

L'[état des fonctionnalités](docs/status.md) indique les capacités disponibles et leurs limites. La [carte d'architecture](docs/architecture.md) distingue les rôles visés et les frontières de confiance ; le [modèle de sécurité](docs/security-model.md) et le [guide de validation](docs/testing.md) précisent les preuves attendues.

## Vérifier et contribuer

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Ces trois commandes ont passé le 8 octobre 2026 : 46/46 tests workspace, format vérifié et Clippy strict sans avertissement. Elles ne qualifient pas les parcours graphiques ou réseaux réels et doivent désormais être exécutées localement. Le [pipeline GitHub unique](docs/releasing.md) produit uniquement les archives des applications pour Linux, Windows et macOS, selon leurs architectures et backends disponibles. Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour les attentes de test et de revue, et [SECURITY.md](SECURITY.md) pour signaler une vulnérabilité de façon privée.

## Licence

Le dépôt est mis à disposition sous [PolyForm Internal Use License 1.0.0](LICENSE), selon le [texte officiel](https://polyformproject.org/licenses/internal-use/1.0.0). Cette licence permet certains usages internes et modifications, mais **interdit la redistribution**. Un accès public au code et la possibilité de contribuer ne suffisent pas à le rendre open source au sens de l'Open Source Initiative : cette licence est de type **source-available**. Pour autoriser des forks redistribuables, il faudrait une licence différente ou une permission distincte du titulaire des droits. Les dépendances conservent leurs propres licences.
