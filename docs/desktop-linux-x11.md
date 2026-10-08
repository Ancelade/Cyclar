# Essayer le contrôle Linux/X11

Cette procédure décrit le **prototype** disponible dans `cyclar-host` et `cyclar-desktop`. Les deux machines doivent disposer d'une session X11 accessible à leur utilisateur, avec visuel TrueColor 24 bits en pixels 32 bits little-endian. L'injection d'entrées nécessite XTest ; sans XTest, utilisez `--view-only` côté hôte et `--view-only-host` côté application complète. Wayland, Windows et macOS ne disposent pas de backend de capture actif dans cette version.

Le serveur central autorise la session. Les deux postes doivent pouvoir joindre son API ; hors boucle locale, elle doit être servie via HTTPS. Le contrôleur essaie d'abord l'adresse TCP annoncée par l'hôte, puis le relais WebSocket du central si ce chemin échoue. Le relais relaie les octets du canal Noise sans les déchiffrer ; sur un serveur public, son URL doit être en **WSS** et le proxy TLS doit transmettre la mise à niveau WebSocket. Le repli a été testé sur WebSocket loopback, pas encore à travers un proxy public ni sur deux réseaux distincts. Aucune traversée NAT directe ou voie QUIC n'est fournie.

## Essai sur un même poste

Démarrez d'abord le serveur selon le [guide de déploiement](deployment.md), avec `--listen 127.0.0.1:8080 --insecure-cookies`. Dans un deuxième terminal de la même session X11 :

```sh
cargo run -p cyclar-desktop --bin cyclar-host -- \
  --server http://127.0.0.1:8080 \
  --listen 127.0.0.1:7420 \
  --state ./data/host.json
```

L'hôte affiche son ID et montre son secret temporaire uniquement sur un terminal local interactif ; la commande `secret` le réaffiche. Gardez ce terminal privé et ne copiez pas ce secret dans un journal. Les commandes locales `rotate`, `set-password` et `clear-password` demandent au central de renouveler le secret temporaire ou de définir/supprimer un mot de passe permanent ; `set-password` masque et confirme la saisie. `sessions` liste les contrôleurs présents et `kick ID_SESSION` en interrompt un localement. Ces commandes ne remplacent pas un parcours de consentement local ni l'élévation système, encore absents. Dans un troisième terminal :

```sh
cargo run -p cyclar-desktop --bin cyclar-desktop -- \
  --server http://127.0.0.1:8080 \
  --listen 127.0.0.1:7421 \
  --state ./data/controller.json
```

L'application complète démarre aussi son propre hôte ; le second port et le second fichier d'identité évitent un conflit avec `cyclar-host`. À l'invite `cyclar>`, saisissez `connect ID` en remplaçant `ID` par le numéro affiché sur l'hôte, puis saisissez son secret dans l'invite masquée. Une fenêtre X11 affiche les images distantes. Fermez cette fenêtre pour terminer la session, puis tapez `quit` dans les terminaux des deux applications. L'essai sur un seul écran peut montrer une récursion visuelle lorsque la fenêtre de contrôle apparaît dans l'écran capturé.

Pour forcer le chemin relais lors de cet essai local, relancez l'hôte avec `--relay-only` et le même `--state`, puis reconnectez le contrôleur. L'hôte n'annonce alors aucune adresse directe et son port de session reste lié à la boucle locale. Le test automatisé serveur valide un échange Noise complet via le relais WebSocket local ; il ne valide pas le WSS d'un domaine public ni le pare-feu d'un réseau externe.

## Transfert manuel expérimental

Pour recevoir un fichier, relancez l'hôte avec `--allow-files` en conservant son `--state`. Préparez un dossier de destination existant dans l'environnement de test, par exemple `./data/reception`. Depuis l'invite du contrôleur, `send ID ./data/fichier-de-test.bin` propose un fichier existant sans lire ni expédier encore son contenu. Côté hôte, `files` affiche l'offre ; `approve ID_TRANSFERT ./data/reception` accepte le transfert dans ce dossier. Un grant avec capacité `FileTransfer`, cette option locale et l'approbation explicite sont tous requis. Le fichier est envoyé par blocs de 16 KiB après la demande de l'hôte, vérifié avec BLAKE3, puis publié sans écraser un fichier existant. `--connect ID --send-file CHEMIN` permet aussi de proposer un fichier à l'ouverture de la session.

Le test automatisé couvre un fichier de 100 Ko sur TCP loopback avec Noise, approbation, hachage final et publication. Il ne prouve pas un transfert de plusieurs Go, la reprise après redémarrage ou l'usage entre deux machines. L'état de reprise du prototype reste en mémoire ; n'en déduisez pas une reprise garantie après arrêt du processus. Le presse-papiers natif et le glisser-déposer ne sont pas intégrés.

Pour deux postes, remplacez l'URL du serveur par une URL HTTPS accessible aux deux. Si vous voulez tester le direct, faites annoncer à l'hôte une adresse joignable par le contrôleur avec `--advertise IP:PORT` et ouvrez uniquement ce port TCP sur un réseau de test maîtrisé. La valeur annoncée doit correspondre au port de `--listen` ; le serveur ne vérifie pas son accessibilité. Si vous voulez éviter tout port entrant sur l'hôte, utilisez `--relay-only` **sans** `--advertise` : les deux postes doivent alors pouvoir établir leurs connexions WSS sortantes vers le central. Chaque poste garde son propre fichier `--state`, qui contient une clé privée et des secrets de machine : ne le versionnez pas et protégez ses permissions.

Ce parcours utilise du JPEG logiciel à cadence modeste et un canal Noise chiffré sur TCP direct ou relais WebSocket. Il ne propose pas encore d'audio, de presse-papiers, d'USB, d'assistance avec élévation, de carnet de compte ni de sélection adaptative de codec. Il ne constitue pas une qualification de sécurité ou de latence pour un usage de production.
