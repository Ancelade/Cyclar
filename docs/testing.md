# Validation

La vérification automatisée de base d'un workspace Rust est :

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Ces commandes ont passé le 8 octobre 2026, avec 46/46 tests workspace. L'[état des fonctionnalités](status.md) donne les preuves ciblées et leurs limites. La CI lance ces contrôles à chaque proposition de changement. Les tests unitaires doivent couvrir les entrées limites et les transitions d'état ; les tests d'intégration vérifient les échanges entre composants et les erreurs observables. Les tests de protocole, de réseau contraint, de permissions OS et de matériel doivent être exécutés sur les plateformes réellement annoncées comme supportées. Une compilation sur un OS ne prouve pas le fonctionnement de la capture, de l'injection ou du codec sur cet OS.

La CI est configurée pour compiler et tester le workspace sur trois OS et pour vérifier la version Rust minimale annoncée (1.88). Le backend Linux/X11 exige une session graphique et un autre poste ou une seconde instance pour son essai de bout en bout : suivez le [guide expérimental](desktop-linux-x11.md), puis vérifiez l'inscription, l'ID, le refus d'un mauvais secret, l'ouverture d'une session en lecture seule et avec entrées, la fermeture locale et la révocation depuis le panel. Le test desktop automatise un transfert de 100 Ko sur TCP loopback via Noise ; le test serveur fait communiquer les modules relais serveur et client avec un échange Noise sur WebSocket local. Ces tests ne valident pas encore un gros fichier, la reprise après redémarrage, deux postes physiques, le proxy WSS public ou les performances sous charge. Les essais manuels ne sont pas remplacés par un `cargo test` sur un runner sans affichage.

Pour une fonction de sécurité, associez un cas autorisé et un cas refusé : signature invalide, secret erroné, grant expiré ou révoqué, chemin sortant du répertoire, entrée malformée ou dépassement de quota selon le composant. Pour une optimisation, enregistrez le matériel, l'OS, les versions, le profil codec, le réseau, le nombre d'échantillons, la médiane/p95/p99 et les ressources consommées avant et après. Les objectifs de performance restent des cibles de qualification, pas des résultats acquis.

Les campagnes manuelles supplémentaires comprennent restauration, changements réseau, endurance, interopérabilité clavier, audio, presse-papiers différé et USB. Une fonctionnalité conditionnelle est marquée indisponible si son essai de qualification n'a pas réussi.
