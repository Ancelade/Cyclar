# Contribuer à Cyclar

Les propositions de correction, de documentation et de tests sont les bienvenues. L'[état des fonctionnalités](docs/status.md) distingue le prototype actuel des fonctions encore absentes ; la [carte d'architecture](docs/architecture.md) décrit les frontières du code. Une fonction prévue ne doit pas être présentée comme livrée avant une preuve d'exécution.

## Préparer une modification

Installez la chaîne Rust stable et les composants `rustfmt` et `clippy`. Depuis la racine :

```sh
rustup component add rustfmt clippy
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Ajoutez un test qui vérifie le comportement observable ou un cas limite pertinent. Pour les changements liés à l'identité, aux droits, aux chemins de fichiers ou aux messages réseau, couvrez aussi le refus des entrées invalides. Pour les changements du chemin média ou réseau sensible à la latence, joignez le protocole de mesure, l'environnement et les résultats avant/après. Ne présentez pas un benchmark local comme une garantie générale.

Gardez les demandes de changement ciblées et décrivez leur impact utilisateur, les plateformes testées, les limites connues et les commandes exécutées. Signalez les différences entre OS au lieu de masquer un comportement non disponible. Les interfaces et exemples doivent rester simples pour les usages courants. Aucun secret, capture d'écran d'une session réelle, saisie brute ni contenu de fichier utilisateur ne doit entrer dans les tests, traces ou discussions publiques.

Les versions publiées doivent conserver leur `Cargo.lock`. Une nouvelle dépendance nécessite une justification, la vérification de sa maintenance et de sa licence, puis des tests sur les plateformes touchées. Les modifications de protocole ou de stockage nécessitent une stratégie de compatibilité ou de migration documentée.

## Licence et contributions

Le code est proposé sous [PolyForm Internal Use 1.0.0](LICENSE). Cette licence autorise certains usages internes et changements, mais **n'accorde pas de droit de redistribution**. L'accès au dépôt et l'acceptation de contributions ne transforment pas la licence en licence open source au sens de l'OSI. Assurez-vous d'avoir le droit de proposer votre contribution et demandez une autorisation distincte au titulaire des droits avant toute redistribution d'un fork ou d'une version modifiée. Aucun transfert de droits ni licence différente n'est présumé par ce guide.

Pour signaler une vulnérabilité, suivez [SECURITY.md](SECURITY.md) plutôt qu'une issue publique.
