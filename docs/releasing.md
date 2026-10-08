# Préparer une livraison

Le workflow unique [Application artifacts](../.github/workflows/artifacts.yml) compile les applications en mode release avec le `Cargo.lock` du dépôt. Il démarre sur les pushes vers `main` ou `master`, les pull requests, les étiquettes `v*` ou manuellement. Les anciennes automatisations de tests, de lint, d'audit des dépendances, de contrôle Docker et Dependabot sont supprimées ; ce pipeline sert uniquement à produire les artefacts.

| Système | Architecture | Cible Rust | Applications |
| --- | --- | --- | --- |
| Linux | x86 64 bits | `x86_64-unknown-linux-gnu` | Serveur, hôte, client desktop |
| Linux | x86 32 bits | `i686-unknown-linux-gnu` | Serveur, hôte, client desktop |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` | Serveur, hôte, client desktop |
| Linux | ARMv7 32 bits, hard-float | `armv7-unknown-linux-gnueabihf` | Serveur, hôte, client desktop |
| Windows | x86 64 bits | `x86_64-pc-windows-msvc` | Serveur |
| Windows | x86 32 bits | `i686-pc-windows-msvc` | Serveur |
| Windows | ARM64 | `aarch64-pc-windows-msvc` | Serveur |
| macOS | Intel 64 bits | `x86_64-apple-darwin` | Serveur |
| macOS | Apple Silicon | `aarch64-apple-darwin` | Serveur |

Dans l'onglet Actions, ouvrez une exécution puis téléchargez l'artefact `cyclar-<cible Rust>`. Il contient une archive par application (`.tar.gz` sur Linux/macOS, `.zip` sur Windows) et son fichier `.sha256`. Chaque archive contient le binaire et la licence. Les artefacts sont conservés 14 jours. Les cibles Linux x86 et ARMv7 sont compilées depuis un runner x64 avec le compilateur C adapté ; les autres architectures utilisent des [runners GitHub natifs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Les hôtes et clients desktop exigent Linux/X11 : les backends Windows/macOS et les clients mobiles ne sont pas disponibles dans le dépôt. La matrice décrit les compilations demandées au pipeline ; son exécution réussie reste à vérifier sur GitHub pour chaque cible.

Avant de publier une version, les mainteneurs doivent exécuter les [contrôles locaux](testing.md) sur le commit exact, vérifier que la matrice de plateformes annoncée a été exécutée, que le [journal des changements](../CHANGELOG.md) et le [guide de déploiement](deployment.md) reflètent la version, et qu'une sauvegarde/restauration **hors ligne** depuis la version précédente a été répétée sur une installation isolée. Les opérations manuelles dépendantes de l'OS (signature, notarisation Apple, installateurs, pilotes et tests matériels) ne sont pas remplacées par ce workflow. Ces artefacts ne constituent pas, seuls, une publication signée ou une certification de sécurité.

Un tag `v*` ne déploie aucun service et ne crée pas automatiquement de publication GitHub. La distribution du logiciel et des versions modifiées reste soumise à [PolyForm Internal Use 1.0.0](../LICENSE) et aux droits du titulaire de la licence. Vérifiez aussi les obligations des dépendances et des codecs utilisés par les binaires effectivement distribués.
