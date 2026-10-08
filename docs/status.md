# État des fonctionnalités

Cyclar est un prototype de contrôle distant auto-hébergé. Cette page décrit le code publié ; une compilation ou un test en boucle locale ne constitue pas une qualification sur matériel, réseau ou système d'exploitation réel.

| Fonction | État actuel | Limite principale |
| --- | --- | --- |
| Serveur central et panel web | Initialisation, comptes administrateur, registre des machines, présence, droits de session signés et révocation implémentés. | Administration et sécurité à qualifier avant un usage de production. |
| Identité machine | Clé Ed25519 prouvée à l'inscription, ID numérique attribué par le serveur, secret temporaire et mot de passe permanent facultatif. | Récupération d'identité et rotation automatique du secret absentes. |
| Contrôle desktop | Hôte et contrôleur Rust disponibles pour Linux/X11, capture JPEG CPU, fenêtre de restitution et entrées XTest. | L'hôte utilise un terminal ; Wayland, Windows, macOS et les hautes fréquences ne sont pas qualifiés. |
| Connexion réseau | TCP direct tenté en premier, puis relais WebSocket opaque avec Noise de bout en bout, droits courts et contrôle de révocation. | Interopérabilité testée sur boucle locale ; WSS public authentifié, NAT direct/QUIC, proxy réseau et performance restent à qualifier. |
| Transfert de fichier | Envoi manuel contrôleur → hôte, offre sans lecture anticipée, approbation locale, blocs bornés, BLAKE3 et publication atomique sans écrasement. | Aucun presse-papiers natif, glisser-déposer ni essai de gros fichier sur réseau instable. |
| Sauvegarde et restauration | Commandes hors ligne avec manifeste SHA-256, validation de la base et de l'identité avant restauration. | La sauvegarde contient la clé privée en clair ; restauration multi-OS et migration à qualifier. |
| Son système, USB, client mobile, élévation locale | Absents. | Ces parcours ne sont pas utilisables dans cette version. |

Le 8 octobre 2026, `cargo test --workspace --locked` a passé **46/46 tests** ; `cargo fmt --all -- --check` et Clippy strict ont aussi réussi. Les tests comprennent un échange Noise entre le vrai client Rust et le relais Axum via WebSocket **local**, ainsi qu'un transfert de 100 Ko sur boucle locale. Ils ne mesurent ni la latence de bout en bout ni la compatibilité matérielle.

La [carte d'architecture](architecture.md), le [guide de validation](testing.md) et le [modèle de sécurité](security-model.md) détaillent les frontières du prototype et les essais encore nécessaires.
