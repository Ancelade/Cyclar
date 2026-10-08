# Modèle de sécurité cible

Cette page traduit les frontières de confiance du produit en critères de revue. Elle décrit les protections **à démontrer** pour chaque version concernée, sans attribuer ces garanties aux composants encore absents.

| Frontière | Risque | Preuve attendue |
| --- | --- | --- |
| Client ↔ central | Usurpation de compte ou de machine | Preuve d'identité cryptographique, limitation des essais, refus des clés remplacées sans procédure. |
| Central ↔ hôte | Autorisation forgée, rejouée ou révoquée | Signature/MAC vérifiée par l'hôte, expiration, nonce, époque de révocation et capacités minimales. |
| Hôte ↔ contrôleur | Lecture ou modification de la session | Chiffrement authentifié de bout en bout, identité des pairs liée à l'autorisation. |
| Hôte/contrôleur ↔ relais | Observation des contenus | Paquets opaques pour le relais, quotas et refus de destinations arbitraires. |
| Session ↔ système | Commande élevée ou entrée non autorisée | Contrôle local des capacités, consentement à l'élévation et helper privilégié minimal. |
| Flux ↔ fichiers/clipboard/USB | Traversée de chemin, volume excessif ou données malformées | Validation des longueurs et chemins, quotas, transfert demandé, tests de propriété et fuzzing. |
| Administration web ↔ central | CSRF, injection ou fuite de secret | Contrôle d'accès, validation d'entrée, cookies et en-têtes adaptés, journaux expurgés. |

Le central peut autoriser une session, mais l'hôte doit pouvoir refuser localement une opération sensible. Une compromission de l'identité du central peut compromettre la décision d'accès ; le chiffrement E2E n'annule pas ce risque. Les contenus d'écran, frappes, sons et fichiers ne doivent pas être journalisés par défaut. Les rapports de diagnostic et jeux de tests doivent employer des données fictives.

Sur Unix, la base redb est ramenée à `0600` lors de son ouverture et la clé est créée en `0600` dans un répertoire de données `0700`. Sur Windows, l'exploitant doit définir des ACL équivalentes ; aucune protection de fichier Unix n'y est transposée automatiquement. Les sauvegardes incluent la clé privée en clair et exigent une protection distincte.

Le prototype Linux/X11 utilise `snow` pour `Noise_NN_25519_ChaChaPoly_SHA256`. Le grant signé par le central est le prologue Noise ; des signatures Ed25519 lient les deux messages de handshake aux identités autorisées. La suite desktop a passé 15/15 tests, dont un transfert de 100 Ko sur TCP loopback après approbation locale et contrôle d'intégrité avant publication. La suite serveur a passé 17/17 tests, dont un vrai échange Noise entre client et serveur relais via WebSocket **local**, ainsi que des refus après expiration, révocation et changement d'époque de clé. Cela vérifie des invariants ciblés du code, **pas** un audit cryptographique, un test du WSS public ou une qualification sur réseau hostile. Le serveur relais ne déchiffre pas les octets de session dans ce chemin testé ; sa résistance à une compromission ou à une charge réelle reste à démontrer.

Pour une installation derrière un proxy TLS, la limite par IP cliente réelle des routes de connexion, d'inscription et de demande de session doit être appliquée par ce proxy à partir d'une adresse vérifiée. Le serveur applique des quotas par compte et par ID de machine, mais ne fait pas confiance à un en-tête `X-Forwarded-For` envoyé par un client. La topologie réseau doit empêcher de contourner le proxy et d'atteindre directement le port HTTP interne.

Chaque mécanisme ajouté doit posséder des tests de refus correspondants. Voir le [guide de validation](testing.md) et la [politique de signalement](../SECURITY.md).
