# Journal des changements

Ce projet n'a pas encore de version produit qualifiée. Les changements vérifiés et publiés seront consignés ici avec leurs limites de plateforme et de sécurité.

## En développement

- Amorçage du workspace Rust, du serveur et des grants de session signés.
- Premier parcours direct expérimental de contrôle Linux/X11 en Rust, avec image JPEG et entrées XTest.
- Commandes locales de rotation et de définition/suppression du secret permanent ; transfert manuel de fichier vers l'hôte avec approbation locale, éprouvé sur TCP loopback.
- Sauvegarde et restauration hors ligne de la base et de la clé serveur, avec manifeste SHA-256 et validation avant publication.
- Repli expérimental par relais WebSocket opaque pour le canal Noise, testé entre serveur et client sur boucle locale.
- Documentation de développement, de sécurité et de livraison.
