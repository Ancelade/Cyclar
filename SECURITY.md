# Sécurité

Cyclar traite des autorisations de contrôle distant et, selon les composants livrés, des secrets de machines, des flux d'écran et des fichiers. Une version de développement ne doit pas être considérée apte à l'exposition Internet ou à un usage sensible sans qualification des fonctions réellement présentes.

## Signaler une vulnérabilité

Utilisez le signalement privé de vulnérabilité de GitHub dans l'onglet **Security** du dépôt, s'il est activé. Sinon, contactez les mainteneurs par un canal privé indiqué sur la page du projet. Évitez une issue ou une pull request publique pour une faille exploitable. Décrivez la version, le composant, les étapes minimales de reproduction et l'impact ; n'envoyez pas de secrets ni de données personnelles réelles.

Les mainteneurs accuseront réception, reproduiront le problème, détermineront les versions touchées et publieront une correction accompagnée d'une note de sécurité quand cela est possible. Aucun délai de réponse fixe n'est annoncé avant la mise en place d'un canal de suivi dédié.

## Frontières de confiance visées

Le [modèle de sécurité](docs/security-model.md) consigne les protections attendues et les vérifications à mener. En particulier, le chiffrement de transport seul ne prouve ni l'identité d'une machine ni la validité des droits de contrôle ; un serveur central autoritaire ne dispense pas l'hôte de revérifier les capacités sensibles. Les promesses de chiffrement de bout en bout, de résistance au rejeu et d'absence de fuite par le relais exigent des tests ciblés avant d'être annoncées comme garanties d'une version.
