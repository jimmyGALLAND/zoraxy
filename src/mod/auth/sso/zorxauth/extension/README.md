# SKYNET SSO — extension Firefox

Extension compagnon de Zoraxy Auth.

## Fonctionnalités
- Barre supérieure escamotable au clic n'importe où en dehors de la barre.
- Encoche de réouverture activable ou désactivable dans les paramètres.
- Affichage de l'état de la session centrale et du nom d'utilisateur.
- Déconnexion depuis n'importe quelle page couverte.
- Icône SKYNET intégrée à l'extension.
- Thème sombre bleu nuit / cyan SKYNET.

## Installation temporaire
1. Ouvrir `about:debugging#/runtime/this-firefox`.
2. Choisir « Charger un module complémentaire temporaire ».
3. Sélectionner `manifest.json`.

## Configuration
L'URL du fournisseur est actuellement définie à `https://auth.celjim.fr` dans `background.js`.
Les domaines protégés et l'affichage de l'encoche sont configurables depuis la page d'options.

## API utilisée côté Zoraxy Auth
- `GET /user/api/info` — endpoint natif du portail utilisateur ; confirme la session et renvoie le profil de l'utilisateur.
- `POST /logout` — endpoint natif existant ; invalide toutes les sessions centrales de l'utilisateur et expire le cookie SSO du navigateur courant.

L'extension n'accède jamais au cookie SSO et ne le lit pas. Elle demande simplement au navigateur d'inclure le cookie dans les requêtes vers le fournisseur. Les éventuelles sessions locales propres aux applications tierces restent soumises à leur propre cycle de vie.