# 4.4 — Gestion des secrets

**Date :** 28 novembre 2026 · **Dépôt :** `arijtrab/Doc-Vault` · **Heures :** UTC
**Preuves :** dossier `preuves/` (fichiers `4.4-*`), captures GitHub

## 1. Inventaire des secrets de DocVault

| Secret | Usage | Fourni par |
|---|---|---|
| `DOCVAULT_MASTER_KEY` | Clé maîtresse AES-256 (64 caractères hexadécimaux) qui protège les clés des documents | Fichier monté : secret Compose, puis Secret Kubernetes (4.5) |
| `DOCVAULT_MASTER_KEY_VERSION` | Version de la clé active, ce qui permet la rotation | Variable non sensible |
| `DOCVAULT_PASSWORD_RESET_WEBHOOK_TOKEN` | Jeton du webhook de réinitialisation de mot de passe (optionnel) | Variable d'environnement ; non utilisé dans le labo |
| `GITHUB_TOKEN` du pipeline | Jeton fourni automatiquement par GitHub Actions, en lecture seule (`contents: read`) | GitHub, durée de vie limitée au job |

Aucun de ces secrets n'est écrit dans le code, dans `compose.yaml`, dans les Dockerfile ou dans l'historique Git.

## 2. Défense en profondeur contre les fuites

| Couche | Moment | Mécanisme | Preuve |
|---|---|---|---|
| 1 | Avant le commit | `.gitignore` : `secrets/`, `.env*` | `git check-ignore -v secrets/docvault_master_key` → `.gitignore:12:secrets/` |
| 2 | Avant le build | `.dockerignore` : `**/secrets/**`, `**/*secret*`, `**/*.key`, `.env*` | La règle `**/*secret*` a exclu un fichier de **code** nommé `secrets.ts` : le module a été renommé `runtimeKeys.ts` plutôt que d'affaiblir la règle |
| 3 | Au push | GitHub **push protection** | Push refusé (`GH013`, T1) |
| 4 | Dans le pipeline | Gitleaks `v8.30.1`, caviardage `--redact` | PR #2 bloquée (4.3) ; PR #7 verte |
| 5 | Sur l'image | Trivy `--scanners secret`, contrôle `DS-0031` | 0 secret dans les images ; `DS-0031` en PASS |
| 6 | Sur GitHub | Secret scanning (alertes) | Alerte #1 « GitHub Personal Access Token », fermée comme *Revoked* |

## 3. Secrets fournis à l'exécution, jamais dans l'image ni le code

**Mécanisme.**
- `security/runtimeKeys.ts` lit la clé dans le fichier désigné par `DOCVAULT_MASTER_KEY_FILE`, ou, à défaut, dans `DOCVAULT_MASTER_KEY`.
- Il vérifie que la clé fait 64 caractères hexadécimaux.
- Il n'écrit jamais sa valeur dans les journaux, seulement sa version et une empreinte (8 premiers caractères de son SHA-256).
- `backend/index.ts` charge la clé au démarrage : **le serveur refuse de démarrer sans clé valide**.
- Dans `compose.yaml`, la clé est un secret Compose monté dans `/run/secrets/docvault_master_key`. Le conteneur ne reçoit que le **chemin** du fichier. La clé elle-même (`secrets/docvault_master_key`, générée par `openssl rand -hex 32`) reste sur le poste et n'est jamais commitée.

**Preuves (`preuves/4.4-B-preuves.txt`).**

| Où chercher la clé | Méthode | Occurrences |
|---|---|---|
| Configuration du conteneur | `docker inspect` | **0** (seulement `DOCVAULT_MASTER_KEY_FILE=/run/secrets/docvault_master_key` et `DOCVAULT_MASTER_KEY_VERSION=v1`) |
| Image backend | `docker save` | **0** |
| Journaux | `docker compose logs backend` | **0** (seulement `version v1, fingerprint 3e300f8e (value never logged)`) |

**Refus de démarrer (`preuves/4.4-B-sans-cle.txt`).** Avec une clé invalide, le backend s'arrête (`Exited (1)`) avec le message :
`Error: DOCVAULT_MASTER_KEY_FILE (or DOCVAULT_MASTER_KEY) must provide 64 hexadecimal characters.`
L'application ne démarre jamais avec une clé absente, vide ou par défaut.

**Rotation (`preuves/4.4-B-demarrage.txt`).** Une nouvelle clé est générée et la version passe à `v2`. L'empreinte change, de `3e300f8e` (v1) à `d6c7c7e4` (v2) : on prouve le changement sans révéler la valeur.

**Contrôle dans le pipeline.** La PR #7 (commit `2bf8204`) passe Gitleaks, Dépendances, IaC et les deux scans d'images. Semgrep échoue uniquement sur les failles volontaires DV-06, DV-07 et DV-09.

## 4. Démonstration « révoquer d'abord, purger ensuite »

**Secret utilisé :** un vrai jeton GitHub *fine-grained*, sans aucune permission et valable 1 jour. Il est sans danger, détectable, et sa révocation est vérifiable par l'API GitHub. La clé AWS de la PR #2, inventée, ne permettait pas de prouver une révocation.

| Étape | Heure (UTC) | Événement |
|---|---|---|
| T0 | 09:34:58 | Jeton créé ; API GitHub → `HTTP 200` (valide) |
| T0b | 09:36:41 | Jeton collé par erreur dans une conversation avec un assistant IA : exposition **hors dépôt** |
| T1 | 09:44:21 | Commit `0b7aa0c` (jeton), puis commit de suppression du fichier ; **push refusé** par la push protection (`GH013`) |
| T2 | 09:50:06 | Gitleaks retrouve le jeton (`github-fine-grained-pat`, commit `0b7aa0c`) **malgré la suppression du fichier**, valeur caviardée |
| T3 | 09:55:13 | Contournement **volontaire** de la push protection (raison : test) ; jeton sur `origin/demo/secret-revocation` ; alerte secret scanning #1 « Public leak » |
| **T4** | 10:01:29 | **Révocation constatée** : API → `HTTP 401`. Jeton invalidé automatiquement par GitHub (fuite publique) ; l'heure exacte se situe entre T3 et T4 |
| T4b | 10:07:38 | Jeton supprimé par sa propriétaire ; alerte #1 fermée comme *Revoked* |
| **T5** | 10:08:35 | **Purge** : branche réécrite (`git filter-branch --index-filter … --prune-empty`), suppression de `refs/original`, du reflog et des objets (`gc`), puis `push --force` |
| T6 | 10:16:08 | **Limite constatée** : le commit `0b7aa0c` reste consultable par son identifiant sur GitHub (« does not belong to any branch ») |

**La révocation (T4) précède la purge (T5).** Quand l'historique a été nettoyé, le secret était déjà inutilisable.

## 5. Vérification : aucun secret dans le dépôt ni l'historique

| Vérification | Commits analysés | Résultat |
|---|---|---|
| Branche purgée `demo/secret-revocation` (clone neuf) | 10 | **0 fuite** |
| Après suppression de `demo/secret` (fausse clé AWS) : clone neuf, **toutes les branches** (`--all`) | 11 | **0 fuite** |
| Clone miroir (`--mirror`, références `refs/pull/*` incluses) | 13 | 1 fuite : fausse clé AWS, via `refs/pull/2/head` |

Le critère « l'outil ne trouve aucun secret dans l'historique » est rempli pour le dépôt et toutes ses branches. Le clone miroir montre une limite propre à GitHub (§ 6).

## 6. Limites et réflexion critique

- **La purge ne fait pas disparaître un secret publié.**
  - GitHub sert encore le commit purgé `0b7aa0c` par son identifiant.
  - Il garde aussi pour toujours les commits des pull requests, même fermées : `refs/pull/2/head` contient encore la fausse clé.
  - Seul le support GitHub peut supprimer ces copies, et les clones ou forks faits avant la purge restent hors de contrôle.
  - C'est pour ça que la révocation passe toujours en premier, et qu'il ne faut jamais ouvrir de PR avec un vrai secret.
- **La révocation automatique est un filet, pas une méthode.** GitHub a invalidé le jeton parce qu'il s'agissait d'un jeton GitHub, dans un dépôt public. Une clé de chiffrement DocVault ou un mot de passe de base de données ne serait jamais révoqué automatiquement.
- **La push protection peut être contournée.** Un développeur a pu passer outre (T3) en choisissant une raison. En production, le contournement devrait exiger l'approbation d'un responsable sécurité.
- **Une fuite peut se produire hors du dépôt.** Le jeton a été collé dans une conversation avec un assistant IA (T0b). Ni Gitleaks ni GitHub ne voient ce canal : seules la révocation et la formation de l'équipe y répondent.
- **Supprimer un fichier ne retire pas un secret.** Gitleaks a retrouvé le jeton dans le commit précédent (T2).
- **Le refus de démarrer doit venir du code.** Docker Compose n'a affiché qu'un avertissement quand le fichier du secret manquait, et Docker a créé un dossier vide à sa place. C'est l'application qui garantit qu'elle ne tourne jamais sans clé.
- **La variable de secours reste visible.** `DOCVAULT_MASTER_KEY` reste accepté pour le développement local, mais il apparaîtrait dans `docker inspect` : seule la forme `_FILE` est utilisée dans les déploiements.
- **La rotation n'est que partielle.** Tant que DV-05 (stockage en clair) n'est pas corrigée, la rotation ne fait que changer la clé chargée. Une rotation complète devra rechiffrer les clés des documents (`security/migrateEncryption.ts`), en gardant l'ancienne clé dans `DOCVAULT_MASTER_KEYRING` pendant l'opération.
- **La clé est en clair sur l'hôte.** `secrets/docvault_master_key` n'est protégé que par les droits du système de fichiers local. En 4.5, le Secret Kubernetes sera seulement encodé en base64 : il faudra activer le chiffrement au repos du cluster, ou utiliser un coffre externe.
- **L'outil de purge utilisé est déconseillé.** `git filter-branch` a été utilisé parce qu'il est inclus dans Git ; `git filter-repo` est l'outil recommandé pour un vrai dépôt.
