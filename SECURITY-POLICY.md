# Politique de blocage du pipeline — DocVault

**Version :** 27 novembre 2026 · **Pipeline :** `.github/workflows/ci.yml` (GitHub Actions)
**Règle générale :** tout job de sécurité qui se termine avec un code de sortie non nul fait échouer le pipeline. Une pull request vers `main` ne peut être fusionnée que si les cinq contrôles réussissent (protection de branche, voir § 5).

## 1. Contrôles et seuils

| # | Contrôle | Outil (version épinglée) | Périmètre | Casse le build si… | Justification du seuil |
|---|---|---|---|---|---|
| 1 | Secrets | Gitleaks `v8.30.1` | Tout l'historique accessible depuis le commit testé | **au moins un secret**, quelle que soit sa nature | Un secret poussé est compromis dès le push : il doit être révoqué, ce qu'aucune gravité ne permet d'ignorer. Les valeurs sont caviardées (`--redact`) dans les journaux et le rapport. |
| 2 | SAST | Semgrep (règles `p/owasp-top-ten`, `p/security-audit`, `semgrep-rules/docvault.yml`) | `backend`, `database`, `security`, `frontend/src` | au moins un résultat de sévérité **ERROR** | ERROR correspond aux règles à forte confiance (injection, XSS, CORS permissif). Les niveaux WARNING/INFO produisent trop de faux positifs pour bloquer sans revue ; ils restent visibles dans le rapport. |
| 3 | Dépendances | Trivy `0.76.2` (`fs`) | `package-lock.json`, `docker/backend-runtime/package-lock.json`, dépendances de dev incluses | CVE **HIGH ou CRITICAL** avec **correctif disponible** | Une CVE corrigible ne demande qu'une mise à jour : la bloquer ne paralyse pas l'équipe. Les dépendances de dev sont incluses car React et Vite finissent dans le bundle servi aux navigateurs. |
| 4 | IaC | Trivy `0.76.2` (`config`) | Dockerfiles, puis manifestes Kubernetes (4.5) | mauvaise configuration **HIGH ou CRITICAL** | Ces niveaux couvrent l'exécution en root, les secrets dans les build-args/ENV, les privilèges excessifs : exactement ce que 4.1 et 4.5 interdisent. |
| 5 | Images | Trivy `0.76.2` (`image`, vuln + secret) | Images backend et frontend construites dans le job | CVE **HIGH ou CRITICAL** avec **correctif disponible**, ou **un secret** dans l'image | Même logique que le contrôle 3, appliquée au système d'exploitation de l'image. |

### Pourquoi HIGH et pas seulement CRITICAL

Le 27/11/2026, l'image frontend contenait 6 CVE **HIGH** dans `libxml2`, dont plusieurs permettent une exécution de code arbitraire. Un seuil CRITICAL seul les aurait laissées passer. Le CVSS classe la gravité « en général » ; une exécution de code dans un composant exposé justifie un blocage même en HIGH.

### Pourquoi ignorer les CVE sans correctif (`--ignore-unfixed`)

Bloquer sur une CVE sans correctif arrêterait le pipeline sans qu'aucune action de l'équipe ne puisse le débloquer. Ces CVE ne sont pas oubliées : elles sont listées sans filtre dans un scan complet hebdomadaire et réexaminées (voir § 4).

## 2. Exceptions tolérées

Une exception n'est acceptée que si **les quatre conditions** sont remplies :

1. **Pas de correctif applicable** dans l'immédiat (correctif absent, ou incompatible et en cours d'adaptation).
2. **Analyse de risque écrite** : composant touché, exposition réelle, mesure compensatoire.
3. **Approbation** par deux membres de l'équipe, dont le responsable sécurité de la semaine.
4. **Date d'expiration** inscrite dans le mécanisme d'exception lui-même, pour que le pipeline se remette à bloquer tout seul.

| Contrôle | Mécanisme | Échéance maximale |
|---|---|---|
| Dépendances / images | `.trivyignore` avec `exp:AAAA-MM-JJ` (ex. `CVE-2026-11979 exp:2026-12-11`) | CRITICAL : 7 jours · HIGH : 30 jours |
| SAST | commentaire `// nosemgrep: <id-de-règle> -- <raison>, expire le AAAA-MM-JJ` | 30 jours, puis correction obligatoire |
| IaC | `.trivyignore` avec `AVD-…`/`DS-…` et `exp:` | 30 jours |
| Secrets | **aucune exception** pour un vrai secret. Un faux positif avéré peut être ajouté à `.gitleaksignore` (empreinte) après vérification par deux membres. | — |

**Exception en cours :** `libxml2` dans l'image frontend — l'image de base `nginx-unprivileged:1.30.8-alpine3.24` n'est pas encore republiée avec le correctif. Mesure appliquée : `apk upgrade --no-cache libxml2` dans `Dockerfile.frontend`. Échéance : retirer cette ligne et épingler le nouveau digest dès la publication de l'image corrigée, au plus tard le 27/12/2026.

## 3. Failles volontaires du laboratoire

La branche `main` contient volontairement les failles DV-01 à DV-11. Semgrep en détecte trois (DV-06 SQLi, DV-07 XSS, DV-09 CORS) : **le job SAST échoue donc sur `main` jusqu'à leur correction.** C'est le comportement attendu et la preuve que le contrôle fonctionne. Aucune exception n'est créée pour ces failles : elles sont corrigées, puis le pipeline redevient vert.

Les autres failles (DV-01 à DV-04, DV-11 : logique d'authentification et d'autorisation) **ne sont pas détectables par ce SAST** ; elles sont couvertes par les tests dynamiques (4.6) et les tests de non-régression (`TEST-PLAN.md`).

## 4. Revue périodique

- Scan complet hebdomadaire sans `--ignore-unfixed` ni filtre de gravité, archivé.
- Revue des exceptions à chaque échéance ; une exception expirée n'est jamais prolongée sans nouvelle analyse.
- Mise à jour des versions épinglées des outils une fois par mois, dans une pull request dédiée.

## 5. Ce que le pipeline ne prouve pas

- Un pipeline vert signifie « aucun résultat au-dessus des seuils, avec ces règles, à cette date ». Ce n'est pas une preuve d'absence de faille : une image propre le 25/11 ne l'était plus le 27/11.
- Le SAST ne voit pas les failles de logique (mot de passe ignoré, contrôle d'accès absent, rôle forcé).
- Semgrep n'a analysé que partiellement 4 fichiers TSX (erreurs d'analyse sur le caractère `&` dans du texte JSX) ; une faille dans ces portions pourrait passer inaperçue.
- Gitleaks ne détecte que les formats de secrets connus ; un mot de passe « maison » peut passer.
- Le blocage n'est effectif que si la protection de branche impose la réussite des cinq jobs avant fusion.
