# 4.3 — Pipeline de sécurité avant déploiement

**Date :** 27 novembre 2026 · **Dépôt :** `arijtrab/Doc-Vault` (GitHub) · **Pipeline :** `.github/workflows/ci.yml` (GitHub Actions)
**Politique de blocage complète :** `SECURITY-POLICY.md`

## 1. Architecture du pipeline

Le pipeline se déclenche sur chaque pull request et sur chaque push vers `main`. Il exécute en parallèle six vérifications indépendantes, qui couvrent les cinq contrôles demandés :

| # | Contrôle | Job | Outil (version épinglée) | Rapport conservé |
|---|---|---|---|---|
| 1 | Détection de secrets, avec caviardage | `Secrets (Gitleaks)` | Gitleaks `v8.30.1` | `gitleaks-report` (JSON) |
| 2 | Analyse statique du code (SAST) | `SAST (Semgrep)` | Semgrep `1.186.0` | `semgrep-report` (JSON) |
| 3 | Analyse des dépendances | `Dépendances (Trivy fs)` | Trivy `0.76.2` | `trivy-deps-report` |
| 4 | Analyse des fichiers de déploiement (IaC) | `IaC (Trivy config)` | Trivy `0.76.2` | `trivy-iac-report` |
| 5 | Analyse des images | `Images (Trivy image) (backend)` et `(frontend)` | Trivy `0.76.2` | `trivy-image-*-report` |

**Choix de conception :**

- **Versions épinglées.** Les trois outils sont fixés à une version précise, pour que deux exécutions sur le même code donnent le même verdict. Une version `latest` peut changer de règles d'un jour à l'autre sans modification du dépôt.
- **Rapports conservés.** Chaque job dépose son rapport comme artefact, même en cas d'échec (`if: always()`), pour garder la trace de ce qui a bloqué.
- **Échec réel du build.** Chaque outil est lancé avec un code de sortie non nul en cas de résultat au-dessus du seuil (`--exit-code 1`, `--error`). Les commandes Trivy sont exécutées avec `shell: bash` (option `pipefail`), pour que le `tee` vers le rapport ne masque pas l'échec.
- **Moindre privilège.** Le workflow n'a que la permission `contents: read`, et `persist-credentials: false` empêche le jeton GitHub de rester dans le dépôt cloné.
- **Images analysées telles que construites.** Le job d'images reconstruit chaque image à partir de son Dockerfile, puis l'analyse : on vérifie ce qui sera déployé, pas une image ancienne.
- **Un seul run par pull request.** Le push ne déclenche le pipeline que sur `main` ; sur les autres branches, seul l'événement `pull_request` le lance. Cela évite d'exécuter chaque contrôle deux fois.

## 2. Seuils de blocage et justification

| Contrôle | Le build échoue si… | Justification |
|---|---|---|
| Secrets | au moins un secret, quelle que soit sa nature | Un secret poussé est compromis dès le push ; seule la révocation le neutralise. Les valeurs sont caviardées (`--redact`) dans les journaux et le rapport. |
| SAST | au moins un résultat de sévérité **ERROR** | Les règles ERROR sont celles à forte confiance (injection, XSS, CORS permissif). WARNING et INFO produisent trop de faux positifs pour bloquer sans revue humaine. |
| Dépendances et images | CVE **HIGH ou CRITICAL** avec **correctif disponible** | Une CVE corrigible se règle par une mise à jour : la bloquer ne paralyse pas l'équipe. Une CVE sans correctif bloquerait sans action possible ; elle est suivie par un scan hebdomadaire complet. |
| IaC | mauvaise configuration **HIGH ou CRITICAL** | Couvre l'exécution en root, les secrets dans les build-args et les privilèges excessifs, que 4.1 et 4.5 interdisent. |

**Pourquoi HIGH et pas seulement CRITICAL.** Le 27/11/2026, l'image frontend contenait 6 CVE **HIGH** dans `libxml2`, dont plusieurs permettent une exécution de code arbitraire (voir § 4). Un seuil limité à CRITICAL les aurait laissées passer.

**Pourquoi seulement ERROR pour le SAST.** Sur les 199 règles chargées, `--severity ERROR` en garde 33 pour le code du projet. Ce seuil limite le bruit, au prix de laisser passer des constats WARNING, qui restent consultables dans le rapport.

**Exceptions.** Une exception exige : l'absence de correctif applicable, une analyse de risque écrite, l'approbation de deux membres et une date d'expiration inscrite dans le mécanisme lui-même (`.trivyignore` avec `exp:`, `// nosemgrep` daté). Aucune exception n'est admise pour un vrai secret. Les échéances maximales sont de 7 jours pour un CRITICAL et 30 jours pour un HIGH.

## 3. Le pipeline bloque réellement : preuves

### 3.1 Fonctionnement de référence (`main`, run #15, commit `49c78e3`)

| Job | Résultat | Explication |
|---|---|---|
| Secrets (Gitleaks) | ✅ | Aucun secret dans l'historique de `main` |
| SAST (Semgrep) | ❌ | Failles volontaires DV-06, DV-07, DV-09 (§ 3.4) |
| Dépendances (Trivy fs) | ✅ | 0 CVE HIGH/CRITICAL corrigible |
| IaC (Trivy config) | ✅ | 0 mauvaise configuration HIGH/CRITICAL |
| Images backend / frontend | ✅ / ✅ | 0 CVE HIGH/CRITICAL corrigible, 0 secret |

### 3.2 Un secret poussé fait échouer le pipeline (PR #2, branche `demo/secret`)

- **Démonstration :** un faux identifiant AWS (`AKIA…`, valeur inventée) est ajouté dans `backend/demo-secret.ts`.
- **Résultat :** le job Secrets échoue (run #8 : `leaks found: 1`, code de sortie 1).
- **Caviardage :** le rapport contient `"RuleID": "aws-access-token"`, `"File": "backend/demo-secret.ts"`, `"StartLine": 2`, `"Commit": "b019234…"`, mais `"Secret": "REDACTED"` et `"Match": "REDACTED"`. La valeur n'apparaît ni dans les journaux ni dans le rapport.
- **Suite :** la PR a été fermée sans fusion.

### 3.3 Une vulnérabilité critique fait échouer le pipeline (branche `demo/vuln-dep`, commit `8509989`)

- **Démonstration :** la dépendance `minimist` est fixée à la version vulnérable `1.2.5`.
- **Résultat :** le job Dépendances échoue.

```
package-lock.json (npm)
Total: 1 (HIGH: 0, CRITICAL: 1)
│ minimist │ CVE-2021-44906 │ CRITICAL │ fixed │ 1.2.5 │ 1.2.6, 0.2.4 │ minimist: prototype pollution │
```

- **Suite :** la PR a été fermée sans fusion.

### 3.4 Le SAST détecte trois failles du laboratoire

Semgrep (run #18) a analysé 42 fichiers et exécuté 33 règles ; il a trouvé 4 résultats bloquants.

| Règle | Emplacement | Faille |
|---|---|---|
| `docvault-cors-reflects-any-origin` | `backend/index.ts:18` | DV-09 — A02:2025 |
| `docvault-sql-injection-better-sqlite3` | `backend/routes/documents.ts:141` | DV-06 — A05:2025 |
| `docvault-react-dangerously-set-inner-html` | `MyDocumentsPage.tsx:422` et `:584` | DV-07 — A05:2025 |

**Constat important :** les 4 résultats proviennent des 3 règles écrites par l'équipe (`semgrep-rules/docvault.yml`). Les 196 règles publiques (`p/owasp-top-ten`, `p/security-audit`) n'ont rien trouvé au niveau ERROR. Sans règles adaptées au code (`better-sqlite3`, rendu React), ces trois failles seraient passées.

### 3.5 La fusion est bloquée tant qu'un contrôle échoue

Le ruleset GitHub `protect-main` est actif sur `main` :
- pull request obligatoire ;
- 6 vérifications marquées **Required** ;
- force-push interdit.

Sur la PR `demo/vuln-dep`, le bouton « Merge pull request » est grisé, car les vérifications Dépendances et SAST échouent. Sans ce ruleset, un pipeline rouge n'aurait été qu'un avertissement.

## 4. Cas réel : blocage de l'image frontend (27/11/2026)

1. **Blocage.** Le scan de l'image frontend a échoué sur 6 CVE HIGH corrigibles dans `libxml2 2.13.9-r3` (`CVE-2026-11979`, `CVE-2026-86138`, `CVE-2026-86139`, `CVE-2026-86140`, `CVE-2026-86142`, `CVE-2026-86143`), corrigées en `2.13.9-r5`.
2. **Cause.** L'image de base épinglée `nginx-unprivileged:1.30.8-alpine3.24` contenait déjà ces CVE, et l'éditeur ne l'avait pas encore republiée (même digest après `docker pull`).
3. **Exception documentée.** `Dockerfile.frontend` met à jour ce seul paquet (`apk upgrade --no-cache libxml2`). Le passage en `root` est limité à la construction ; l'image s'exécute toujours sous `USER 101`, et le contrôle `DS-0002` reste en PASS.
4. **Échéance.** Retirer cette ligne et épingler le nouveau digest dès la publication de l'image corrigée, au plus tard le 27/12/2026.
5. **Résultat.** Après reconstruction, l'image frontend présente 0 CVE HIGH/CRITICAL corrigible, avec un code de sortie 0.

Ce cas montre aussi qu'un résultat propre est daté : l'image était conforme le 25/11 et ne l'était plus le 27/11, sans aucune modification du code.

## 5. Limites et réflexion critique

- **Le SAST ne voit pas la logique.** Les failles DV-01 à DV-04 et DV-11 (mot de passe non vérifié, autorisation absente, rôle forcé, journal falsifiable) ne sont détectées par aucun contrôle statique. Elles relèvent des tests dynamiques (4.6) et des tests de non-régression (`TEST-PLAN.md`).
- **Les règles publiques ne suffisent pas.** Les trois failles détectées l'ont été par des règles écrites pour ce code. La qualité du SAST dépend de l'effort investi dans les règles.
- **Gitleaks ne connaît que des formats.** Un premier faux secret, au format invalide, n'a pas été détecté par la version récente de Gitleaks ; il a fallu une clé au format AWS valide. Un mot de passe « maison » passerait.
- **Le périmètre de Gitleaks est un choix.** Sans `--log-opts=HEAD`, Gitleaks analysait toutes les branches récupérées, y compris `demo/secret`, et échouait sur toutes les pull requests. Le périmètre retenu est l'historique accessible depuis le commit testé.
- **Deux fichiers de verrouillage.** Le dépôt contient `package-lock.json` et `bun.lock`. La démonstration `minimist` n'a modifié que le premier ; le second est resté propre. Les images sont construites avec `npm ci`, mais deux fichiers peuvent diverger sans alerte.
- **Le blocage a un coût.** Avec le ruleset actif, la présence de DV-06, DV-07 et DV-09 sur `main` empêche toute fusion : leurs corrections doivent être livrées ensemble, dans une seule pull request.
- **Un pipeline vert n'est pas une preuve d'absence de faille.** Il signifie seulement « aucun résultat au-dessus des seuils, avec ces règles, à cette date ».
- **Les actions GitHub ne sont pas épinglées par empreinte.** `actions/checkout@v4` et `actions/upload-artifact@v4` sont référencées par étiquette. Une étiquette peut être déplacée ; les épingler par SHA de commit renforcerait la chaîne d'approvisionnement (A03:2025).
