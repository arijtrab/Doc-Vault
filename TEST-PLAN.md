# Plan de tests — DocVault Lab (DV-01 à DV-11)

Cible : stack Compose locale, entrée unique `http://127.0.0.1:8080` (l'API n'est jamais publiée).
Comptes jetables : Alice (propriétaire) et Bob (`role: user`). Données synthétiques uniquement.

Chaque test est rejoué **avant** correction (résultat « vulnérable ») puis **après** correction (résultat « corrigé »). Conserver la sortie de chaque commande comme preuve.

## Préparation (bash / Git Bash)

```bash
A=http://127.0.0.1:8080/api/v1
reg(){ curl -s -X POST $A/auth/register -H 'Content-Type: application/json' \
  -d "{\"name\":\"$1\",\"email\":\"$2\",\"password\":\"LabPass123!\"}"; }
reg Alice alice.lab@example.test   # noter le champ token -> TA
reg Bob   bob.lab@example.test     # noter le champ token -> TB
# Alice téléverse un document Restricted
curl -s -X POST $A/documents -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' \
  -d "{\"title\":\"TestIDOR\",\"originalFileName\":\"a.txt\",\"fileType\":\"txt\",\"fileSizeBytes\":8,\"sensitivity\":\"Restricted\",\"category\":\"Operations\",\"fileContentBase64\":\"$(printf TestIDOR | base64)\"}"
# noter le champ id -> DOC
```

## Tests

| ID | Commande | Vulnérable | Corrigé |
|---|---|---|---|
| DV-01 | `curl -s -X POST $A/auth/login -H 'Content-Type: application/json' -d '{"email":"bob.lab@example.test","password":"faux"}'` | `200` + `token` | `401` |
| DV-02 lecture | `curl -s -o /dev/null -w '%{http_code}' $A/documents/$DOC -H "Authorization: Bearer $TB"` (idem `/preview` en GET, `/download` en POST) | `200` | `403` |
| DV-02 écriture | `curl -s -w ' %{http_code}' -X PATCH $A/documents/$DOC -H "Authorization: Bearer $TB" -H 'Content-Type: application/json' -d '{"title":"Modifie par Bob"}'` | `200`, titre modifié | `403` |
| DV-03 | `curl -s -o /dev/null -w '%{http_code}' $A/admin/users -H "Authorization: Bearer $TB"` | `200` + liste | `403` |
| DV-04 | `for i in $(seq 12); do curl -s -o /dev/null -w '%{http_code} ' -X POST $A/auth/login -H 'Content-Type: application/json' -d '{"email":"inconnu@example.test","password":"x"}'; done` | 12 × `401` | `429` après le seuil |
| DV-05 | `sqlite3` sur une copie de la base : `SELECT CAST(ciphertext AS TEXT), encryption_version, key_version FROM document_blobs WHERE document_id='$DOC';` | `TestIDOR`, `0`, `plaintext-lab` | octets illisibles, version > 0 |
| DV-06 | `curl -s -G $A/documents --data-urlencode "query=' OR 1=1 --" -H "Authorization: Bearer $TB"` | tous les documents | aucun résultat / filtre normal |
| DV-07 | créer un document au titre `<img src=x onerror=alert(1)>`, ouvrir *My Documents* | alerte `1` | titre affiché comme texte |
| DV-08 | téléverser `notepad.exe` depuis l'interface | accepté | refusé (`400`) |
| DV-09 | `curl -s -i $A/documents -H 'Origin: https://example.invalid' -H "Authorization: Bearer $TB" \| grep -i access-control` | origine reflétée + `credentials: true` | pas d'en-tête pour cette origine |
| DV-10 | `curl -s -i http://127.0.0.1:8080/api/health` | pas de `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` | en-têtes présents |
| DV-11 | `curl -s -o /dev/null -X POST $A/documents/$DOC/download -H "Authorization: Bearer $TB" -H 'X-Forwarded-For: 203.0.113.66'` puis `curl -s $A/admin/audit-logs -H "Authorization: Bearer $TA" \| grep 203.0.113.66` | IP `203.0.113.66` enregistrée | IP réelle du client |

## Contrôles conteneur (exigence 4.1)

| Contrôle | Commande | Attendu |
|---|---|---|
| Utilisateur déclaré | `docker image inspect --format '{{.Config.User}}' <image>` | `65532:65532` / `101` |
| Processus réels | `docker top <conteneur> -eo pid,uid,gid,cmd` | UID non nul |
| Scan configuration | `trivy config --severity HIGH,CRITICAL .` | aucune alerte root |
| Scan secrets | `trivy image --scanners secret --image-config-scanners secret <image>` | aucune détection |
| Scan vulnérabilités | `trivy image --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 <image>` | code de sortie `0` |
| Pas de `.git` / `.env` | `docker export <conteneur> \| tar -t \| grep -E '(^\|/)\.(git\|env)'` | aucune ligne |
