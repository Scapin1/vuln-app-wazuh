# GitHub Actions (CI/CD)

Este repositorio usa GitHub Actions para:

- **CI**: tests + cobertura (backend y frontend) + análisis con **SonarQube Cloud (SonarCloud)**
- **DAST**: escaneo con **OWASP ZAP** (nightly / manual) usando Docker Compose

## 1) Variables y Secrets requeridos

En GitHub: **Settings → Secrets and variables → Actions**

### Variables (Repository variables)

- `SONAR_ORGANIZATION`: *organization key* de SonarQube Cloud
- `SONAR_PROJECT_KEY`: *project key* en SonarQube Cloud

### Secrets (Repository secrets)

- `SONAR_TOKEN`: token de SonarQube Cloud

## 2) ¿Qué es el “organization key”?

Es el identificador de tu organización en SonarQube Cloud. No es el nombre visible, es el *key/slug*.
Lo vas a ver al crear la organización o en la URL dentro de SonarQube Cloud.

## 3) Workflows

- `.github/workflows/ci.yml`
  - Corre en PRs y push a `main`.
  - Backend: `pytest` + `coverage.xml`.
  - Frontend: `vitest run --coverage` (genera `frontend/coverage/lcov.info`).
  - Sonar: ejecuta scan y luego Quality Gate.

- `.github/workflows/zap.yml`
  - Corre **nightly** (cron) y **manual** (`workflow_dispatch`).
  - Levanta el stack con `docker compose up -d --build`.
  - Ejecuta `dev-tools/jenkins/scripts/run_zap.sh`.
  - Publica reportes HTML como artifacts del workflow.

## 4) Cómo probarlo

1. Subí estos cambios al repo (push a una rama y PR).
2. Configurá `SONAR_ORGANIZATION`, `SONAR_PROJECT_KEY` y `SONAR_TOKEN`.
3. Abrí un PR: debería correr **CI (tests + Sonar)** automáticamente.
4. Para ZAP: GitHub → pestaña **Actions** → workflow **DAST (OWASP ZAP)** → **Run workflow**.
