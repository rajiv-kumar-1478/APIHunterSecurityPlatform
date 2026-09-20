# Render Deployment Guide for APIHunter Security Platform

This guide outlines how to deploy the entire **APIHunter Security Platform** to [Render](https://render.com) using the included `render.yaml` Blueprint specification.

---

## 1. Prerequisites

1. A [Render account](https://dashboard.render.com).
2. The Git repository pushed to GitHub or GitLab.

---

## 2. Architecture on Render

The deployment provisions 4 components in Render:

| Component | Render Service Type | Source / Runtime | Description |
|---|---|---|---|
| **Database** | Managed PostgreSQL (`apihunter-postgres`) | PostgreSQL 16 | Stores security findings, credentials, audit events, users, and AI routing configurations. |
| **Backend API** | Web Service (`apihunter-api`) | Docker (`Dockerfile.api`) | ASP.NET Core REST API serving authentication, triage, AI orchestration, and audit logs. |
| **Worker Engine** | Background Worker (`apihunter-worker`) | Docker (`Dockerfile.worker`) | Background worker processing repository acquisitions, triage sweep, and AI analysis. |
| **Frontend UI** | Web Service (`apihunter-frontend`) | Node.js (Next.js 16) | Next.js Dashboard with interactive security remediation, AI settings, and credentials views. |

---

## 3. Fast Deployment via Render Blueprint (Recommended)

1. Navigate to the **[Render Dashboard](https://dashboard.render.com)**.
2. Click **New +** in the top right and select **Blueprint**.
3. Connect your Git repository (`APIHunterSecurityPlatform`).
4. Render will detect the root `render.yaml` file automatically.
5. Review the resources to be created:
   - `apihunter-postgres` (PostgreSQL)
   - `apihunter-api` (Web Service)
   - `apihunter-worker` (Background Worker)
   - `apihunter-frontend` (Web Service)
6. Click **Apply**.
7. Render will automatically:
   - Provision the PostgreSQL database.
   - Build and deploy the API container.
   - Generate secure 256-bit cryptographic encryption keys (`Security__MasterEncryptionKey` and `Authentication__JwtSecret`).
   - Wire the frontend to the backend URL.

---

## 4. Manual Configuration (Alternative)

If deploying services individually without Blueprints:

### Step A: PostgreSQL
- Click **New +** $\to$ **PostgreSQL**.
- Name: `apihunter-postgres`
- Database: `platform_db`
- User: `platform`
- Copy the **Internal Database URL** for the API and Worker.

### Step B: Backend API
- Click **New +** $\to$ **Web Service**.
- Select repo, choose **Docker**.
- Dockerfile Path: `deployment/docker/Dockerfile.api`
- Docker Context: `.`
- Health Check Path: `/api/v1/health/ready`
- Environment Variables:
  - `ASPNETCORE_ENVIRONMENT`: `Production`
  - `Database__ConnectionString`: (paste Internal Database URL)
  - `Security__MasterEncryptionKey`: (generate a 32+ character random secret)
  - `Authentication__JwtSecret`: (generate a 32+ character random secret)
  - `Tenant__Id`: `00000000-0000-0000-0000-000000000001`
  - `Seed__AdminEmail`: `admin@yourdomain.com`
  - `Seed__AdminPassword`: `YourStrongAdminPassword123!`
  - `Cors__AllowedOrigins__0`: `https://<your-frontend-url>.onrender.com`

### Step C: Background Worker
- Click **New +** $\to$ **Background Worker**.
- Dockerfile Path: `deployment/docker/Dockerfile.worker`
- Docker Context: `.`
- Environment Variables:
  - `DOTNET_ENVIRONMENT`: `Production`
  - `Database__ConnectionString`: (same internal PostgreSQL URL)
  - `Security__MasterEncryptionKey`: (same master key as API)
  - `Tenant__Id`: `00000000-0000-0000-0000-000000000001`

### Step D: Frontend Dashboard
- Click **New +** $\to$ **Web Service**.
- Root Directory: `frontend/dashboard`
- Runtime: **Node**
- Build Command: `npm install && npm run build`
- Start Command: `npm start`
- Environment Variables:
  - `NEXT_PUBLIC_API_URL`: `https://<your-api-url>.onrender.com`

---

## 5. Post-Deployment Verification

1. Check API Health:
   ```bash
   curl https://<your-api-url>.onrender.com/api/v1/health/ready
   ```
   Should return `HTTP 200` with `status: "Healthy"`.

2. Log In to Dashboard:
   - Visit `https://<your-frontend-url>.onrender.com`.
   - Log in using `admin@apihunter.local` (or the `Seed__AdminEmail` you specified) and the admin password shown in the API service logs.
