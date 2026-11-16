# Deploying Plumbline to Cloud Run

This is the one-time setup, then every push to `main` that passes CI deploys
automatically (`.github/workflows/deploy.yml`). Run the commands from your own
machine with `gcloud` logged in as a project owner.

> **Single-instance demo.** The job queue and SQLite live inside one Cloud Run
> instance (`--max-instances=1`). Data is on the in-memory filesystem and resets
> when the instance stops; the simulated tenant re-seeds itself at startup.

## 0. Variables

```bash
export PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"
export GH_REPO="Rahul03082001/plumbline-sspm"      # owner/repo that may deploy
export SCAN_ORG="plumbline-demo-org"               # the GitHub org to scan
export PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
export RUNTIME_SA="plumbline-runtime@${PROJECT_ID}.iam.gserviceaccount.com"
export DEPLOYER_SA="plumbline-deployer@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud config set project "$PROJECT_ID"
```

## 1. Enable APIs

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com
```

## 2. Artifact Registry repository

```bash
gcloud artifacts repositories create plumbline \
  --repository-format=docker \
  --location="$REGION" \
  --description="Plumbline container images"
```

## 3. Secret for the GitHub token

Create the fine-grained, read-only token first (see `docs/permissions.md`).
`read -s` keeps the token out of your shell history and off the screen.

```bash
read -rs GH_PAT && printf '%s' "$GH_PAT" | gcloud secrets create plumbline-github-token \
  --replication-policy=automatic --data-file=- && unset GH_PAT
```

## 4. Runtime service account (what the app runs as)

It can read exactly one secret and nothing else.

```bash
gcloud iam service-accounts create plumbline-runtime \
  --display-name="Plumbline Cloud Run runtime"

gcloud secrets add-iam-policy-binding plumbline-github-token \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role=roles/secretmanager.secretAccessor
```

## 5. Deployer service account (what GitHub Actions acts as)

```bash
gcloud iam service-accounts create plumbline-deployer \
  --display-name="Plumbline GitHub Actions deployer"

# Deploy Cloud Run revisions (not change who can invoke them).
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${DEPLOYER_SA}" --role=roles/run.developer

# Push images to this one repository only.
gcloud artifacts repositories add-iam-policy-binding plumbline \
  --location="$REGION" \
  --member="serviceAccount:${DEPLOYER_SA}" --role=roles/artifactregistry.writer

# Allow the deployer to start the service *as* the runtime account.
gcloud iam service-accounts add-iam-policy-binding "$RUNTIME_SA" \
  --member="serviceAccount:${DEPLOYER_SA}" --role=roles/iam.serviceAccountUser
```

## 6. Workload Identity Federation (bound to this repo's `main` only)

```bash
gcloud iam workload-identity-pools create github \
  --location=global --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc plumbline-repo \
  --location=global \
  --workload-identity-pool=github \
  --display-name="plumbline-sspm repo" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition="assertion.repository == '${GH_REPO}' && assertion.ref == 'refs/heads/main'"

# Only identities from that repo may impersonate the deployer.
gcloud iam service-accounts add-iam-policy-binding "$DEPLOYER_SA" \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/attribute.repository/${GH_REPO}"
```

## 7. GitHub repository variables

None of these are secrets. (Variable names can't start with `GITHUB_`, hence
`PLUMBLINE_GITHUB_ORG`.)

```bash
gh variable set GCP_PROJECT_ID --body "$PROJECT_ID"
gh variable set GCP_REGION --body "$REGION"
gh variable set WIF_PROVIDER --body "projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/providers/plumbline-repo"
gh variable set DEPLOYER_SA --body "$DEPLOYER_SA"
gh variable set RUNTIME_SA --body "$RUNTIME_SA"
gh variable set PLUMBLINE_GITHUB_ORG --body "$SCAN_ORG"
```

Also create a `production` environment in the repo (Settings → Environments);
the deploy job uses it, so you can add a required reviewer later.

## 8. First deploy, then make it public

Push to `main` (or run the Deploy workflow by hand). The deployer can't change
who may invoke the service (least privilege), so open it to the public once:

```bash
gcloud run services add-iam-policy-binding plumbline \
  --region="$REGION" --member=allUsers --role=roles/run.invoker
gcloud run services describe plumbline --region="$REGION" --format='value(status.url)'
```

## 9. Budget alert ($5)

```bash
gcloud services enable billingbudgets.googleapis.com
gcloud billing budgets create \
  --billing-account="$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingAccountName)' | sed 's|billingAccounts/||')" \
  --display-name="plumbline" --budget-amount=5USD \
  --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0
```

A budget alert only **emails** you; it does not stop spending. The real limits
are `--max-instances=1`, `--min-instances=0`, and the per-IP rate limit.

## 10. Measure (for the README and interviews)

```bash
# Image size
gcloud artifacts docker images list "${REGION}-docker.pkg.dev/${PROJECT_ID}/plumbline/plumbline" \
  --include-tags --format='table(tags,metadata.imageSizeBytes)'
# Cold start: wait ~15 min idle, then
URL="$(gcloud run services describe plumbline --region="$REGION" --format='value(status.url)')"
curl -s -o /dev/null -w 'cold: %{time_total}s\n' "$URL/healthz"
curl -s -o /dev/null -w 'warm: %{time_total}s\n' "$URL/healthz"
# Scan duration histogram (p50 from the buckets)
curl -s "$URL/metrics" | grep plumbline_scan_duration_seconds
# Direct dependencies
go list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all | tail -n +2 | grep -c .
```

## Verify the client-IP setting

`TRUSTED_PROXY_HOPS=1` makes the rate limiter use the right-most
`X-Forwarded-For` entry. After deploying, run 6 scan POSTs quickly from your
machine: the 6th must get 429. Then send one with a fake header
(`-H 'X-Forwarded-For: 1.2.3.4'`): it must **still** be limited. If every visitor
is limited together, the hop count is too high; it can never be bypassed.
