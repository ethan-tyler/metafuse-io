# Deploying MetaFuse on Google Cloud Platform

This guide covers production deployment of MetaFuse on GCP using Google Cloud Storage as the catalog backend.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Authentication Setup](#authentication-setup)
- [Cloud Run Deployment](#cloud-run-deployment-serverless)
- [GKE Deployment](#gke-deployment-kubernetes)
- [Cost Estimation](#cost-estimation)
- [Best Practices](#best-practices)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### 1. GCP Project Setup

```bash
# Set your GCP project
export PROJECT_ID="your-project-id"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable storage-api.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable container.googleapis.com
```

### 2. Create GCS Bucket

```bash
# Create bucket for catalog storage
export BUCKET_NAME="metafuse-catalog-prod"
export REGION="us-central1"

gsutil mb -l $REGION gs://$BUCKET_NAME

# Enable versioning (recommended)
gsutil versioning set on gs://$BUCKET_NAME

# Set lifecycle policy to delete old versions after 30 days
cat > lifecycle.json <<EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {
          "numNewerVersions": 5,
          "isLive": false
        }
      }
    ]
  }
}
EOF
gsutil lifecycle set lifecycle.json gs://$BUCKET_NAME
```

### 3. Initialize Catalog

```bash
# Build with GCS support
cargo build --release --features gcs

# Initialize catalog in GCS
export METAFUSE_CATALOG_URI="gs://$BUCKET_NAME/catalog.db"
./target/release/metafuse init
```

---

## Authentication Setup

### Option 1: Service Account (Recommended for Production)

```bash
# Create service account
export SA_NAME="metafuse-sa"
export SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

gcloud iam service-accounts create $SA_NAME \
  --display-name="MetaFuse Catalog Service Account"

# Grant storage permissions
gsutil iam ch serviceAccount:$SA_EMAIL:objectAdmin gs://$BUCKET_NAME

# Create and download key
gcloud iam service-accounts keys create ~/metafuse-sa-key.json \
  --iam-account=$SA_EMAIL

# Set environment variable
export GOOGLE_APPLICATION_CREDENTIALS=~/metafuse-sa-key.json
```

### Option 2: Workload Identity (Recommended for GKE)

Workload Identity binds Kubernetes service accounts to GCP service accounts, eliminating the need for JSON keys.

```bash
# Enable Workload Identity on GKE cluster (see GKE section)
gcloud container clusters update CLUSTER_NAME \
  --workload-pool=$PROJECT_ID.svc.id.goog

# Create Kubernetes service account (see GKE section)
kubectl create serviceaccount metafuse-sa -n default

# Bind to GCP service account
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:$PROJECT_ID.svc.id.goog[default/metafuse-sa]"

# Annotate Kubernetes service account
kubectl annotate serviceaccount metafuse-sa \
  iam.gke.io/gcp-service-account=$SA_EMAIL
```

### IAM Permissions Required

Minimum permissions for the service account:

```yaml
# Custom role definition (minimal permissions)
title: "MetaFuse Catalog Access"
description: "Read and write catalog files in GCS"
includedPermissions:
- storage.objects.get
- storage.objects.create
- storage.objects.delete
- storage.objects.list
```

---

## Cloud Run Deployment (Serverless)

Cloud Run is ideal for the MetaFuse API server with automatic scaling and pay-per-use pricing.

### 1. Build Container Image

```dockerfile
# Dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --features gcs --bin metafuse-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/metafuse-api /usr/local/bin/
EXPOSE 8080
ENV RUST_LOG=info
CMD ["metafuse-api"]
```

```bash
# Build and push to Artifact Registry
export IMAGE_NAME="metafuse-api"
export IMAGE_TAG="v0.3.0"
export REPO_LOCATION="us-central1"
export REPO_NAME="metafuse"

# Create Artifact Registry repository
gcloud artifacts repositories create $REPO_NAME \
  --repository-format=docker \
  --location=$REPO_LOCATION

# Build and push
gcloud builds submit --tag $REPO_LOCATION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$IMAGE_NAME:$IMAGE_TAG
```

### 2. Deploy to Cloud Run

```bash
gcloud run deploy metafuse-api \
  --image=$REPO_LOCATION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$IMAGE_NAME:$IMAGE_TAG \
  --platform=managed \
  --region=$REGION \
  --service-account=$SA_EMAIL \
  --set-env-vars="METAFUSE_CATALOG_URI=gs://$BUCKET_NAME/catalog.db,METAFUSE_CACHE_TTL_SECS=60,RUST_LOG=info" \
  --allow-unauthenticated \
  --memory=512Mi \
  --cpu=1 \
  --concurrency=80 \
  --min-instances=0 \
  --max-instances=10
```

### 3. Configure Custom Domain (Optional)

```bash
# Map custom domain
gcloud run domain-mappings create --service=metafuse-api --domain=catalog.yourdomain.com --region=$REGION

# Follow DNS setup instructions
gcloud run domain-mappings describe --domain=catalog.yourdomain.com --region=$REGION
```

### 4. Test Deployment

```bash
# Get Cloud Run URL
export SERVICE_URL=$(gcloud run services describe metafuse-api --region=$REGION --format='value(status.url)')

# Health check
curl $SERVICE_URL/health

# List datasets
curl $SERVICE_URL/api/v1/datasets

# Search
curl "$SERVICE_URL/api/v1/search?q=revenue"
```

---

## GKE Deployment (Kubernetes)

GKE is suitable for workloads requiring persistent connections, custom scaling policies, or integration with existing Kubernetes infrastructure.

### 1. Create GKE Cluster

```bash
export CLUSTER_NAME="metafuse-cluster"
export CLUSTER_ZONE="us-central1-a"

gcloud container clusters create $CLUSTER_NAME \
  --zone=$CLUSTER_ZONE \
  --num-nodes=2 \
  --machine-type=e2-medium \
  --enable-autoscaling \
  --min-nodes=1 \
  --max-nodes=5 \
  --enable-autorepair \
  --enable-autoupgrade \
  --workload-pool=$PROJECT_ID.svc.id.goog \
  --addons=HorizontalPodAutoscaling,HttpLoadBalancing

# Get credentials
gcloud container clusters get-credentials $CLUSTER_NAME --zone=$CLUSTER_ZONE
```

### 2. Create Kubernetes Manifests

**ConfigMap** (config.yaml):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: metafuse-config
  namespace: default
data:
  METAFUSE_CATALOG_URI: "gs://metafuse-catalog-prod/catalog.db"
  METAFUSE_CACHE_TTL_SECS: "60"
  RUST_LOG: "info"
```

**Deployment** (deployment.yaml):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metafuse-api
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: metafuse-api
  template:
    metadata:
      labels:
        app: metafuse-api
    spec:
      serviceAccountName: metafuse-sa
      containers:
      - name: metafuse-api
        image: us-central1-docker.pkg.dev/PROJECT_ID/metafuse/metafuse-api:v0.3.0
        ports:
        - containerPort: 8080
          name: http
        envFrom:
        - configMapRef:
            name: metafuse-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: metafuse-api
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: metafuse-api
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
```

**HorizontalPodAutoscaler** (hpa.yaml):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: metafuse-api-hpa
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: metafuse-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### 3. Deploy to GKE

```bash
# Apply manifests
kubectl apply -f config.yaml
kubectl apply -f deployment.yaml
kubectl apply -f hpa.yaml

# Wait for deployment
kubectl rollout status deployment/metafuse-api

# Get external IP
kubectl get service metafuse-api

# Test
export LB_IP=$(kubectl get service metafuse-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
curl http://$LB_IP/health
```

### 4. Ingress with HTTPS (Optional)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: metafuse-ingress
  namespace: default
  annotations:
    kubernetes.io/ingress.class: "gce"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - catalog.yourdomain.com
    secretName: metafuse-tls
  rules:
  - host: catalog.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: metafuse-api
            port:
              number: 80
```

---

## Cost Estimation

### Cloud Run (Recommended for most workloads)

**Assumptions**: 1M API requests/month, avg 200ms execution time, 512MB memory

| Resource | Usage | Cost/Month |
|----------|-------|------------|
| Request charges | 1M requests | $0.40 |
| CPU time | 1M × 0.2s × $0.00002400/vCPU-sec | $4.80 |
| Memory | 1M × 0.2s × 0.5GB × $0.00000250/GB-sec | $0.25 |
| **Total Cloud Run** | | **$5.45** |
| GCS storage (10GB) | 10GB × $0.020/GB | $0.20 |
| GCS API calls | 100K Class A ops × $0.05/10K | $0.50 |
| **Total Monthly** | | **$6.15** |

### GKE (For high-traffic or persistent workloads)

**Assumptions**: 2 × e2-medium nodes (2 vCPU, 4GB RAM each)

| Resource | Usage | Cost/Month |
|----------|-------|------------|
| GKE cluster management | 1 zonal cluster | $74.40 |
| Compute (e2-medium) | 2 nodes × $24.27 | $48.54 |
| Load Balancer | 1 external LB | $18.26 |
| **Total GKE** | | **$141.20** |
| GCS (same as above) | | $0.70 |
| **Total Monthly** | | **$141.90** |

**Recommendation**: Start with Cloud Run unless you need:
- Persistent WebSocket connections
- Custom networking (VPC, private services)
- Integration with existing GKE workloads
- Sub-10ms latency requirements

---

## Best Practices

### Security

#### Core Security Hardening

1. **Use Workload Identity** instead of service account keys in GKE
2. **Restrict bucket access** to specific service accounts only
3. **Enable VPC Service Controls** for sensitive data
4. **Use Cloud Armor** for DDoS protection on public APIs
5. **Enable audit logging** for GCS access

```bash
# Enable audit logs
gcloud projects set-iam-policy $PROJECT_ID policy.yaml
```

#### Rate Limiting & API Key Authentication

**Build with security features**:

```bash
# Build with both rate limiting and API key authentication
docker build \
  --build-arg FEATURES="rate-limiting,api-keys" \
  -t gcr.io/$PROJECT_ID/metafuse-api:latest .

# Push to Google Container Registry
docker push gcr.io/$PROJECT_ID/metafuse-api:latest
```

**Configure trusted proxies for Cloud Load Balancing**:

```bash
# GCP Cloud Load Balancer uses specific IP ranges
# Set in Cloud Run or GKE deployment
env:
  - name: RATE_LIMIT_TRUSTED_PROXIES
    value: "130.211.0.0/22,35.191.0.0/16"
  - name: RATE_LIMIT_REQUESTS_PER_HOUR
    value: "5000"  # Authenticated clients
  - name: RATE_LIMIT_IP_REQUESTS_PER_HOUR
    value: "100"   # Unauthenticated clients
```

**Store API keys in Secret Manager**:

```bash
# Create API key using CLI (run once)
metafuse api-key create "production-api" > /tmp/key.txt

# Extract the key value
API_KEY=$(grep "API Key:" /tmp/key.txt | awk '{print $3}')

# Store in Secret Manager
echo -n "$API_KEY" | gcloud secrets create metafuse-api-key \
  --data-file=- \
  --replication-policy="automatic" \
  --project=$PROJECT_ID

# Clean up temporary file
rm -f /tmp/key.txt

# Grant access to service account
gcloud secrets add-iam-policy-binding metafuse-api-key \
  --member="serviceAccount:metafuse-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Retrieve in Cloud Run (automatic via volume mount)
# Or in GKE using Workload Identity and Secret Store CSI driver
```

**Cloud Run deployment with security**:

```bash
gcloud run deploy metafuse-api \
  --image gcr.io/$PROJECT_ID/metafuse-api:latest \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars RATE_LIMIT_TRUSTED_PROXIES="130.211.0.0/22,35.191.0.0/16" \
  --set-env-vars RATE_LIMIT_REQUESTS_PER_HOUR=5000 \
  --set-env-vars RATE_LIMIT_IP_REQUESTS_PER_HOUR=100 \
  --set-secrets="/etc/secrets/api-key=metafuse-api-key:latest" \
  --service-account metafuse-api@$PROJECT_ID.iam.gserviceaccount.com \
  --min-instances 1 \
  --max-instances 10 \
  --memory 512Mi \
  --cpu 1
```

**GKE deployment with security**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metafuse-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: metafuse-api
  template:
    metadata:
      labels:
        app: metafuse-api
    spec:
      serviceAccountName: metafuse-api
      containers:
      - name: metafuse-api
        image: gcr.io/PROJECT_ID/metafuse-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: RATE_LIMIT_TRUSTED_PROXIES
          value: "130.211.0.0/22,35.191.0.0/16"
        - name: RATE_LIMIT_REQUESTS_PER_HOUR
          value: "5000"
        - name: RATE_LIMIT_IP_REQUESTS_PER_HOUR
          value: "100"
        volumeMounts:
        - name: api-key
          mountPath: "/etc/secrets"
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          runAsNonRoot: true
          runAsUser: 1001
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
      volumes:
      - name: api-key
        secret:
          secretName: metafuse-api-key
---
apiVersion: v1
kind: Service
metadata:
  name: metafuse-api
spec:
  type: LoadBalancer
  selector:
    app: metafuse-api
  ports:
  - port: 443
    targetPort: 8080
    protocol: TCP
```

**IAM policy for least privilege**:

```bash
# Create service account
gcloud iam service-accounts create metafuse-api \
  --display-name="MetaFuse API Service Account"

# Grant GCS access
gcloud storage buckets add-iam-policy-binding gs://metafuse-catalog-prod \
  --member="serviceAccount:metafuse-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# Grant Secret Manager access
gcloud secrets add-iam-policy-binding metafuse-api-key \
  --member="serviceAccount:metafuse-api@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Bind Workload Identity (for GKE)
gcloud iam service-accounts add-iam-policy-binding \
  metafuse-api@$PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:$PROJECT_ID.svc.id.goog[default/metafuse-api]"
```

**Enable Cloud Armor for DDoS protection**:

```bash
# Create security policy
gcloud compute security-policies create metafuse-armor \
  --description "MetaFuse API protection"

# Add rate limiting rule
gcloud compute security-policies rules create 1000 \
  --security-policy metafuse-armor \
  --expression "true" \
  --action "rate-based-ban" \
  --rate-limit-threshold-count 100 \
  --rate-limit-threshold-interval-sec 60 \
  --ban-duration-sec 600 \
  --conform-action allow \
  --exceed-action deny-429 \
  --enforce-on-key IP

# Add geo-blocking (example: allow only US traffic)
gcloud compute security-policies rules create 2000 \
  --security-policy metafuse-armor \
  --expression "origin.region_code != 'US'" \
  --action deny-403

# Attach to backend service
gcloud compute backend-services update metafuse-backend \
  --security-policy metafuse-armor \
  --global
```

**Security monitoring with Cloud Monitoring**:

```bash
# Create alert for rate limit violations
gcloud alpha monitoring policies create \
  --notification-channels=$CHANNEL_ID \
  --display-name="MetaFuse Rate Limit Exceeded" \
  --condition-display-name="429 Response Rate >5%" \
  --condition-threshold-value=5 \
  --condition-threshold-duration=300s \
  --condition-filter='
    resource.type="cloud_run_revision"
    AND resource.labels.service_name="metafuse-api"
    AND metric.type="run.googleapis.com/request_count"
    AND metric.labels.response_code_class="4xx"'

# Create alert for authentication failures
gcloud alpha monitoring policies create \
  --notification-channels=$CHANNEL_ID \
  --display-name="MetaFuse Auth Failures" \
  --condition-display-name="401 Response Rate >1%" \
  --condition-threshold-value=1 \
  --condition-threshold-duration=300s \
  --condition-filter='
    resource.type="cloud_run_revision"
    AND resource.labels.service_name="metafuse-api"
    AND metric.type="run.googleapis.com/request_count"
    AND metric.labels.response_code="401"'
```

**HTTPS/TLS configuration**:

```bash
# Cloud Run automatically provides HTTPS
# For GKE with Ingress:

cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: metafuse-ingress
  annotations:
    kubernetes.io/ingress.class: "gce"
    networking.gke.io/managed-certificates: "metafuse-cert"
    kubernetes.io/ingress.allow-http: "false"
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /*
        pathType: ImplementationSpecific
        backend:
          service:
            name: metafuse-api
            port:
              number: 443
---
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: metafuse-cert
spec:
  domains:
  - api.example.com
EOF
```

**For complete security guidance, see**:

- [docs/SECURITY.md](../SECURITY.md) - Comprehensive security guide
- [docs/security-checklist.md](../security-checklist.md) - Pre-deployment checklist
- [.github/SECURITY.md](../.github/SECURITY.md) - Vulnerability reporting

### Reliability

1. **Enable GCS versioning** to recover from accidental overwrites
2. **Use health checks** with proper liveness/readiness probes
3. **Set resource limits** to prevent OOM kills
4. **Configure retry policies** for transient failures
5. **Use multiple regions** for disaster recovery

### Performance

1. **Co-locate services** in the same region as the GCS bucket
2. **Enable caching** with `METAFUSE_CACHE_TTL_SECS=60`
3. **Use GCS nearline storage** for archival catalogs
4. **Tune concurrency** based on workload patterns
5. **Monitor cache hit rates** and adjust TTL accordingly

### Operations

1. **Use structured logging** with `RUST_LOG=info,metafuse_catalog_storage=debug`
2. **Set up Cloud Monitoring alerts** for error rates
3. **Export logs to BigQuery** for analysis
4. **Use Cloud Trace** for request latency insights
5. **Automate deployments** with Cloud Build triggers

---

## Monitoring

### Cloud Monitoring Dashboards

```bash
# Create uptime check
gcloud monitoring uptime-checks create metafuse-health \
  --resource-type=uptime-url \
  --host=$SERVICE_URL \
  --path=/health

# Create alert policy for errors
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="MetaFuse Error Rate" \
  --condition-display-name="Error rate > 5%" \
  --condition-threshold-value=5 \
  --condition-threshold-duration=60s
```

### Key Metrics to Monitor

| Metric | Threshold | Action |
|--------|-----------|--------|
| Request latency (p99) | > 2s | Increase cache TTL, scale up |
| Error rate | > 1% | Check logs, GCS connectivity |
| Cache hit rate | < 70% | Increase TTL or cache size |
| GCS API quota | > 80% | Request quota increase |
| Memory usage | > 90% | Increase memory limits |

### Logging Best Practices

```bash
# View logs in Cloud Logging
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=metafuse-api" --limit=50 --format=json

# Filter for errors
gcloud logging read "resource.type=cloud_run_revision AND severity>=ERROR" --limit=10

# Export logs to BigQuery
gcloud logging sinks create metafuse-logs-export \
  bigquery.googleapis.com/projects/$PROJECT_ID/datasets/metafuse_logs \
  --log-filter='resource.type="cloud_run_revision"'
```

---

## Troubleshooting

### Issue: Authentication Failures

**Symptoms**: `Failed to create GCS client. Check GOOGLE_APPLICATION_CREDENTIALS`

**Solutions**:
1. Verify service account has `storage.objectAdmin` on the bucket
2. Check `GOOGLE_APPLICATION_CREDENTIALS` points to valid JSON key
3. Ensure service account key is not expired
4. For Workload Identity, verify annotation on Kubernetes service account

```bash
# Debug authentication
gcloud auth application-default print-access-token
gsutil ls gs://$BUCKET_NAME  # Test bucket access
```

### Issue: Precondition Failed (409 Conflict)

**Symptoms**: `ConflictError: concurrent modification detected`

**Solutions**:
1. Reduce concurrent writers (optimistic locking supports single writer)
2. Increase retry delays in application code
3. Check for clock skew between clients

### Issue: High Cache Miss Rate

**Symptoms**: Slow reads, high GCS API costs

**Solutions**:
1. Increase `METAFUSE_CACHE_TTL_SECS` (default: 60)
2. Check cache directory exists: `~/.cache/metafuse`
3. Verify disk space for cache storage
4. Monitor cache eviction logs

```bash
# Check cache usage
du -sh ~/.cache/metafuse
```

### Issue: Cold Start Latency

**Symptoms**: First request after idle period is slow (Cloud Run)

**Solutions**:
1. Set `--min-instances=1` to keep warm instance
2. Use Cloud Scheduler to ping `/health` every 5 minutes
3. Reduce image size (multi-stage Dockerfile)
4. Use startup probes instead of liveness probes

---

## Next Steps

- [AWS Deployment Guide](deployment-aws.md) - Deploy on AWS with S3
- [Authentication Guide](auth-gcp.md) - Advanced GCP authentication
- [Migration Guide](migration-local-to-cloud.md) - Migrate from local to GCS
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions

---

**Last Updated**: 2025-01-21
