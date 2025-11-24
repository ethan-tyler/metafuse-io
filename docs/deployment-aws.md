# Deploying MetaFuse on Amazon Web Services

This guide covers production deployment of MetaFuse on AWS using Amazon S3 as the catalog backend.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Authentication Setup](#authentication-setup)
- [ECS Deployment](#ecs-deployment-fargate)
- [EKS Deployment](#eks-deployment-kubernetes)
- [Lambda Deployment](#lambda-deployment-serverless)
- [Cost Estimation](#cost-estimation)
- [Best Practices](#best-practices)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### 1. AWS Account Setup

```bash
# Configure AWS CLI
aws configure
# Enter: Access Key ID, Secret Access Key, Region (e.g., us-east-1)

# Set environment variables
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### 2. Create S3 Bucket

```bash
# Create bucket for catalog storage
export BUCKET_NAME="metafuse-catalog-prod"

aws s3 mb s3://$BUCKET_NAME --region $AWS_REGION

# Enable versioning (recommended)
aws s3api put-bucket-versioning \
  --bucket $BUCKET_NAME \
  --versioning-configuration Status=Enabled

# Set lifecycle policy to delete old versions after 30 days
cat > lifecycle-policy.json <<EOF
{
  "Rules": [
    {
      "Id": "DeleteOldVersions",
      "Status": "Enabled",
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 30
      }
    }
  ]
}
EOF
aws s3api put-bucket-lifecycle-configuration \
  --bucket $BUCKET_NAME \
  --lifecycle-configuration file://lifecycle-policy.json

# Enable server-side encryption
aws s3api put-bucket-encryption \
  --bucket $BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

### 3. Initialize Catalog

```bash
# Build with S3 support
cargo build --release --features s3

# Initialize catalog in S3
export METAFUSE_CATALOG_URI="s3://$BUCKET_NAME/catalog.db?region=$AWS_REGION"
./target/release/metafuse init
```

---

## Authentication Setup

### Option 1: IAM Role (Recommended for ECS/EKS/Lambda)

IAM roles provide temporary credentials without managing access keys.

**Create IAM Policy**:

```bash
# Create policy document
cat > metafuse-s3-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::$BUCKET_NAME",
        "arn:aws:s3:::$BUCKET_NAME/*"
      ]
    }
  ]
}
EOF

# Create policy
aws iam create-policy \
  --policy-name MetaFuseCatalogAccess \
  --policy-document file://metafuse-s3-policy.json

export POLICY_ARN="arn:aws:iam::$AWS_ACCOUNT_ID:policy/MetaFuseCatalogAccess"
```

**Create IAM Role for ECS**:

```bash
# Trust policy for ECS tasks
cat > ecs-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "ecs-tasks.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Create role
aws iam create-role \
  --role-name MetaFuseECSTaskRole \
  --assume-role-policy-document file://ecs-trust-policy.json

# Attach policy
aws iam attach-role-policy \
  --role-name MetaFuseECSTaskRole \
  --policy-arn $POLICY_ARN
```

### Option 2: IAM User (For Local Development)

```bash
# Create IAM user
aws iam create-user --user-name metafuse-dev

# Attach policy
aws iam attach-user-policy \
  --user-name metafuse-dev \
  --policy-arn $POLICY_ARN

# Create access key
aws iam create-access-key --user-name metafuse-dev

# Set environment variables
export AWS_ACCESS_KEY_ID="<AccessKeyId from output>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey from output>"
```

### Option 3: IRSA (IAM Roles for Service Accounts - EKS)

```bash
# Create OIDC provider for EKS cluster (see EKS section)
eksctl utils associate-iam-oidc-provider --cluster=metafuse-cluster --approve

# Create service account with IAM role
eksctl create iamserviceaccount \
  --name metafuse-sa \
  --namespace default \
  --cluster metafuse-cluster \
  --attach-policy-arn $POLICY_ARN \
  --approve
```

---

## ECS Deployment (Fargate)

AWS Fargate provides serverless container execution ideal for the MetaFuse API.

### 1. Build and Push Container Image

```bash
# Create ECR repository
aws ecr create-repository --repository-name metafuse-api --region $AWS_REGION

# Get ECR login token
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Build Docker image
docker build -t metafuse-api:v0.3.0 -f Dockerfile .

# Tag and push
export ECR_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/metafuse-api"
docker tag metafuse-api:v0.3.0 $ECR_REPO:v0.3.0
docker push $ECR_REPO:v0.3.0
```

**Dockerfile**:

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --features s3 --bin metafuse-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/metafuse-api /usr/local/bin/
EXPOSE 8080
ENV RUST_LOG=info
CMD ["metafuse-api"]
```

### 2. Create ECS Cluster

```bash
# Create cluster
aws ecs create-cluster --cluster-name metafuse-cluster --region $AWS_REGION

# Create VPC and subnets (if needed)
# Use existing VPC or create with AWS Console/CloudFormation
```

### 3. Create Task Definition

```bash
# Create task definition JSON
cat > task-definition.json <<EOF
{
  "family": "metafuse-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::$AWS_ACCOUNT_ID:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::$AWS_ACCOUNT_ID:role/MetaFuseECSTaskRole",
  "containerDefinitions": [
    {
      "name": "metafuse-api",
      "image": "$ECR_REPO:v0.3.0",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "METAFUSE_CATALOG_URI",
          "value": "s3://$BUCKET_NAME/catalog.db?region=$AWS_REGION"
        },
        {
          "name": "METAFUSE_CACHE_TTL_SECS",
          "value": "60"
        },
        {
          "name": "RUST_LOG",
          "value": "info"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/metafuse-api",
          "awslogs-region": "$AWS_REGION",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
EOF

# Create CloudWatch log group
aws logs create-log-group --log-group-name /ecs/metafuse-api --region $AWS_REGION

# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json --region $AWS_REGION
```

### 4. Create ECS Service with ALB

```bash
# Create Application Load Balancer
aws elbv2 create-load-balancer \
  --name metafuse-alb \
  --subnets subnet-xxx subnet-yyy \
  --security-groups sg-xxx \
  --region $AWS_REGION

# Create target group
aws elbv2 create-target-group \
  --name metafuse-tg \
  --protocol HTTP \
  --port 8080 \
  --vpc-id vpc-xxx \
  --target-type ip \
  --health-check-path /health \
  --health-check-interval-seconds 30 \
  --region $AWS_REGION

# Create listener
aws elbv2 create-listener \
  --load-balancer-arn <ALB-ARN> \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=forward,TargetGroupArn=<TG-ARN> \
  --region $AWS_REGION

# Create ECS service
aws ecs create-service \
  --cluster metafuse-cluster \
  --service-name metafuse-api \
  --task-definition metafuse-api \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=<TG-ARN>,containerName=metafuse-api,containerPort=8080" \
  --region $AWS_REGION
```

### 5. Test Deployment

```bash
# Get ALB DNS name
export ALB_DNS=$(aws elbv2 describe-load-balancers --names metafuse-alb --query 'LoadBalancers[0].DNSName' --output text --region $AWS_REGION)

# Health check
curl http://$ALB_DNS/health

# List datasets
curl http://$ALB_DNS/api/v1/datasets
```

---

## EKS Deployment (Kubernetes)

EKS is suitable for complex workloads requiring advanced orchestration.

### 1. Create EKS Cluster

```bash
# Install eksctl (if not installed)
# https://eksctl.io/installation/

# Create cluster
eksctl create cluster \
  --name metafuse-cluster \
  --region $AWS_REGION \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 2 \
  --nodes-min 1 \
  --nodes-max 5 \
  --managed

# Update kubeconfig
aws eks update-kubeconfig --name metafuse-cluster --region $AWS_REGION
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
  METAFUSE_CATALOG_URI: "s3://metafuse-catalog-prod/catalog.db?region=us-east-1"
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
        image: ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/metafuse-api:v0.3.0
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
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
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

### 3. Deploy to EKS

```bash
# Apply manifests
kubectl apply -f config.yaml
kubectl apply -f deployment.yaml
kubectl apply -f hpa.yaml

# Wait for deployment
kubectl rollout status deployment/metafuse-api

# Get external endpoint
kubectl get service metafuse-api

# Test
export NLB_DNS=$(kubectl get service metafuse-api -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl http://$NLB_DNS/health
```

---

## Lambda Deployment (Serverless)

AWS Lambda can run the MetaFuse API with API Gateway for event-driven workloads.

### 1. Build Lambda Package

Lambda requires a custom runtime for Rust applications.

```bash
# Install cargo-lambda
cargo install cargo-lambda

# Build for Lambda
cargo lambda build --release --features s3 --bin metafuse-api

# Package
cd target/lambda/metafuse-api
zip -r ../metafuse-api.zip .
cd -
```

**Note**: Lambda deployments require refactoring the API to use Lambda runtime. Consider using ECS/EKS for HTTP APIs unless you need event-driven triggers.

### 2. Alternative: Lambda Container Image

```dockerfile
FROM public.ecr.aws/lambda/provided:al2 as builder
RUN yum install -y gcc openssl-devel
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app
COPY . .
RUN cargo build --release --features s3 --bin metafuse-api

FROM public.ecr.aws/lambda/provided:al2
COPY --from=builder /app/target/release/metafuse-api /var/runtime/bootstrap
CMD ["metafuse-api"]
```

**Note**: This requires significant refactoring to adapt the Axum server to Lambda's event model. ECS/EKS is recommended for HTTP APIs.

---

## Cost Estimation

### ECS Fargate (Recommended for most workloads)

**Assumptions**: 2 tasks, 0.25 vCPU, 512MB RAM, 730 hours/month

| Resource | Usage | Cost/Month |
|----------|-------|------------|
| Fargate vCPU | 2 tasks × 0.25 vCPU × 730h × $0.04048/vCPU-hour | $14.78 |
| Fargate memory | 2 tasks × 0.5GB × 730h × $0.004445/GB-hour | $3.24 |
| Application Load Balancer | 730h × $0.0225/hour | $16.43 |
| ALB LCU charges | ~10 LCUs × 730h × $0.008/LCU-hour | $5.84 |
| **Total ECS** | | **$40.29** |
| S3 storage (10GB) | 10GB × $0.023/GB | $0.23 |
| S3 API calls | 100K PUT/GET × $0.005/1K | $0.50 |
| **Total Monthly** | | **$41.02** |

### EKS (For complex orchestration needs)

**Assumptions**: 2 × t3.medium nodes (2 vCPU, 4GB RAM each)

| Resource | Usage | Cost/Month |
|----------|-------|------------|
| EKS cluster | 1 cluster | $73.00 |
| EC2 instances (t3.medium) | 2 nodes × $0.0416/hour × 730h | $60.74 |
| Network Load Balancer | 730h × $0.0225/hour | $16.43 |
| **Total EKS** | | **$150.17** |
| S3 (same as above) | | $0.73 |
| **Total Monthly** | | **$150.90** |

**Recommendation**: Start with ECS Fargate unless you need:
- Complex service mesh (Istio, Linkerd)
- Advanced scheduling constraints
- Integration with existing EKS workloads
- Multi-region failover with sophisticated routing

---

## Best Practices

### Security

#### Core Security Hardening

1. **Use IAM roles** instead of access keys for ECS/EKS
2. **Enable S3 encryption** at rest (SSE-S3 or SSE-KMS)
3. **Use VPC endpoints** for S3 to avoid internet traffic
4. **Enable AWS WAF** on ALB for DDoS protection
5. **Enable CloudTrail** for API audit logging

```bash
# Enable S3 bucket logging
aws s3api put-bucket-logging \
  --bucket $BUCKET_NAME \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "metafuse-logs",
      "TargetPrefix": "s3-access/"
    }
  }'
```

#### Rate Limiting & API Key Authentication

**Build with security features**:

```bash
# Build with both rate limiting and API key authentication
docker build \
  --build-arg FEATURES="rate-limiting,api-keys" \
  -t metafuse-api:latest .
```

**Configure trusted proxies for ALB**:

```bash
# ALB uses private IPs (RFC 1918)
# Set in ECS task definition or Kubernetes deployment
environment:
  - name: RATE_LIMIT_TRUSTED_PROXIES
    value: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
  - name: RATE_LIMIT_REQUESTS_PER_HOUR
    value: "5000"  # Authenticated clients
  - name: RATE_LIMIT_IP_REQUESTS_PER_HOUR
    value: "100"   # Unauthenticated clients
```

**Store API keys in AWS Secrets Manager**:

```bash
# Create API key using CLI (run once)
metafuse api-key create "production-api" > /tmp/key.txt

# Extract the key value
API_KEY=$(grep "API Key:" /tmp/key.txt | awk '{print $3}')

# Store in Secrets Manager
aws secretsmanager create-secret \
  --name metafuse/api-key/production \
  --description "MetaFuse production API key" \
  --secret-string "$API_KEY" \
  --region $AWS_REGION

# Clean up temporary file
rm -f /tmp/key.txt

# Retrieve in application code or task definition
aws secretsmanager get-secret-value \
  --secret-id metafuse/api-key/production \
  --query SecretString \
  --output text
```

**Security Group configuration**:

```bash
# Create security group for MetaFuse
aws ec2 create-security-group \
  --group-name metafuse-api-sg \
  --description "MetaFuse API security group" \
  --vpc-id vpc-xxx

# Allow inbound from ALB only (not public)
aws ec2 authorize-security-group-ingress \
  --group-id sg-metafuse \
  --protocol tcp \
  --port 8080 \
  --source-group sg-alb

# ALB security group allows 443 from anywhere
aws ec2 authorize-security-group-ingress \
  --group-id sg-alb \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0
```

**ALB configuration for HTTPS**:

```bash
# Create ALB with HTTPS listener
aws elbv2 create-load-balancer \
  --name metafuse-alb \
  --subnets subnet-xxx subnet-yyy \
  --security-groups sg-alb \
  --scheme internet-facing

# Create target group
aws elbv2 create-target-group \
  --name metafuse-tg \
  --protocol HTTP \
  --port 8080 \
  --vpc-id vpc-xxx \
  --health-check-path /health \
  --health-check-interval-seconds 30

# Add HTTPS listener with ACM certificate
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:... \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=arn:aws:acm:... \
  --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:...

# Redirect HTTP to HTTPS
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:... \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=redirect,RedirectConfig="{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}"
```

**IAM policy for least privilege**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::metafuse-catalog-prod",
        "arn:aws:s3:::metafuse-catalog-prod/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:metafuse/*"
    }
  ]
}
```

**Security monitoring with CloudWatch**:

```bash
# Create alarms for security metrics
aws cloudwatch put-metric-alarm \
  --alarm-name metafuse-rate-limit-exceeded \
  --alarm-description "Alert when rate limit 429 responses exceed 5%" \
  --metric-name HTTPCode_Target_4XX_Count \
  --namespace AWS/ApplicationELB \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold

aws cloudwatch put-metric-alarm \
  --alarm-name metafuse-auth-failures \
  --alarm-description "Alert when 401 responses exceed 1%" \
  --metric-name HTTPCode_Target_4XX_Count \
  --namespace AWS/ApplicationELB \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold
```

**Enable AWS WAF for additional protection**:

```bash
# Create Web ACL with rate limiting
aws wafv2 create-web-acl \
  --name metafuse-waf \
  --scope REGIONAL \
  --region $AWS_REGION \
  --default-action Allow={} \
  --rules file://waf-rules.json

# Example waf-rules.json
cat > waf-rules.json <<'EOF'
[
  {
    "Name": "RateLimitRule",
    "Priority": 1,
    "Statement": {
      "RateBasedStatement": {
        "Limit": 2000,
        "AggregateKeyType": "IP"
      }
    },
    "Action": {
      "Block": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitRule"
    }
  }
]
EOF

# Associate WAF with ALB
aws wafv2 associate-web-acl \
  --web-acl-arn arn:aws:wafv2:... \
  --resource-arn arn:aws:elasticloadbalancing:...
```

**For complete security guidance, see**:

- [docs/SECURITY.md](../SECURITY.md) - Comprehensive security guide
- [docs/security-checklist.md](../security-checklist.md) - Pre-deployment checklist
- [.github/SECURITY.md](../.github/SECURITY.md) - Vulnerability reporting

### Reliability

1. **Enable S3 versioning** to recover from accidental deletes
2. **Use multi-AZ deployments** for ECS/EKS
3. **Configure health checks** with appropriate thresholds
4. **Set up auto-scaling** based on CPU/memory metrics
5. **Enable Cross-Region Replication** for disaster recovery

### Performance

1. **Co-locate services** in the same region as S3 bucket
2. **Enable caching** with `METAFUSE_CACHE_TTL_SECS=60`
3. **Use S3 Transfer Acceleration** for multi-region access
4. **Tune task/pod resources** based on workload
5. **Monitor cache hit rates** with CloudWatch metrics

### Operations

1. **Use CloudWatch Logs** with structured logging
2. **Set up CloudWatch Alarms** for error rates and latency
3. **Enable AWS X-Ray** for distributed tracing
4. **Use Systems Manager Parameter Store** for secrets
5. **Automate deployments** with CodePipeline or GitHub Actions

---

## Monitoring

### CloudWatch Dashboards

```bash
# Create CloudWatch dashboard (JSON via Console or CLI)
aws cloudwatch put-dashboard \
  --dashboard-name metafuse-monitoring \
  --dashboard-body file://dashboard.json
```

### Key Metrics to Monitor

| Metric | Threshold | Action |
|--------|-----------|--------|
| ECS CPU utilization | > 80% | Scale up tasks |
| ECS memory utilization | > 85% | Increase memory limit |
| ALB target response time | > 2s | Investigate slow queries |
| ALB 5xx error rate | > 1% | Check application logs |
| S3 API latency | > 500ms | Check region proximity |

### CloudWatch Logs Insights Queries

```sql
# Find errors in last hour
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 20

# P99 latency by endpoint
filter @type = "REQUEST"
| stats pct(@duration, 99) as p99_latency by endpoint
| sort p99_latency desc
```

### X-Ray Tracing

```bash
# Enable X-Ray daemon sidecar in ECS task definition
{
  "name": "xray-daemon",
  "image": "public.ecr.aws/xray/aws-xray-daemon:latest",
  "cpu": 32,
  "memoryReservation": 256,
  "portMappings": [{
    "containerPort": 2000,
    "protocol": "udp"
  }]
}
```

---

## Troubleshooting

### Issue: Authentication Failures

**Symptoms**: `Failed to create S3 client` or `AccessDenied` errors

**Solutions**:
1. Verify IAM role/user has required S3 permissions
2. Check task role is attached to ECS task definition
3. Ensure bucket policy doesn't deny access
4. For IRSA (EKS), verify service account annotation

```bash
# Test S3 access from ECS task
aws ecs execute-command \
  --cluster metafuse-cluster \
  --task TASK_ID \
  --container metafuse-api \
  --interactive \
  --command "aws s3 ls s3://$BUCKET_NAME"
```

### Issue: Precondition Failed (412)

**Symptoms**: `ConflictError: ETag mismatch detected`

**Solutions**:
1. Reduce concurrent writers (single writer recommended)
2. Increase retry delays in application
3. Check for multiple ECS tasks/pods writing simultaneously

### Issue: High Cache Miss Rate

**Symptoms**: High S3 API costs, slow reads

**Solutions**:
1. Increase `METAFUSE_CACHE_TTL_SECS` (default: 60)
2. Ensure persistent storage for cache in ECS (EFS mount)
3. For Lambda, consider using Lambda layers for cache

```bash
# Mount EFS for persistent cache (ECS)
{
  "containerDefinitions": [{
    "mountPoints": [{
      "sourceVolume": "cache",
      "containerPath": "/home/.cache/metafuse"
    }]
  }],
  "volumes": [{
    "name": "cache",
    "efsVolumeConfiguration": {
      "fileSystemId": "fs-xxx",
      "transitEncryption": "ENABLED"
    }
  }]
}
```

### Issue: ECS Task Startup Failures

**Symptoms**: Tasks fail health checks and restart

**Solutions**:
1. Increase `startPeriod` in health check (default: 60s)
2. Check CloudWatch logs for startup errors
3. Verify ECR image exists and is accessible
4. Ensure execution role can pull from ECR

```bash
# View ECS task logs
aws logs tail /ecs/metafuse-api --follow
```

---

## Next Steps

- [GCP Deployment Guide](deployment-gcp.md) - Deploy on GCP with GCS
- [Authentication Guide](auth-aws.md) - Advanced AWS authentication
- [Migration Guide](migration-local-to-cloud.md) - Migrate from local to S3
- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions

---

**Last Updated**: 2025-01-21
