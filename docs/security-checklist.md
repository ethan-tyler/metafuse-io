# MetaFuse Security Checklist

Quick-reference security checklist for MetaFuse deployments. For detailed guidance, see [docs/SECURITY.md](SECURITY.md).

---

## Pre-Production Deployment

### Features & Build

- [ ] **Rate limiting enabled**: `cargo build --features rate-limiting`
- [ ] **API key auth enabled**: `cargo build --features api-keys`
- [ ] **Both features enabled**: `cargo build --features "rate-limiting,api-keys"`
- [ ] Release build optimizations: `cargo build --release`

### Configuration

- [ ] **Trusted proxies configured**: Set `RATE_LIMIT_TRUSTED_PROXIES` to match infrastructure
  - AWS ALB: `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`
  - GCP LB: `130.211.0.0/22,35.191.0.0/16`
  - Cloudflare: Check current IP ranges
- [ ] **Rate limits tuned**: Review `RATE_LIMIT_REQUESTS_PER_HOUR` and `RATE_LIMIT_IP_REQUESTS_PER_HOUR`
- [ ] **Production API keys created**: `metafuse api-key create "production"`
- [ ] **Test/dev keys revoked**: Never deploy with test keys

### Infrastructure

- [ ] **HTTPS/TLS enabled**: Configure reverse proxy (Nginx, Caddy, ALB, etc.)
- [ ] **Non-root user**: Run MetaFuse as dedicated user (not root)
- [ ] **File permissions**: `chmod 600 /path/to/catalog.db`
- [ ] **Firewall rules**: Allow only 443 (HTTPS) and 80 (HTTP redirect)
- [ ] **Secrets management**: Store API keys in AWS Secrets Manager / GCP Secret Manager
- [ ] **Network isolation**: Use VPC / private subnets where possible

### Authentication

- [ ] **Authorization header preferred**: Clients use `Authorization: Bearer <key>`
- [ ] **Query param usage documented**: Only for browsers/testing, not production APIs
- [ ] **Key rotation policy**: Document when/how to rotate keys
- [ ] **Key access restricted**: Only admins can create/revoke keys

---

## Operational Security

### Monitoring

- [ ] **Logging enabled**: API requests, auth failures, rate limit hits
- [ ] **Metrics collection**: Prometheus, CloudWatch, or equivalent
- [ ] **Alerts configured**:
  - 429 (rate limit) response rate >5%
  - 401 (unauthorized) response rate >1%
  - API key validation latency >500ms
  - Memory usage >80%
- [ ] **Dashboard created**: Real-time view of security metrics

### Maintenance

- [ ] **Backup strategy**: Regular database backups (daily/hourly)
- [ ] **Key rotation schedule**: Rotate keys every 90 days or on personnel changes
- [ ] **Dependency updates**: Review security advisories weekly
- [ ] **Security patches**: Apply critical patches within 7 days
- [ ] **Access review**: Audit who has key creation/revocation permissions

### Incident Response

- [ ] **Runbook created**: Steps for key compromise, DDoS, etc.
- [ ] **Contacts identified**: Security team, on-call engineer
- [ ] **Escalation path**: Who to notify for critical incidents
- [ ] **Testing done**: Simulate key revocation, rate limit breach

---

## Testing

### Rate Limiting

- [ ] **Unauthenticated limit tested**: Verify 429 after ~100 requests/hour (IP)
- [ ] **Authenticated limit tested**: Verify 429 after ~5000 requests/hour (API key)
- [ ] **Trusted proxy tested**: Verify correct IP extraction from `X-Forwarded-For`
- [ ] **IPv6 tested**: Verify rate limiting works with IPv6 clients

### API Key Authentication

- [ ] **Valid key tested**: Returns 200 with correct key
- [ ] **Invalid key tested**: Returns 401 with incorrect key
- [ ] **Revoked key tested**: Returns 401 immediately after revocation
- [ ] **Cache tested**: Verify validation is fast (<10ms) on cache hit
- [ ] **Flush tested**: Verify `last_used_at` updates within 30 seconds

### Security

- [ ] **Trusted proxy validation**: Attacker cannot spoof X-Forwarded-For
- [ ] **HTTPS enforcement**: HTTP requests redirect to HTTPS
- [ ] **Cache eviction on revoke**: Revoked keys fail immediately
- [ ] **SQL injection tested**: Try malicious input in API params
- [ ] **Header injection tested**: Try CRLF in headers

---

## Documentation

### User-Facing

- [ ] **Security policy published**: `.github/SECURITY.md` accessible
- [ ] **API docs include auth**: Document how to authenticate requests
- [ ] **Rate limit docs**: Explain limits and how to request increases
- [ ] **Error handling docs**: Explain 401 vs 429 responses

### Internal

- [ ] **Deployment guide**: Include security hardening steps
- [ ] **Runbook updated**: Incident response procedures current
- [ ] **Architecture docs**: Document security boundaries
- [ ] **Monitoring guide**: How to read security metrics

---

## Cloud-Specific (AWS)

- [ ] **Security Groups**: Restrict inbound to ALB only
- [ ] **IAM roles**: Least privilege for API instance
- [ ] **Secrets Manager**: API keys stored securely
- [ ] **CloudWatch Logs**: Enabled for audit trails
- [ ] **ALB access logs**: Enabled to S3
- [ ] **WAF configured**: (optional) AWS WAF for advanced protection
- [ ] **VPC**: API runs in private subnet

---

## Cloud-Specific (GCP)

- [ ] **Firewall Rules**: Restrict access to load balancer
- [ ] **Service Accounts**: Minimal permissions
- [ ] **Secret Manager**: API keys stored securely
- [ ] **Cloud Logging**: Enabled for all requests
- [ ] **Cloud Monitoring**: Dashboards and alerts configured
- [ ] **Cloud Armor**: (optional) For DDoS protection
- [ ] **VPC**: API runs in private network

---

## Container Security (Docker/Kubernetes)

- [ ] **Base image minimal**: Use `debian:bookworm-slim` or `alpine`
- [ ] **Non-root user**: Run as UID 1001 or similar
- [ ] **Image scanning**: Scan for CVEs with Trivy/Snyk
- [ ] **Secrets as volumes**: Mount secrets, don't use ENV vars
- [ ] **Resource limits**: Set memory/CPU limits
- [ ] **Network policies**: Restrict pod-to-pod traffic
- [ ] **Read-only filesystem**: Mount `/data` as only writable volume

---

## Compliance (if applicable)

- [ ] **GDPR**: Document data retention for `last_used_at`
- [ ] **SOC 2**: Implement access logging and audit trails
- [ ] **PCI DSS**: Ensure key storage meets requirements
- [ ] **HIPAA**: (if handling PHI) Encrypt database at rest

---

## Final Pre-Launch Check

Run through this checklist 24 hours before launch:

1. [ ] All above items completed
2. [ ] Security review by second engineer
3. [ ] Penetration testing completed (if required)
4. [ ] Load testing with security features enabled
5. [ ] Rollback plan documented
6. [ ] Monitoring and alerts tested (trigger manually)
7. [ ] On-call rotation scheduled
8. [ ] Security contacts shared with team

---

**Status**: 🔴 Not Ready | 🟡 In Progress | 🟢 Production Ready

**Last Reviewed**: ____________________

**Reviewed By**: ____________________

**Notes**:
