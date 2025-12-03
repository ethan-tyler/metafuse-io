//! Enterprise Feature Integration Tests
//!
//! Tests for enterprise-only features including:
//! - Audit logging (feature = "audit")
//! - Usage analytics (feature = "usage-analytics")
//! - Classification (feature = "classification")
//!
//! Run with: `cargo test -p metafuse-catalog-api --features "api-keys,test-utils,enterprise" --test enterprise_feature_tests`

// ============================================================================
// Audit Logging Tests (feature = "audit")
// ============================================================================

#[cfg(feature = "audit")]
mod audit_logging {
    use metafuse_catalog_api::audit::{ActorType, AuditAction, AuditEvent};
    use serde_json::json;

    #[test]
    fn test_audit_action_values() {
        assert_eq!(AuditAction::Create.as_str(), "create");
        assert_eq!(AuditAction::Update.as_str(), "update");
        assert_eq!(AuditAction::Delete.as_str(), "delete");
        assert_eq!(AuditAction::Read.as_str(), "read");
        assert_eq!(AuditAction::Search.as_str(), "search");
        assert_eq!(AuditAction::Export.as_str(), "export");
        assert_eq!(AuditAction::Import.as_str(), "import");
    }

    #[test]
    fn test_actor_type_values() {
        assert_eq!(ActorType::User.as_str(), "user");
        assert_eq!(ActorType::Service.as_str(), "service");
        assert_eq!(ActorType::System.as_str(), "system");
        assert_eq!(ActorType::Anonymous.as_str(), "anonymous");
    }

    #[test]
    fn test_create_audit_event() {
        let event = AuditEvent::create(
            "dataset",
            "my_dataset",
            json!({"name": "my_dataset", "format": "delta"}),
            "req-123",
        );

        assert_eq!(event.action, AuditAction::Create);
        assert_eq!(event.entity_type, "dataset");
        assert_eq!(event.entity_id, Some("my_dataset".to_string()));
        assert_eq!(event.request_id, "req-123");
        assert!(event.old_values.is_none());
        assert!(event.new_values.is_some());
    }

    #[test]
    fn test_update_audit_event() {
        let event = AuditEvent::update(
            "dataset",
            "my_dataset",
            json!({"description": "old desc"}),
            json!({"description": "new desc"}),
            "req-456",
        );

        assert_eq!(event.action, AuditAction::Update);
        assert!(event.old_values.is_some());
        assert!(event.new_values.is_some());
    }

    #[test]
    fn test_delete_audit_event() {
        let event = AuditEvent::delete(
            "dataset",
            "deleted_dataset",
            json!({"name": "deleted_dataset"}),
            "req-789",
        );

        assert_eq!(event.action, AuditAction::Delete);
        assert!(event.old_values.is_some());
        assert!(event.new_values.is_none());
    }

    #[test]
    fn test_audit_event_with_actor() {
        let mut event = AuditEvent::create("dataset", "test", json!({}), "req-001");

        event = event.with_actor("user@example.com", ActorType::User);

        assert_eq!(event.actor, Some("user@example.com".to_string()));
        assert_eq!(event.actor_type, ActorType::User);
    }

    #[test]
    fn test_audit_event_with_api_key() {
        let mut event = AuditEvent::create("dataset", "test", json!({}), "req-002");

        event = event.with_api_key(42);

        assert_eq!(event.api_key_id, Some(42));
    }

    #[test]
    fn test_audit_event_with_client_ip() {
        let mut event = AuditEvent::create("dataset", "test", json!({}), "req-003");

        event = event.with_client_ip("192.168.1.100");

        assert_eq!(event.client_ip, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::create("dataset", "test", json!({"name": "test"}), "req-serialize");

        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("create"));
        assert!(serialized.contains("dataset"));
        assert!(serialized.contains("req-serialize"));
    }
}

// ============================================================================
// Usage Analytics Tests (feature = "usage-analytics")
// ============================================================================

#[cfg(feature = "usage-analytics")]
mod usage_analytics {
    use metafuse_catalog_api::usage_analytics::AccessType;

    #[test]
    fn test_access_type_values() {
        assert_eq!(AccessType::Read.as_str(), "read");
        assert_eq!(AccessType::SearchAppearance.as_str(), "search_appearance");
        assert_eq!(AccessType::LineageQuery.as_str(), "lineage_query");
        assert_eq!(AccessType::ApiCall.as_str(), "api_call");
    }

    #[test]
    fn test_access_type_serialization() {
        let read = AccessType::Read;
        let serialized = serde_json::to_string(&read).unwrap();
        assert!(serialized.contains("read"));
    }

    #[test]
    fn test_access_type_equality() {
        assert_eq!(AccessType::Read, AccessType::Read);
        assert_ne!(AccessType::Read, AccessType::SearchAppearance);
    }

    #[test]
    fn test_access_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AccessType::Read);
        set.insert(AccessType::SearchAppearance);
        set.insert(AccessType::Read); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&AccessType::Read));
        assert!(set.contains(&AccessType::SearchAppearance));
    }
}

// ============================================================================
// Classification Tests (feature = "classification")
// ============================================================================

#[cfg(feature = "classification")]
mod classification {
    use metafuse_catalog_api::classification::{Classification, ClassificationSource};

    #[test]
    fn test_classification_types() {
        assert_eq!(Classification::Pii.as_str(), "pii");
        assert_eq!(Classification::Sensitive.as_str(), "sensitive");
        assert_eq!(Classification::Confidential.as_str(), "confidential");
        assert_eq!(Classification::Public.as_str(), "public");
        assert_eq!(Classification::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_classification_parsing() {
        assert_eq!(Classification::parse("pii"), Classification::Pii);
        assert_eq!(Classification::parse("PII"), Classification::Pii);
        assert_eq!(Classification::parse("Pii"), Classification::Pii);
        assert_eq!(
            Classification::parse("sensitive"),
            Classification::Sensitive
        );
        assert_eq!(
            Classification::parse("confidential"),
            Classification::Confidential
        );
        assert_eq!(Classification::parse("public"), Classification::Public);
        assert_eq!(Classification::parse("invalid"), Classification::Unknown);
        assert_eq!(Classification::parse(""), Classification::Unknown);
    }

    #[test]
    fn test_classification_source_values() {
        assert_eq!(ClassificationSource::Auto.as_str(), "auto");
        assert_eq!(ClassificationSource::Manual.as_str(), "manual");
        assert_eq!(ClassificationSource::Rule.as_str(), "rule");
    }

    #[test]
    fn test_classification_serialization() {
        let pii = Classification::Pii;
        let serialized = serde_json::to_string(&pii).unwrap();
        assert!(serialized.contains("pii"));
    }

    #[test]
    fn test_classification_source_serialization() {
        let source = ClassificationSource::Auto;
        let serialized = serde_json::to_string(&source).unwrap();
        assert!(serialized.contains("auto"));
    }

    #[test]
    fn test_classification_equality() {
        assert_eq!(Classification::Pii, Classification::Pii);
        assert_ne!(Classification::Pii, Classification::Sensitive);
    }

    #[test]
    fn test_classification_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Classification::Pii);
        set.insert(Classification::Sensitive);
        set.insert(Classification::Pii); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&Classification::Pii));
        assert!(set.contains(&Classification::Sensitive));
    }
}

// ============================================================================
// Quality Framework Tests (core functionality, not feature-gated)
// ============================================================================

mod quality_framework {
    use metafuse_catalog_api::quality::{QualityDetails, QualityScores};

    #[test]
    fn test_quality_details_default() {
        let details = QualityDetails::default();
        assert!(details.row_count.is_none());
        assert!(details.file_count.is_none());
        assert!(details.size_bytes.is_none());
        assert!(details.small_file_count.is_none());
        assert!(details.avg_file_size.is_none());
        assert!(details.total_null_count.is_none());
        assert!(details.freshness_sla_secs.is_none());
        assert!(details.staleness_secs.is_none());
        assert!(details.last_modified.is_none());
    }

    #[test]
    fn test_quality_scores_all_none() {
        let scores = QualityScores {
            completeness_score: None,
            freshness_score: None,
            file_health_score: None,
            overall_score: None,
            details: QualityDetails::default(),
        };

        assert!(scores.completeness_score.is_none());
        assert!(scores.freshness_score.is_none());
        assert!(scores.file_health_score.is_none());
        assert!(scores.overall_score.is_none());
    }

    #[test]
    fn test_quality_scores_with_values() {
        let scores = QualityScores {
            completeness_score: Some(0.95),
            freshness_score: Some(0.85),
            file_health_score: Some(0.90),
            overall_score: Some(0.90),
            details: QualityDetails {
                row_count: Some(1000),
                file_count: Some(10),
                size_bytes: Some(1024 * 1024 * 100),
                ..Default::default()
            },
        };

        assert_eq!(scores.completeness_score, Some(0.95));
        assert_eq!(scores.freshness_score, Some(0.85));
        assert_eq!(scores.file_health_score, Some(0.90));
        assert_eq!(scores.overall_score, Some(0.90));
        assert_eq!(scores.details.row_count, Some(1000));
        assert_eq!(scores.details.file_count, Some(10));
    }

    #[test]
    fn test_quality_scores_partial() {
        // Testing partial quality scores (some metrics unavailable)
        let scores = QualityScores {
            completeness_score: Some(0.95),
            freshness_score: None, // No freshness config
            file_health_score: Some(0.80),
            overall_score: Some(0.875), // Computed from available
            details: QualityDetails::default(),
        };

        assert!(scores.completeness_score.is_some());
        assert!(scores.freshness_score.is_none());
        assert!(scores.file_health_score.is_some());
        assert!(scores.overall_score.is_some());
    }

    #[test]
    fn test_quality_details_with_file_stats() {
        let details = QualityDetails {
            row_count: Some(10000),
            file_count: Some(50),
            size_bytes: Some(1024 * 1024 * 500), // 500 MB
            small_file_count: Some(10),
            avg_file_size: Some(1024 * 1024 * 10), // 10 MB avg
            total_null_count: Some(500),
            freshness_sla_secs: Some(3600),
            staleness_secs: Some(1800),
            last_modified: Some("2025-01-15T10:00:00Z".to_string()),
        };

        assert_eq!(details.row_count, Some(10000));
        assert_eq!(details.file_count, Some(50));
        assert_eq!(details.small_file_count, Some(10));
        assert_eq!(details.total_null_count, Some(500));
        assert_eq!(details.freshness_sla_secs, Some(3600));
        assert_eq!(details.staleness_secs, Some(1800));
    }

    #[test]
    fn test_quality_scores_serialization() {
        let scores = QualityScores {
            completeness_score: Some(0.95),
            freshness_score: None,
            file_health_score: Some(0.80),
            overall_score: Some(0.875),
            details: QualityDetails {
                row_count: Some(1000),
                ..Default::default()
            },
        };

        // Test that serialization works
        let json = serde_json::to_string(&scores).unwrap();
        assert!(json.contains("completeness_score"));
        assert!(json.contains("0.95"));
        // Freshness should be skipped since it's None (skip_serializing_if)
        assert!(!json.contains("freshness_score"));
    }

    #[test]
    fn test_quality_score_boundaries() {
        // Test boundary values
        let perfect_scores = QualityScores {
            completeness_score: Some(1.0),
            freshness_score: Some(1.0),
            file_health_score: Some(1.0),
            overall_score: Some(1.0),
            details: QualityDetails::default(),
        };

        assert_eq!(perfect_scores.overall_score, Some(1.0));

        let zero_scores = QualityScores {
            completeness_score: Some(0.0),
            freshness_score: Some(0.0),
            file_health_score: Some(0.0),
            overall_score: Some(0.0),
            details: QualityDetails::default(),
        };

        assert_eq!(zero_scores.overall_score, Some(0.0));
    }

    #[test]
    fn test_quality_details_empty_dataset() {
        // Test details for an empty dataset
        let details = QualityDetails {
            row_count: Some(0),
            file_count: Some(0),
            size_bytes: Some(0),
            small_file_count: Some(0),
            avg_file_size: None, // Can't compute avg for 0 files
            total_null_count: Some(0),
            freshness_sla_secs: None,
            staleness_secs: None,
            last_modified: None,
        };

        assert_eq!(details.row_count, Some(0));
        assert_eq!(details.file_count, Some(0));
    }
}

// ============================================================================
// Control Plane Audit Log Integration Tests
// ============================================================================

#[cfg(feature = "test-utils")]
mod control_plane_audit {
    use metafuse_catalog_api::test_utils::{TestControlPlane, TestTenantBuilder};

    const AUDIT_LOG_LIMIT: usize = 100;

    #[tokio::test]
    async fn test_tenant_operations_logged() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenant
        TestTenantBuilder::new("logged-tenant")
            .build(&cp)
            .await
            .unwrap();

        // Fetch audit log
        let logs = cp
            .control_plane()
            .get_audit_log(Some("logged-tenant"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(
            !logs.is_empty(),
            "Should have audit entries for tenant creation"
        );
    }

    #[tokio::test]
    async fn test_audit_log_records_actor() {
        use metafuse_catalog_api::control_plane::{AuditContext, CreateTenantRequest};

        let cp = TestControlPlane::new().await.unwrap();

        let request = CreateTenantRequest {
            tenant_id: "actor-test".to_string(),
            display_name: "Actor Test Tenant".to_string(),
            admin_email: "admin@actor-test.com".to_string(),
            tier: None,
            region: None,
            quota_max_datasets: None,
            quota_max_storage_bytes: None,
            quota_max_api_calls_per_hour: None,
        };

        let audit = AuditContext {
            actor: "specific-actor@test.com".to_string(),
            request_id: Some("req-actor-test".to_string()),
            client_ip: Some("10.0.0.1".to_string()),
        };

        cp.control_plane()
            .create_tenant(request, audit)
            .await
            .unwrap();

        let logs = cp
            .control_plane()
            .get_audit_log(Some("actor-test"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(logs.iter().any(|l| l.actor == "specific-actor@test.com"));
    }

    #[tokio::test]
    async fn test_audit_log_limit_works() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create multiple tenants
        for i in 0..10 {
            TestTenantBuilder::new(&format!("audit-limit-{}", i))
                .build(&cp)
                .await
                .unwrap();
        }

        // Fetch with limit of 5
        let logs = cp.control_plane().get_audit_log(None, 5).await.unwrap();

        assert_eq!(logs.len(), 5, "Should respect the limit");
    }

    #[tokio::test]
    async fn test_audit_log_ordered_by_time() {
        let cp = TestControlPlane::new().await.unwrap();

        // Create tenants with small delays
        for i in 0..3 {
            TestTenantBuilder::new(&format!("ordered-{}", i))
                .build(&cp)
                .await
                .unwrap();
        }

        let logs = cp.control_plane().get_audit_log(None, 10).await.unwrap();

        // Logs should be ordered by timestamp descending (most recent first)
        for i in 0..logs.len() - 1 {
            assert!(
                logs[i].timestamp >= logs[i + 1].timestamp,
                "Audit logs should be ordered by timestamp descending"
            );
        }
    }

    #[tokio::test]
    async fn test_audit_log_tenant_filter() {
        let cp = TestControlPlane::new().await.unwrap();

        TestTenantBuilder::new("filter-tenant-a")
            .build(&cp)
            .await
            .unwrap();
        TestTenantBuilder::new("filter-tenant-b")
            .build(&cp)
            .await
            .unwrap();

        // Filter for tenant A only
        let logs_a = cp
            .control_plane()
            .get_audit_log(Some("filter-tenant-a"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(logs_a.iter().all(|l| l.tenant_id == "filter-tenant-a"));

        // Filter for tenant B only
        let logs_b = cp
            .control_plane()
            .get_audit_log(Some("filter-tenant-b"), AUDIT_LOG_LIMIT)
            .await
            .unwrap();

        assert!(logs_b.iter().all(|l| l.tenant_id == "filter-tenant-b"));
    }
}

// ============================================================================
// Feature Flag Combination Tests
// ============================================================================

mod feature_combinations {
    /// Test that default features compile and work
    #[test]
    fn test_default_features_available() {
        // Default features should always be available - quality module is core
        use metafuse_catalog_api::quality::{QualityDetails, QualityScores};
        let _ = QualityScores {
            completeness_score: Some(1.0),
            freshness_score: None,
            file_health_score: None,
            overall_score: Some(1.0),
            details: QualityDetails::default(),
        };
    }

    #[cfg(feature = "audit")]
    #[test]
    fn test_audit_feature_available() {
        use metafuse_catalog_api::audit::AuditAction;
        let _ = AuditAction::Create;
    }

    #[cfg(feature = "usage-analytics")]
    #[test]
    fn test_usage_analytics_feature_available() {
        use metafuse_catalog_api::usage_analytics::AccessType;
        let _ = AccessType::Read;
    }

    #[cfg(feature = "classification")]
    #[test]
    fn test_classification_feature_available() {
        use metafuse_catalog_api::classification::Classification;
        let _ = Classification::Pii;
    }

    #[cfg(all(feature = "audit", feature = "usage-analytics"))]
    #[test]
    fn test_audit_and_analytics_together() {
        use metafuse_catalog_api::audit::AuditAction;
        use metafuse_catalog_api::usage_analytics::AccessType;
        let _ = (AuditAction::Create, AccessType::Read);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn test_enterprise_bundle() {
        // Enterprise bundle includes audit, usage-analytics, classification
        use metafuse_catalog_api::audit::AuditAction;
        use metafuse_catalog_api::classification::Classification;
        use metafuse_catalog_api::usage_analytics::AccessType;

        let _ = (AuditAction::Create, AccessType::Read, Classification::Pii);
    }
}

// =============================================================================
// Data Contracts (v0.9.0)
// =============================================================================

#[cfg(feature = "contracts")]
mod data_contracts {
    use metafuse_catalog_api::contracts::*;

    #[test]
    fn test_contract_types_available() {
        let _ = OnViolation::Alert;
        let _ = OnViolation::Warn;
        let _ = OnViolation::Block;
    }

    #[test]
    fn test_schema_contract_creation() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "order_id".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            }],
            allow_additional_columns: true,
        };

        assert_eq!(contract.required_columns.len(), 1);
        assert!(contract.allow_additional_columns);
    }

    #[test]
    fn test_quality_contract_creation() {
        let contract = QualityContract {
            min_completeness: Some(0.95),
            min_freshness: Some(0.90),
            min_overall: Some(0.85),
        };

        assert_eq!(contract.min_completeness, Some(0.95));
        assert_eq!(contract.min_freshness, Some(0.90));
        assert_eq!(contract.min_overall, Some(0.85));
    }

    #[test]
    fn test_freshness_contract_creation() {
        let contract = FreshnessContract {
            max_staleness_secs: 3600,
            expected_interval_secs: Some(1800),
        };

        assert_eq!(contract.max_staleness_secs, 3600);
        assert_eq!(contract.expected_interval_secs, Some(1800));
    }

    #[test]
    fn test_data_contract_creation() {
        let contract = DataContract {
            id: None,
            name: "orders_contract".to_string(),
            dataset_pattern: "orders*".to_string(),
            version: 1,
            schema_contract: Some(SchemaContract {
                required_columns: vec![],
                allow_additional_columns: true,
            }),
            quality_contract: Some(QualityContract {
                min_completeness: Some(0.95),
                min_freshness: None,
                min_overall: None,
            }),
            freshness_contract: Some(FreshnessContract {
                max_staleness_secs: 3600,
                expected_interval_secs: None,
            }),
            on_violation: OnViolation::Alert,
            alert_channels: vec!["https://webhook.example.com".to_string()],
            enabled: true,
        };

        assert_eq!(contract.name, "orders_contract");
        assert_eq!(contract.dataset_pattern, "orders*");
        assert!(contract.schema_contract.is_some());
        assert!(contract.quality_contract.is_some());
        assert!(contract.freshness_contract.is_some());
    }

    #[test]
    fn test_contract_validation_pass() {
        let contract = DataContract {
            id: None,
            name: "valid_contract".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(
            errors.is_empty(),
            "Expected no validation errors: {:?}",
            errors
        );
    }

    #[test]
    fn test_contract_validation_fail_empty_name() {
        let contract = DataContract {
            id: None,
            name: "".to_string(),
            dataset_pattern: "*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.field == "name"));
    }

    #[test]
    fn test_validation_result_types() {
        let pass = ValidationResult::pass("test_contract", "test_dataset");
        assert!(pass.passed);
        assert!(pass.violations.is_empty());

        let fail = ValidationResult::fail(
            "test_contract",
            "test_dataset",
            vec!["Missing column".to_string()],
        );
        assert!(!fail.passed);
        assert_eq!(fail.violations.len(), 1);
    }

    #[test]
    fn test_enforcement_action_types() {
        assert!(!EnforcementAction::Allow.should_block());
        assert!(!EnforcementAction::Warn(vec!["test".to_string()]).should_block());
        assert!(!EnforcementAction::Alert(vec!["test".to_string()]).should_block());
        assert!(EnforcementAction::Block(vec!["test".to_string()]).should_block());
    }

    #[test]
    fn test_schema_evaluation_missing_column() {
        let contract = SchemaContract {
            required_columns: vec![RequiredColumn {
                name: "required_col".to_string(),
                data_type: "Int64".to_string(),
                nullable: false,
            }],
            allow_additional_columns: true,
        };

        let fields = vec![FieldInfo {
            name: "other_col".to_string(),
            data_type: "Int64".to_string(),
            nullable: false,
        }];

        let violations = evaluate_schema_contract(&contract, &fields);
        assert!(!violations.is_empty());
        assert!(violations[0].contains("Missing required column"));
    }

    #[test]
    fn test_quality_evaluation_below_threshold() {
        let contract = QualityContract {
            min_completeness: Some(0.95),
            min_freshness: None,
            min_overall: None,
        };

        let metrics = QualityMetrics {
            completeness_score: Some(0.80),
            freshness_score: None,
            overall_score: None,
            staleness_secs: None,
        };

        let violations = evaluate_quality_contract(&contract, &metrics);
        assert!(!violations.is_empty());
        assert!(violations[0].contains("Completeness"));
    }

    #[test]
    fn test_freshness_evaluation_stale() {
        let contract = FreshnessContract {
            max_staleness_secs: 3600, // 1 hour
            expected_interval_secs: None,
        };

        let metrics = QualityMetrics {
            completeness_score: None,
            freshness_score: None,
            overall_score: None,
            staleness_secs: Some(7200), // 2 hours
        };

        let violations = evaluate_freshness_contract(&contract, &metrics);
        assert!(!violations.is_empty());
        assert!(violations[0].contains("staleness"));
    }

    #[test]
    fn test_contract_crud_operations() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create
        let contract = DataContract {
            id: None,
            name: "test_contract".to_string(),
            dataset_pattern: "test*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let id = create_contract(&conn, &contract).unwrap();
        assert!(id > 0);

        // Read
        let retrieved = get_contract(&conn, "test_contract").unwrap().unwrap();
        assert_eq!(retrieved.name, "test_contract");

        // Update
        let updated = DataContract {
            id: Some(id),
            name: "test_contract".to_string(),
            dataset_pattern: "updated*".to_string(),
            version: 2,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Block,
            alert_channels: vec![],
            enabled: true,
        };

        let success = update_contract(&conn, "test_contract", &updated).unwrap();
        assert!(success);

        let after_update = get_contract(&conn, "test_contract").unwrap().unwrap();
        assert_eq!(after_update.dataset_pattern, "updated*");
        assert_eq!(after_update.on_violation, OnViolation::Block);

        // Delete
        let deleted = delete_contract(&conn, "test_contract").unwrap();
        assert!(deleted);

        let after_delete = get_contract(&conn, "test_contract").unwrap();
        assert!(after_delete.is_none());
    }

    #[test]
    fn test_find_matching_contracts_by_pattern() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create contracts with different patterns
        let c1 = DataContract {
            id: None,
            name: "orders_contract".to_string(),
            dataset_pattern: "orders*".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        let c2 = DataContract {
            id: None,
            name: "raw_contract".to_string(),
            dataset_pattern: "*_raw".to_string(),
            version: 1,
            schema_contract: None,
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Warn,
            alert_channels: vec![],
            enabled: true,
        };

        create_contract(&conn, &c1).unwrap();
        create_contract(&conn, &c2).unwrap();

        // Test matching
        let matches = find_matching_contracts(&conn, "orders_raw").unwrap();
        assert_eq!(matches.len(), 2); // Matches both patterns

        let matches = find_matching_contracts(&conn, "orders_clean").unwrap();
        assert_eq!(matches.len(), 1); // Only matches orders*

        let matches = find_matching_contracts(&conn, "customers").unwrap();
        assert_eq!(matches.len(), 0); // Matches neither
    }

    #[test]
    fn test_contract_evaluator_integration() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        metafuse_catalog_core::init_sqlite_schema(&conn).unwrap();
        metafuse_catalog_core::migrations::run_migrations(&conn).unwrap();

        // Create dataset with fields
        conn.execute(
            "INSERT INTO datasets (name, path, format, created_at, last_updated) VALUES ('orders', '/data/orders', 'delta', datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        let dataset_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO fields (dataset_id, name, data_type, nullable) VALUES (?1, 'order_id', 'Int64', 0)",
            [dataset_id],
        ).unwrap();

        // Create contract requiring order_id
        let contract = DataContract {
            id: None,
            name: "orders_schema".to_string(),
            dataset_pattern: "orders".to_string(),
            version: 1,
            schema_contract: Some(SchemaContract {
                required_columns: vec![RequiredColumn {
                    name: "order_id".to_string(),
                    data_type: "Int64".to_string(),
                    nullable: false,
                }],
                allow_additional_columns: true,
            }),
            quality_contract: None,
            freshness_contract: None,
            on_violation: OnViolation::Alert,
            alert_channels: vec![],
            enabled: true,
        };

        create_contract(&conn, &contract).unwrap();

        // Evaluate
        let evaluator = ContractEvaluator::new(&conn);
        let ctx = DatasetContext {
            id: dataset_id,
            name: "orders".to_string(),
            tenant_id: None,
        };

        let results = evaluator.evaluate_for_dataset(&ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed, "Contract should pass");
    }
}
