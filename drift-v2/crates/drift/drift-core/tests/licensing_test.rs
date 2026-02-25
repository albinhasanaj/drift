//! Comprehensive tests for Phase 10B Licensing & Feature Gating.
//!
//! T10-LIC-01: License validation correctly gates all 16 features per tier
//! T10-LIC-02: Graceful degradation when license missing
//! T10-LIC-03: Expired license with 7-day grace period
//! T10-LIC-04: JWT validation (valid/tampered/expired)
//! T10-LIC-05: License tier upgrade without restart (hot-reload)

use drift_core::config::license_config::LicenseTier;
use drift_core::licensing;
use drift_core::licensing::{
    features_for_tier, tier_allows, FeatureAccess, GatedFeature, LicenseManager, LicenseSource,
    LicenseStatus,
};

// ============================================================
// T10-LIC-01: Feature gating per tier
// ============================================================

#[test]
fn t10_lic_01a_community_allows_5_features() {
    let allowed = features_for_tier(&LicenseTier::Community);
    assert_eq!(allowed.len(), 5);
    assert!(allowed.contains(&GatedFeature::CoreAnalysis));
    assert!(allowed.contains(&GatedFeature::PatternDetection));
    assert!(allowed.contains(&GatedFeature::CallGraph));
    assert!(allowed.contains(&GatedFeature::BoundaryDetection));
    assert!(allowed.contains(&GatedFeature::QualityGates));
}

#[test]
fn t10_lic_01b_team_allows_9_features() {
    let allowed = features_for_tier(&LicenseTier::Team);
    assert_eq!(allowed.len(), 9);
    // All community features
    assert!(allowed.contains(&GatedFeature::CoreAnalysis));
    // Plus team features
    assert!(allowed.contains(&GatedFeature::AdvancedAnalysis));
    assert!(allowed.contains(&GatedFeature::CiIntegration));
    assert!(allowed.contains(&GatedFeature::ScheduledGrounding));
    assert!(allowed.contains(&GatedFeature::McpTools));
}

#[test]
fn t10_lic_01c_enterprise_allows_all_16() {
    let allowed = features_for_tier(&LicenseTier::Enterprise);
    assert_eq!(allowed.len(), 16);
    // Enterprise gets everything
    for feature in &GatedFeature::ALL {
        assert!(
            tier_allows(&LicenseTier::Enterprise, feature),
            "Enterprise should allow {:?}",
            feature
        );
    }
}

#[test]
fn t10_lic_01d_community_denies_team_features() {
    assert!(!tier_allows(&LicenseTier::Community, &GatedFeature::AdvancedAnalysis));
    assert!(!tier_allows(&LicenseTier::Community, &GatedFeature::CiIntegration));
    assert!(!tier_allows(&LicenseTier::Community, &GatedFeature::ScheduledGrounding));
    assert!(!tier_allows(&LicenseTier::Community, &GatedFeature::McpTools));
}

#[test]
fn t10_lic_01e_team_denies_enterprise_features() {
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::TaintAnalysis));
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::FullGroundingLoop));
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::ContradictionGeneration));
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::CrossDbAnalytics));
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::Telemetry));
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::CustomDetectors));
    assert!(!tier_allows(&LicenseTier::Team, &GatedFeature::ExportImport));
}

#[test]
fn t10_lic_01f_feature_min_tier_correct() {
    assert_eq!(GatedFeature::CoreAnalysis.min_tier(), LicenseTier::Community);
    assert_eq!(GatedFeature::AdvancedAnalysis.min_tier(), LicenseTier::Team);
    assert_eq!(GatedFeature::TaintAnalysis.min_tier(), LicenseTier::Enterprise);
}

#[test]
fn t10_lic_01g_all_16_features_defined() {
    assert_eq!(GatedFeature::ALL.len(), 16);
    assert_eq!(GatedFeature::COMMUNITY.len(), 5);
    assert_eq!(GatedFeature::TEAM.len(), 4);
    assert_eq!(GatedFeature::ENTERPRISE.len(), 7);
    // 5 + 4 + 7 = 16
    assert_eq!(
        GatedFeature::COMMUNITY.len() + GatedFeature::TEAM.len() + GatedFeature::ENTERPRISE.len(),
        16
    );
}

#[test]
fn t10_lic_01h_feature_str_roundtrip() {
    for feature in &GatedFeature::ALL {
        let s = feature.as_str();
        let parsed = GatedFeature::parse(s);
        assert_eq!(parsed, Some(*feature), "Roundtrip failed for {:?}", feature);
    }
    assert_eq!(GatedFeature::parse("nonexistent"), None);
}

#[test]
fn t10_lic_01i_feature_descriptions_nonempty() {
    for feature in &GatedFeature::ALL {
        assert!(
            !feature.description().is_empty(),
            "Feature {:?} has empty description",
            feature
        );
    }
}

// ============================================================
// T10-LIC-02: Graceful degradation when license missing
// ============================================================

#[test]
fn t10_lic_02a_default_manager_is_community() {
    let mgr = LicenseManager::new();
    assert_eq!(mgr.tier(), LicenseTier::Community);
    assert_eq!(mgr.state().source, LicenseSource::Default);
}

#[test]
fn t10_lic_02b_missing_license_allows_core_features() {
    let mgr = LicenseManager::new();

    // Community features should work
    assert!(mgr.check_feature(GatedFeature::CoreAnalysis).is_allowed());
    assert!(mgr.check_feature(GatedFeature::PatternDetection).is_allowed());
    assert!(mgr.check_feature(GatedFeature::CallGraph).is_allowed());
}

#[test]
fn t10_lic_02c_missing_license_denies_with_upgrade_message() {
    let mgr = LicenseManager::new();

    let access = mgr.check_feature(GatedFeature::TaintAnalysis);
    assert!(!access.is_allowed());

    let msg = access.denial_message().unwrap();
    assert!(msg.contains("Enterprise"));
    assert!(msg.contains("driftscan.dev/pricing"));
}

#[test]
fn t10_lic_02d_missing_license_returns_not_crash() {
    let mgr = LicenseManager::new();

    // Check ALL features — none should panic
    for feature in &GatedFeature::ALL {
        let access = mgr.check_feature(*feature);
        // Community features allowed, rest denied — but no crash
        match access {
            FeatureAccess::Allowed => {}
            FeatureAccess::Denied { .. } => {}
            FeatureAccess::GracePeriod { .. } => {}
        }
    }
}

// ============================================================
// T10-LIC-03: Expired license with 7-day grace period
// ============================================================

#[test]
fn t10_lic_03a_grace_period_allows_features() {
    let now = current_unix_time();

    // Create a JWT that expired 1 hour ago (within 7-day grace)
    let claims = licensing::LicenseClaims {
        sub: "test@example.com".to_string(),
        tier: "team".to_string(),
        iat: now - 86400 * 30,
        exp: now - 3600, // Expired 1 hour ago
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");
    std::fs::write(&jwt_path, &token).unwrap();

    let mgr = LicenseManager::load(Some(&jwt_path), None, None, None);
    let state = mgr.state();

    assert!(
        matches!(state.status, LicenseStatus::GracePeriod { .. }),
        "Expected GracePeriod, got {:?}",
        state.status
    );

    // Team features should still work during grace period
    let access = mgr.check_feature(GatedFeature::McpTools);
    assert!(access.is_allowed());

    // But should include warning
    if let FeatureAccess::GracePeriod { days_remaining, .. } = access {
        assert!(days_remaining > 0);
        assert!(days_remaining <= 7);
    }
}

#[test]
fn t10_lic_03b_expired_past_grace_degrades_to_community() {
    let now = current_unix_time();

    // Create a JWT that expired 30 days ago (well past 7-day grace)
    let claims = licensing::LicenseClaims {
        sub: "test@example.com".to_string(),
        tier: "enterprise".to_string(),
        iat: now - 86400 * 60,
        exp: now - 86400 * 30, // Expired 30 days ago
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");
    std::fs::write(&jwt_path, &token).unwrap();

    let mgr = LicenseManager::load(Some(&jwt_path), None, None, None);
    let state = mgr.state();

    assert_eq!(state.tier, LicenseTier::Community);
    assert_eq!(state.status, LicenseStatus::Expired);

    // Enterprise features should be denied
    assert!(!mgr.check_feature(GatedFeature::TaintAnalysis).is_allowed());
    // Community features should still work
    assert!(mgr.check_feature(GatedFeature::CoreAnalysis).is_allowed());
}

#[test]
fn t10_lic_03c_grace_period_message() {
    let now = current_unix_time();

    let claims = licensing::LicenseClaims {
        sub: "test".to_string(),
        tier: "team".to_string(),
        iat: now - 86400,
        exp: now - 3600,
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");
    std::fs::write(&jwt_path, &token).unwrap();

    let mgr = LicenseManager::load(Some(&jwt_path), None, None, None);
    let access = mgr.check_feature(GatedFeature::McpTools);
    let msg = access.denial_message();
    assert!(msg.is_some());
    assert!(msg.unwrap().contains("expired"));
}

// ============================================================
// T10-LIC-04: JWT validation
// ============================================================

#[test]
fn t10_lic_04a_valid_jwt_parses() {
    let now = current_unix_time();
    let claims = licensing::LicenseClaims {
        sub: "user@drift.dev".to_string(),
        tier: "enterprise".to_string(),
        iat: now,
        exp: now + 86400 * 365,
        features: vec!["custom_detectors".to_string()],
        org_id: Some("org-456".to_string()),
        seats: Some(50),
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let parsed = licensing::jwt::parse_jwt(&token).unwrap();

    assert_eq!(parsed.sub, "user@drift.dev");
    assert_eq!(parsed.tier, "enterprise");
    assert_eq!(parsed.org_id.as_deref(), Some("org-456"));
    assert_eq!(parsed.seats, Some(50));
}

#[test]
fn t10_lic_04b_tampered_jwt_rejected() {
    // A JWT with invalid base64 in the payload
    let result = licensing::jwt::parse_jwt("eyJhbGciOiJIUzI1NiJ9.INVALID!!!.signature");
    assert!(result.is_err());
}

#[test]
fn t10_lic_04c_expired_jwt_detected() {
    let claims = licensing::LicenseClaims {
        sub: "test".to_string(),
        tier: "team".to_string(),
        iat: 1000000,
        exp: 1000001,
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let parsed = licensing::jwt::parse_jwt(&token).unwrap();
    let result = licensing::jwt::validate_claims(&parsed);
    assert!(result.is_err());

    if let Err(licensing::JwtError::Expired { .. }) = result {
        // Expected
    } else {
        panic!("Expected Expired error");
    }
}

#[test]
fn t10_lic_04d_non_expiring_jwt() {
    let now = current_unix_time();
    let claims = licensing::LicenseClaims {
        sub: "forever@drift.dev".to_string(),
        tier: "enterprise".to_string(),
        iat: now,
        exp: 0, // Never expires
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let parsed = licensing::jwt::parse_jwt(&token).unwrap();
    assert!(licensing::jwt::validate_claims(&parsed).is_ok());
    assert_eq!(licensing::jwt::seconds_until_expiry(&parsed), u64::MAX);
    assert!(!licensing::jwt::is_in_grace_period(&parsed, 7));
}

#[test]
fn t10_lic_04e_malformed_jwt_format() {
    // Too few parts
    assert!(licensing::jwt::parse_jwt("just-one-part").is_err());
    assert!(licensing::jwt::parse_jwt("two.parts").is_err());
    // Empty string
    assert!(licensing::jwt::parse_jwt("").is_err());
}

#[test]
fn t10_lic_04f_jwt_from_file() {
    let now = current_unix_time();
    let claims = licensing::LicenseClaims {
        sub: "file-test@drift.dev".to_string(),
        tier: "team".to_string(),
        iat: now,
        exp: now + 86400,
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");
    std::fs::write(&jwt_path, &token).unwrap();

    let mgr = LicenseManager::load(Some(&jwt_path), None, None, None);
    assert_eq!(mgr.tier(), LicenseTier::Team);
    assert_eq!(mgr.state().status, LicenseStatus::Valid);
    assert!(matches!(
        mgr.state().source,
        LicenseSource::JwtFile(_)
    ));
}

// ============================================================
// T10-LIC-05: License tier upgrade without restart (hot-reload)
// ============================================================

#[test]
fn t10_lic_05a_hot_reload_upgrades_tier() {
    let now = current_unix_time();
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");

    // Start with Team license
    let team_claims = licensing::LicenseClaims {
        sub: "test@drift.dev".to_string(),
        tier: "team".to_string(),
        iat: now,
        exp: now + 86400,
        features: vec![],
        org_id: None,
        seats: None,
    };
    std::fs::write(&jwt_path, licensing::jwt::create_test_jwt(&team_claims)).unwrap();

    let mgr = LicenseManager::load(Some(&jwt_path), None, None, None);
    assert_eq!(mgr.tier(), LicenseTier::Team);
    assert!(!mgr.check_feature(GatedFeature::TaintAnalysis).is_allowed());

    // Swap JWT to Enterprise
    let enterprise_claims = licensing::LicenseClaims {
        sub: "test@drift.dev".to_string(),
        tier: "enterprise".to_string(),
        iat: now,
        exp: now + 86400,
        features: vec![],
        org_id: None,
        seats: None,
    };
    std::fs::write(&jwt_path, licensing::jwt::create_test_jwt(&enterprise_claims)).unwrap();

    // Hot-reload
    mgr.reload().unwrap();

    assert_eq!(mgr.tier(), LicenseTier::Enterprise);
    assert!(mgr.check_feature(GatedFeature::TaintAnalysis).is_allowed());
}

#[test]
fn t10_lic_05b_hot_reload_downgrades_tier() {
    let now = current_unix_time();
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");

    // Start with Enterprise
    let claims = licensing::LicenseClaims {
        sub: "test@drift.dev".to_string(),
        tier: "enterprise".to_string(),
        iat: now,
        exp: now + 86400,
        features: vec![],
        org_id: None,
        seats: None,
    };
    std::fs::write(&jwt_path, licensing::jwt::create_test_jwt(&claims)).unwrap();

    let mgr = LicenseManager::load(Some(&jwt_path), None, None, None);
    assert_eq!(mgr.tier(), LicenseTier::Enterprise);

    // Swap to Community
    let community = licensing::LicenseClaims {
        tier: "community".to_string(),
        ..claims.clone()
    };
    std::fs::write(&jwt_path, licensing::jwt::create_test_jwt(&community)).unwrap();

    mgr.reload().unwrap();
    assert_eq!(mgr.tier(), LicenseTier::Community);
    assert!(!mgr.check_feature(GatedFeature::TaintAnalysis).is_allowed());
}

#[test]
fn t10_lic_05c_reload_without_jwt_path_fails() {
    let mgr = LicenseManager::new();
    let result = mgr.reload();
    assert!(result.is_err());
}

// ============================================================
// T10-LIC-06: Manager load priority
// ============================================================

#[test]
fn t10_lic_06a_config_tier_fallback() {
    let mgr = LicenseManager::load(None, None, Some(&LicenseTier::Team), None);
    assert_eq!(mgr.tier(), LicenseTier::Team);
    assert_eq!(mgr.state().source, LicenseSource::ConfigFile);
}

#[test]
fn t10_lic_06b_jwt_takes_priority_over_config() {
    let now = current_unix_time();
    let tmp = tempfile::tempdir().unwrap();
    let jwt_path = tmp.path().join("license.jwt");

    let claims = licensing::LicenseClaims {
        sub: "test".to_string(),
        tier: "enterprise".to_string(),
        iat: now,
        exp: now + 86400,
        features: vec![],
        org_id: None,
        seats: None,
    };
    std::fs::write(&jwt_path, licensing::jwt::create_test_jwt(&claims)).unwrap();

    // Even though config says Community, JWT says Enterprise → Enterprise wins
    let mgr = LicenseManager::load(Some(&jwt_path), None, Some(&LicenseTier::Community), None);
    assert_eq!(mgr.tier(), LicenseTier::Enterprise);
}

#[test]
fn t10_lic_06c_custom_upgrade_url() {
    let mgr = LicenseManager::load(None, None, None, Some("https://custom.dev/pricing"));

    let access = mgr.check_feature(GatedFeature::TaintAnalysis);
    if let FeatureAccess::Denied { upgrade_url, .. } = access {
        assert_eq!(upgrade_url, "https://custom.dev/pricing");
    } else {
        panic!("Expected Denied");
    }
}

#[test]
fn t10_lic_06d_nonexistent_jwt_file_falls_through() {
    let mgr = LicenseManager::load(
        Some(std::path::Path::new("/nonexistent/license.jwt")),
        None,
        Some(&LicenseTier::Team),
        None,
    );
    // JWT file doesn't exist, should fall through to config tier
    assert_eq!(mgr.tier(), LicenseTier::Team);
}

// ---- Helpers ----

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
