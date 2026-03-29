//! Auth Profile management for multi-account credential rotation.
//!
//! Profiles are sorted by preference and cooldown status so the
//! resolver always picks the best available credential.

use std::time::{Duration, Instant};

/// A single authentication profile associated with a provider.
///
/// Profiles carry an optional environment variable name for the API key
/// and track rate-limit cooldown state.
#[derive(Debug, Clone)]
pub struct AuthProfile {
    pub profile_id: String,
    pub provider_id: String,
    pub api_key_env: Option<String>,
    pub priority: i32,
    pub cooldown_until: Option<Instant>,
    pub preferred: bool,
}

/// Sorts profiles in resolution order: preferred first, then by ascending
/// priority value, with cooled-down profiles pushed to the end.
pub fn sort_profiles(profiles: &mut [AuthProfile]) {
    profiles.sort_by(|a, b| {
        let a_cooled = is_cooled_down(a);
        let b_cooled = is_cooled_down(b);

        a_cooled
            .cmp(&b_cooled)
            .then_with(|| b.preferred.cmp(&a.preferred))
            .then_with(|| a.priority.cmp(&b.priority))
    });
}

/// Marks a profile as rate-limited for `retry_after` from now.
pub fn report_rate_limit(profile: &mut AuthProfile, retry_after: Duration) {
    profile.cooldown_until = Some(Instant::now() + retry_after);
}

/// Returns `true` if the profile is currently in a cooldown period.
pub fn is_cooled_down(profile: &AuthProfile) -> bool {
    profile
        .cooldown_until
        .is_some_and(|until| Instant::now() < until)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(id: &str, priority: i32, preferred: bool) -> AuthProfile {
        AuthProfile {
            profile_id: id.to_owned(),
            provider_id: "test-provider".to_owned(),
            api_key_env: Some(format!("{}_API_KEY", id.to_uppercase())),
            priority,
            cooldown_until: None,
            preferred,
        }
    }

    #[test]
    fn sort_preferred_first() {
        let mut profiles = vec![
            make_profile("low", 1, false),
            make_profile("high", 0, false),
            make_profile("pref", 5, true),
        ];
        sort_profiles(&mut profiles);
        assert_eq!(profiles[0].profile_id, "pref");
    }

    #[test]
    fn sort_by_priority_within_non_preferred() {
        let mut profiles = vec![
            make_profile("b", 2, false),
            make_profile("a", 1, false),
            make_profile("c", 3, false),
        ];
        sort_profiles(&mut profiles);
        assert_eq!(profiles[0].profile_id, "a");
        assert_eq!(profiles[1].profile_id, "b");
        assert_eq!(profiles[2].profile_id, "c");
    }

    #[test]
    fn cooled_down_profiles_sort_last() {
        let mut profiles = vec![
            make_profile("ok", 1, false),
            make_profile("cooled", 0, true),
        ];
        report_rate_limit(&mut profiles[1], Duration::from_secs(60));
        sort_profiles(&mut profiles);
        assert_eq!(profiles[0].profile_id, "ok");
        assert_eq!(profiles[1].profile_id, "cooled");
    }

    #[test]
    fn report_rate_limit_sets_cooldown() {
        let mut profile = make_profile("test", 0, false);
        assert!(!is_cooled_down(&profile));
        report_rate_limit(&mut profile, Duration::from_secs(10));
        assert!(is_cooled_down(&profile));
    }

    #[test]
    fn expired_cooldown_not_cooled() {
        let mut profile = make_profile("test", 0, false);
        profile.cooldown_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!is_cooled_down(&profile));
    }
}
