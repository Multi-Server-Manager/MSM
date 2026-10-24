//! §8.13: an account name reaches a privilege switch, so it is validated with
//! the same care as a package name.

use msm_protocol::commands::valid_account;

#[test]
fn account_charset() {
    for accepted in ["root", "nebuff", "git_1", "user-1", "a.b"] {
        assert!(valid_account(accepted), "{accepted}");
    }
    for refused in ["", "Root", "-root", "a b", "a/b", "a;b", "$(id)", "--all"] {
        assert!(!valid_account(refused), "{refused}");
    }
}
