//! CLI pieces that work without a terminal: the command parser, Tab
//! completion and `~` expansion. Behaviour inside a real terminal is covered
//! by `tests/e2e/`.

use std::fs;

use rustyline::{Context, completion::Completer, history::DefaultHistory};

use super::support::TempDir;
use crate::{
    adapters::cli::{
        auto_lock,
        commands::{Command, Field},
        describe, expand_path,
        ui::VaultHelper,
    },
    domain::models::Entry,
};

#[test]
fn parses_every_command_with_its_arguments() {
    let cases = [
        ("create personal", Command::Create("personal".into())),
        ("unlock personal", Command::Unlock("personal".into())),
        ("lock", Command::Lock),
        ("passwd", Command::Passwd),
        ("drop work", Command::Drop("work".into())),
        (
            "add github alice",
            Command::Add { service: "github".into(), username: "alice".into() },
        ),
        ("get github", Command::Get("github".into())),
        ("find", Command::Find(None)),
        ("find git", Command::Find(Some("git".into()))),
        ("history github", Command::History("github".into())),
        ("copy github", Command::Copy { service: "github".into(), field: Field::Password }),
        ("copy github password", Command::Copy { service: "github".into(), field: Field::Password }),
        ("copy github user", Command::Copy { service: "github".into(), field: Field::Username }),
        ("copy github username", Command::Copy { service: "github".into(), field: Field::Username }),
        ("update github", Command::Update("github".into())),
        ("rm github", Command::Remove("github".into())),
        ("mv github gh", Command::Move { from: "github".into(), to: "gh".into() }),
        ("gen", Command::Gen(None)),
        ("gen 32", Command::Gen(Some(32))),
        ("commit", Command::Commit),
        ("rename work", Command::Rename("work".into())),
        ("ls", Command::List),
        ("list", Command::List),
        ("info", Command::Info),
        ("export ~/out.csv", Command::Export("~/out.csv".into())),
        ("import in.csv", Command::Import("in.csv".into())),
        ("clear", Command::Clear),
        ("help", Command::Help),
        ("exit", Command::Exit),
    ];
    for (input, expected) in cases {
        assert_eq!(Command::parse(input), Some(expected), "{input:?}");
    }
}

#[test]
fn extra_whitespace_is_ignored() {
    assert_eq!(Command::parse("  get   github  "), Some(Command::Get("github".into())));
}

#[test]
fn missing_arguments_and_unknown_commands_are_rejected() {
    let inputs = [
        "", "   ", "create", "unlock", "drop", "add", "add github", "get", "copy", "update",
        "rm", "history", "mv", "mv github", "rename", "export", "import", "frobnicate", "GET github", "copy github pin",
    ];
    for input in inputs {
        assert_eq!(Command::parse(input), None, "{input:?}");
    }
}

/// Whether `name` followed by one or two arguments parses.
fn parses_with_arguments(name: &str) -> bool {
    [" x", " x y"].iter().any(|args| Command::parse(&format!("{name}{args}")).is_some())
}

#[test]
fn every_completable_name_is_a_command() {
    for name in Command::NAMES {
        assert!(Command::parse(name).is_some() || parses_with_arguments(name), "{name}");
    }
}

#[test]
fn every_command_that_needs_an_argument_declares_it() {
    for name in Command::NAMES {
        let parses_alone = Command::parse(name).is_some();
        match Command::first_argument(name) {
            None => assert!(parses_alone, "{name} takes an argument but doesn't declare it"),
            Some(_) => assert!(parses_with_arguments(name), "{name}"),
        }
    }
}

#[test]
fn copy_takes_the_field_it_names() {
    let entry = Entry::new("github".into(), "alice".into(), "hunter2".into());
    assert_eq!((Field::Password.of(&entry), Field::Password.label()), ("hunter2", "Password"));
    assert_eq!((Field::Username.of(&entry), Field::Username.label()), ("alice", "Username"));
}

/// Completion for `line` with the cursor at its end, given the entry and
/// vault names the CLI would hand over. Replacements come back sorted.
fn complete_with(line: &str, entries: &[&str], vaults: &[&str]) -> (usize, Vec<String>) {
    let mut helper = VaultHelper::new(Command::NAMES.to_vec());
    helper.set_names(
        entries.iter().map(|s| s.to_string()).collect(),
        vaults.iter().map(|s| s.to_string()).collect(),
    );
    let history = DefaultHistory::new();
    let (start, pairs) = helper.complete(line, line.len(), &Context::new(&history)).unwrap();
    let mut replacements: Vec<String> = pairs.into_iter().map(|p| p.replacement).collect();
    replacements.sort();
    (start, replacements)
}

fn complete(line: &str) -> (usize, Vec<String>) {
    complete_with(line, &[], &[])
}

#[test]
fn tab_completes_command_names() {
    assert_eq!(complete("he"), (0, vec!["help".to_string()]));
    assert_eq!(complete("c").1, ["clear", "commit", "copy ", "create "]);
    assert_eq!(complete("xyz"), (0, vec![]));
    assert_eq!(complete("").1.len(), Command::NAMES.len());
}

#[test]
fn commands_that_take_an_argument_complete_with_a_trailing_space() {
    assert_eq!(complete("up").1, ["update "]);
    assert_eq!(complete("lo").1, ["lock"]);
}

#[test]
fn tab_completes_entry_names_after_entry_commands() {
    let entries = ["bank", "github", "gitlab"];
    for command in ["get", "copy", "update", "rm", "find", "history", "mv"] {
        assert_eq!(
            complete_with(&format!("{command} gi"), &entries, &[]),
            (command.len() + 1, vec!["github".to_string(), "gitlab".to_string()]),
            "{command}"
        );
    }
    assert_eq!(complete_with("get b", &entries, &[]).1, ["bank"]);
}

#[test]
fn tab_completes_vault_names_after_unlock_and_drop() {
    let vaults = ["work", "personal"];
    assert_eq!(complete_with("unlock p", &[], &vaults), (7, vec!["personal".to_string()]));
    assert_eq!(complete_with("drop ", &[], &vaults).1, ["personal", "work"]);
}

#[test]
fn commands_are_only_completed_in_the_first_word() {
    // `unlock pa` used to offer `passwd`.
    assert!(complete_with("unlock pa", &[], &["personal"]).1.is_empty());
    assert_eq!(complete_with("unlock p", &[], &["personal"]).1, ["personal"]);
    assert!(complete("get he").1.is_empty());
}

#[test]
fn nothing_is_offered_where_a_new_name_or_a_second_argument_goes() {
    let (entries, vaults) = (["github"], ["personal"]);
    for line in ["create p", "add g", "rename p", "gen 1", "lock x", "add github a", "get github x", "mv github g"] {
        assert!(complete_with(line, &entries, &vaults).1.is_empty(), "{line:?}");
    }
}

#[test]
fn tab_completes_file_paths_after_import_and_export() {
    let dir = TempDir::new();
    fs::write(dir.file("export.csv"), "").unwrap();
    fs::write(dir.file("notes.txt"), "").unwrap();
    fs::create_dir(dir.file("exports")).unwrap();
    let base = dir.path().to_str().unwrap();

    for command in ["import", "export"] {
        let (start, paths) = complete(&format!("{command} {base}/exp"));
        assert_eq!(start, command.len() + 1, "{command}");
        assert_eq!(paths, [format!("{base}/export.csv"), format!("{base}/exports/")]);
    }
}

#[test]
fn expand_path_replaces_a_leading_tilde_only() {
    let home = std::env::var("HOME").unwrap();
    assert_eq!(expand_path("~"), home);
    assert_eq!(expand_path("~/out.csv"), format!("{home}/out.csv"));
    for unchanged in ["/tmp/out.csv", "out.csv", "~user/out.csv", "a/~/b"] {
        assert_eq!(expand_path(unchanged), unchanged);
    }
}

#[test]
fn vault_auto_lock_sets_the_idle_time_in_seconds() {
    use std::time::Duration;
    assert_eq!(auto_lock(None), Ok(Some(Duration::from_secs(300))));
    assert_eq!(auto_lock(Some("90")), Ok(Some(Duration::from_secs(90))));
    assert_eq!(auto_lock(Some(" 600 ")), Ok(Some(Duration::from_secs(600))));
    assert_eq!(auto_lock(Some("0")), Ok(None), "0 turns it off");
    for bad in ["", "5m", "-1", "soon"] {
        assert!(auto_lock(Some(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn idle_times_read_in_minutes_when_whole() {
    use std::time::Duration;
    let read = |seconds| describe(Duration::from_secs(seconds));
    assert_eq!((read(300), read(60), read(90), read(1)), ("5 min".into(), "1 min".into(), "90 s".into(), "1 s".into()));
}
