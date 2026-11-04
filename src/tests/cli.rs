//! CLI pieces that work without a terminal: the command parser, Tab
//! completion and `~` expansion. Behaviour inside a real terminal is covered
//! by `tests/e2e/`.

use rustyline::{Context, completion::Completer, history::DefaultHistory};

use crate::adapters::cli::{commands::Command, expand_path, ui::VaultHelper};

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
        ("copy github", Command::Copy("github".into())),
        ("update github", Command::Update("github".into())),
        ("rm github", Command::Remove("github".into())),
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
        "rm", "rename", "export", "import", "frobnicate", "GET github",
    ];
    for input in inputs {
        assert_eq!(Command::parse(input), None, "{input:?}");
    }
}

#[test]
fn every_completable_name_is_a_command() {
    for name in Command::NAMES {
        assert!(Command::parse(&format!("{name} a b")).is_some(), "{name}");
    }
}

/// Completion candidates for `line` with the cursor at its end.
fn complete(line: &str) -> (usize, Vec<String>) {
    let helper = VaultHelper::new(Command::NAMES.to_vec());
    let history = DefaultHistory::new();
    let (start, pairs) = helper.complete(line, line.len(), &Context::new(&history)).unwrap();
    let mut names: Vec<String> = pairs.into_iter().map(|p| p.replacement).collect();
    names.sort();
    (start, names)
}

#[test]
fn tab_completes_command_names() {
    assert_eq!(complete("he"), (0, vec!["help".to_string()]));
    assert_eq!(complete("c").1, ["clear", "commit", "copy", "create"]);
    assert_eq!(complete("xyz"), (0, vec![]));
    assert_eq!(complete("").1.len(), Command::NAMES.len());
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
