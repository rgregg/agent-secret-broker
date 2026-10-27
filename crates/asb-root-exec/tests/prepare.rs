use asb_client::mock::MockBroker;
use asb_root_exec::{build_command, prepare, Context, Failure, Plan, Policy};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

type Tamper = Box<dyn Fn(&Tree)>;

fn fixture(name: &str) -> String {
    fs::read_to_string(format!(
        "{}/../../tests/fixtures/sudo/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

/// A private tree standing in for `/`: root/bin (programs), root/etc (config), root/home.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        let raw = std::env::temp_dir().join(format!(
            "asbre-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&raw).unwrap();
        let root = fs::canonicalize(&raw).unwrap();
        for d in ["", "bin", "etc", "home"] {
            let p = root.join(d);
            fs::create_dir_all(&p).unwrap();
            chmod(&p, 0o755);
        }
        Tree { root }
    }

    fn program(&self, name: &str, body: &str) -> PathBuf {
        let p = self.root.join("bin").join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        chmod(&p, 0o755);
        p
    }

    fn config(&self, url: &str) -> PathBuf {
        let p = self.root.join("etc/root-exec.json");
        fs::write(&p, format!(r#"{{"url":"{url}","key":"HELPER-KEY"}}"#)).unwrap();
        chmod(&p, 0o600);
        p
    }

    fn policy(&self) -> Policy {
        Policy {
            trusted_uid: unsafe { libc::geteuid() },
            trust_root: self.root.clone(),
            config_path: self.root.join("etc/root-exec.json"),
            secure_path: vec![self.root.join("bin")],
            home: self.root.join("home"),
        }
    }

    fn ctx(&self) -> Context {
        Context::from_env(
            |k| match k {
                "SUDO_USER" => Some("ryan".into()),
                "LANG" => Some("en_US.UTF-8".into()),
                "TERM" => Some("xterm-256color".into()),
                _ => None,
            },
            self.root.join("home"),
            "box",
        )
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn args(words: &[&str]) -> Vec<String> {
    std::iter::once("--")
        .chain(words.iter().copied())
        .map(String::from)
        .collect()
}

fn approve_replies() -> Vec<(u16, String)> {
    vec![
        (202, fixture("created.json").replace("REQUEST-ID", "rid_1")),
        (200, fixture("approved.json")),
    ]
}

fn run(t: &Tree, broker: &MockBroker, words: &[&str]) -> Result<Plan, Failure> {
    t.config(&broker.url);
    prepare(&t.policy(), &args(words), &t.ctx(), |_| {})
}

#[test]
fn an_approved_command_becomes_a_plan_for_the_resolved_file() {
    let t = Tree::new();
    let prog = t.program("svc", "echo hi");
    let broker = MockBroker::start(approve_replies());
    let plan = run(&t, &broker, &["svc", "restart", "web"]).unwrap();
    assert_eq!(plan.program, prog);
    assert_eq!(plan.arg0, prog.to_str().unwrap());
    assert_eq!(plan.args, ["restart", "web"]);
    // the working directory is inherited, never re-entered by path after the approval
    assert_eq!(build_command(&plan).get_current_dir(), None);
    // the human was shown the resolved path, the directory and who asked
    let sent: serde_json::Value = serde_json::from_str(&broker.requests()[0].body).unwrap();
    assert_eq!(sent["mode"], "sudo");
    assert_eq!(
        sent["argv"],
        serde_json::json!([prog.to_str().unwrap(), "restart", "web"])
    );
    assert_eq!(sent["cwd"], t.root.join("home").to_str().unwrap());
    assert_eq!(
        (sent["invoker"].as_str(), sent["source"].as_str()),
        (Some("ryan"), Some("ryan@box"))
    );
    assert_eq!(broker.requests()[0].key.as_deref(), Some("HELPER-KEY"));
}

#[test]
fn a_symlinked_command_is_shown_and_run_as_the_file_it_points_to() {
    let t = Tree::new();
    let real = t.program("real", "true");
    symlink(&real, t.root.join("bin/alias")).unwrap();
    let broker = MockBroker::start(approve_replies());
    let plan = run(&t, &broker, &["alias", "x"]).unwrap();
    assert_eq!(
        (plan.program.as_path(), plan.arg0.as_str()),
        (real.as_path(), real.to_str().unwrap())
    );
    let sent: serde_json::Value = serde_json::from_str(&broker.requests()[0].body).unwrap();
    assert_eq!(
        sent["argv"],
        serde_json::json!([real.to_str().unwrap(), "x"])
    );
}

#[test]
fn a_link_planted_where_the_agent_can_write_cannot_pass_for_something_else() {
    // `./ls` in the (agent-writable) working directory really points at a trusted program: the human
    // is shown that program, never the innocent-looking name.
    let t = Tree::new();
    let rm = t.program("rm", "true");
    symlink(&rm, t.root.join("home/ls")).unwrap();
    let broker = MockBroker::start(approve_replies());
    let plan = run(&t, &broker, &["./ls", "-la"]).unwrap();
    let sent: serde_json::Value = serde_json::from_str(&broker.requests()[0].body).unwrap();
    assert_eq!(sent["argv"][0], rm.to_str().unwrap());
    assert!(!sent["argv"][0].as_str().unwrap().ends_with("/ls"));
    assert_eq!(
        (plan.program, plan.arg0),
        (rm.clone(), rm.to_str().unwrap().to_string())
    );
}

#[test]
fn denial_and_an_unreachable_broker_run_nothing() {
    let t = Tree::new();
    t.program("svc", "true");
    let broker = MockBroker::start(vec![
        (202, fixture("created.json").replace("REQUEST-ID", "rid_1")),
        (200, fixture("denied.json")),
    ]);
    assert_eq!(run(&t, &broker, &["svc"]).unwrap_err().code, 4);
    t.config("http://127.0.0.1:1");
    assert_eq!(
        prepare(&t.policy(), &args(&["svc"]), &t.ctx(), |_| {})
            .unwrap_err()
            .code,
        3
    );
}

#[test]
fn unsafe_things_are_refused_without_ever_asking_the_broker() {
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "program writable by others",
            Box::new(|t| chmod(&t.root.join("bin/svc"), 0o777)),
        ),
        (
            "program writable by group",
            Box::new(|t| chmod(&t.root.join("bin/svc"), 0o775)),
        ),
        (
            "program not executable",
            Box::new(|t| chmod(&t.root.join("bin/svc"), 0o644)),
        ),
        (
            "directory writable by others",
            Box::new(|t| chmod(&t.root.join("bin"), 0o777)),
        ),
        (
            "config readable by group",
            Box::new(|t| chmod(&t.root.join("etc/root-exec.json"), 0o640)),
        ),
        (
            "config readable by others",
            Box::new(|t| chmod(&t.root.join("etc/root-exec.json"), 0o644)),
        ),
        (
            "tree root writable by others",
            Box::new(|t| chmod(&t.root, 0o777)),
        ),
    ];
    for (why, tamper) in cases {
        let t = Tree::new();
        t.program("svc", "true");
        let broker = MockBroker::start(approve_replies());
        t.config(&broker.url);
        tamper(&t);
        let e = prepare(&t.policy(), &args(&["svc"]), &t.ctx(), |_| {}).unwrap_err();
        assert_eq!(e.code, 10, "{why}: {e:?}");
        assert!(
            broker.requests().is_empty(),
            "{why}: the broker was contacted"
        );
    }
}

#[test]
fn a_symlink_out_of_the_trusted_tree_is_refused() {
    let t = Tree::new();
    let outside = Tree::new();
    let target = outside.program("evil", "true");
    symlink(&target, t.root.join("bin/svc")).unwrap();
    let broker = MockBroker::start(approve_replies());
    let e = run(&t, &broker, &["svc"]).unwrap_err();
    assert_eq!(e.code, 10, "{e:?}");
    assert!(broker.requests().is_empty());
}

#[test]
fn names_are_looked_up_only_in_the_secure_path_and_a_missing_one_is_refused() {
    let t = Tree::new();
    let broker = MockBroker::start(approve_replies());
    let e = run(&t, &broker, &["nothing-here"]).unwrap_err();
    assert_eq!(e.code, 10);
    assert!(e.message.contains("secure PATH"), "{}", e.message);
    assert!(broker.requests().is_empty());
}

#[test]
fn usage_errors() {
    let t = Tree::new();
    let broker = MockBroker::start(approve_replies());
    t.config(&broker.url);
    for a in [
        vec![],
        vec!["--".to_string()],
        vec!["svc".to_string()],
        vec!["-x".to_string(), "svc".to_string()],
    ] {
        assert_eq!(
            prepare(&t.policy(), &a, &t.ctx(), |_| {}).unwrap_err().code,
            2,
            "{a:?}"
        );
    }
    assert!(broker.requests().is_empty());
}

#[test]
fn a_command_that_changes_while_waiting_is_not_run() {
    let t = Tree::new();
    let prog = t.program("svc", "true");
    let p2 = prog.clone();
    // while the human decides (the poll), the file becomes writable by others
    let broker = MockBroker::start_hooked(approve_replies(), move |n| {
        if n == 1 {
            chmod(&p2, 0o777);
        }
    });
    let e = run(&t, &broker, &["svc"]).unwrap_err();
    assert_eq!(e.code, 10, "{e:?}");
}

#[test]
fn the_command_runs_with_a_scrubbed_environment() {
    let t = Tree::new();
    // absolute paths: the scrubbed PATH deliberately holds only the secure directories
    t.program("showenv", "/usr/bin/printenv | /usr/bin/sort");
    let broker = MockBroker::start(approve_replies());
    std::env::set_var("ASB_TEST_CANARY", "leaked");
    let plan = run(&t, &broker, &["showenv"]).unwrap();
    let out = build_command(&plan).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.contains("leaked") && !text.contains("ASB_TEST_CANARY"),
        "{text}"
    );
    assert!(!text.contains("HELPER-KEY"), "{text}");
    for want in [
        "USER=root",
        "LOGNAME=root",
        "LANG=en_US.UTF-8",
        "TERM=xterm-256color",
        "SUDO_USER=ryan",
    ] {
        assert!(text.lines().any(|l| l == want), "missing {want} in {text}");
    }
    let path = text.lines().find(|l| l.starts_with("PATH=")).unwrap();
    assert_eq!(path, format!("PATH={}", t.root.join("bin").display()));
}

#[test]
fn context_drops_implausible_caller_values() {
    let get = |k: &str| match k {
        "SUDO_USER" => Some("Bad User; rm".to_string()),
        "LANG" => Some("en_US.UTF-8; rm -rf /".to_string()),
        "TERM" => Some("x".repeat(100)),
        _ => None,
    };
    let c = Context::from_env(get, PathBuf::from("/"), "ho$t\nname");
    assert_eq!((c.invoker, c.lang, c.term), (None, None, None));
    assert_eq!(c.hostname, "hotname");
    assert_eq!(
        Context::from_env(|_| None, PathBuf::from("/"), "\n").hostname,
        "unknown"
    );
}

// ---- script operands: an interpreter runs a file the card does not show --------------------------------
//
// The rule is a strict grammar, not an option parser: `INTERP SCRIPT [ARGS]` with a trusted SCRIPT first, or
// `INTERP -c CODE`; everything else is refused before the broker is asked.

fn script_in_cwd(t: &Tree, name: &str, mode: u32) -> PathBuf {
    let p = t.root.join("home").join(name);
    fs::write(&p, "echo hi\n").unwrap();
    chmod(&p, mode);
    p
}

fn with_interpreters(t: &Tree) {
    for name in [
        "bash",
        "python3",
        "python3.11",
        "perl5.36",
        "ruby",
        "node",
        "php",
        "env",
        "timeout",
        "xargs",
        "cat",
    ] {
        t.program(name, "true");
    }
}

/// Refused locally (exit 10) and the broker never contacted.
fn refused(prepare_files: impl Fn(&Tree), words: &[&str]) -> String {
    let t = Tree::new();
    with_interpreters(&t);
    prepare_files(&t);
    let broker = MockBroker::start(approve_replies());
    let e = run(&t, &broker, words).unwrap_err();
    assert_eq!(e.code, 10, "{words:?}: {e:?}");
    assert!(
        broker.requests().is_empty(),
        "{words:?}: the broker was contacted"
    );
    e.message
}

fn allowed(mut prepare_files: impl FnMut(&Tree), words: &[&str]) -> (Tree, Plan, MockBroker) {
    let t = Tree::new();
    with_interpreters(&t);
    prepare_files(&t);
    let broker = MockBroker::start(approve_replies());
    let plan = run(&t, &broker, words).unwrap_or_else(|e| panic!("{words:?}: {e:?}"));
    (t, plan, broker)
}

#[test]
fn a_script_the_agent_could_rewrite_is_refused() {
    let bad = |t: &Tree| {
        script_in_cwd(t, "deploy.sh", 0o666);
    };
    for words in [
        &["bash", "deploy.sh"][..],
        &["bash", "./deploy.sh", "arg"],
        &["python3.11", "deploy.sh"], // versioned names are recognised
        &["perl5.36", "deploy.sh"],
    ] {
        let msg = refused(bad, words);
        assert!(msg.contains("will not run as root"), "{words:?}: {msg}");
    }
    // by absolute path, and through a symlink to a writable file
    let t = Tree::new();
    with_interpreters(&t);
    let s = script_in_cwd(&t, "deploy.sh", 0o777);
    symlink(&s, t.root.join("home/link.sh")).unwrap();
    for arg in [s.to_str().unwrap(), "link.sh"] {
        let broker = MockBroker::start(approve_replies());
        assert_eq!(
            run(&t, &broker, &["bash", arg]).unwrap_err().code,
            10,
            "{arg}"
        );
        assert!(broker.requests().is_empty());
    }
}

#[test]
fn a_script_the_agent_cannot_write_is_allowed_and_its_args_are_its_own() {
    let (_, plan, broker) = allowed(
        |t| {
            script_in_cwd(t, "good.sh", 0o644);
            script_in_cwd(t, "data.txt", 0o666); // a script argument: the trusted script's business
        },
        &["bash", "good.sh", "data.txt", "-x"],
    );
    assert_eq!(plan.args.len(), 3);
    assert_eq!(&plan.args[1..], ["data.txt", "-x"]);
    assert_eq!(broker.requests().len(), 2);
}

#[test]
fn any_option_before_the_script_is_refused() {
    // each of these changes what the interpreter runs without appearing as a file operand
    let files = |t: &Tree| {
        script_in_cwd(t, "good.sh", 0o644);
        script_in_cwd(t, "evil.sh", 0o666);
    };
    for words in [
        &["bash", "--rcfile", "good.sh", "evil.sh"][..], // a trusted decoy first
        &["bash", "-lc", "echo hi"],                     // clusters are not the exact inline flag
        &["bash", "-s", "good.sh"],                      // reads a program from stdin
        &["bash", "-i", "good.sh"],
        &["python3", "-i", "good.sh"],
        &["python3", "-m", "evil"], // a module found on sys.path, not a shown file
        &["python3", "-u", "good.sh"],
        &["perl5.36", "-Mevil", "good.sh"],
        &["bash", "-h", "evil.sh"],        // `-h` is not "help" in a shell
        &["bash", "--version", "evil.sh"], // a version flag is allowed only on its own
        &["bash", "--norc", "good.sh"],
    ] {
        let msg = refused(files, words);
        assert!(
            msg.contains("refused") || msg.contains("allowed forms"),
            "{words:?}: {msg}"
        );
    }
}

#[test]
fn switches_after_inline_code_are_refused_where_the_interpreter_would_still_parse_them() {
    for words in [
        &["perl5.36", "-e", "print 1", "-MEvil"][..],
        &["perl5.36", "-e", "print 1", "-I/tmp/x"],
        &["ruby", "-e", "puts 1", "-r", "evil"],
        &["node", "-e", "1", "--require", "./evil.js"],
        &["php", "-r", "echo 1;", "-d", "auto_prepend_file=evil"],
    ] {
        let msg = refused(|_| {}, words);
        assert!(msg.contains("after the inline code"), "{words:?}: {msg}");
    }
    assert!(refused(|_| {}, &["bash", "-c"]).contains("no code"));
    // shells and Python take every later word as a plain argument, so these are fine
    for words in [
        &["bash", "-c", "echo $1", "x", "-x"][..],
        &["python3", "-c", "import sys; print(sys.argv)", "-X", "dev"],
        &["perl5.36", "-e", "print 1", "plain", "args"], // later words that are not switches
    ] {
        allowed(|_| {}, words);
    }
}

#[test]
fn stdin_programs_and_missing_scripts_are_refused() {
    for words in [
        &["bash"][..],
        &["python3"],
        &["bash", "-"],
        &["bash", "nope.sh"],
        &["bash", "somedir"],
    ] {
        refused(
            |t| fs::create_dir_all(t.root.join("home/somedir")).unwrap(),
            words,
        );
    }
}

#[test]
fn inline_code_and_a_lone_version_flag_are_allowed() {
    for words in [
        &["bash", "-c", "echo hi"][..],
        &["bash", "-c", "echo $0", "extra"],
        &["python3", "-c", "print(1)"],
        &["perl5.36", "-e", "print 1"],
        &["bash", "--version"],
        &["python3", "--version"],
    ] {
        // a writable script lying in the directory is irrelevant: it is never run
        allowed(
            |t| {
                script_in_cwd(t, "deploy.sh", 0o666);
            },
            words,
        );
    }
}

#[test]
fn wrappers_are_refused_because_they_hide_the_command() {
    let bad = |t: &Tree| {
        script_in_cwd(t, "deploy.sh", 0o666);
    };
    for words in [
        &["env", "bash", "deploy.sh"][..],
        &["env", "-i", "bash", "deploy.sh"],
        &["timeout", "5", "bash", "deploy.sh"],
        &["timeout", "5", "./deploy.sh"],
        &["xargs", "bash"], // xargs builds arguments from stdin
        &["env", "ls"],     // even a harmless one: the check cannot tell
    ] {
        let msg = refused(bad, words);
        assert!(msg.contains("wrapper"), "{words:?}: {msg}");
    }
}

#[test]
fn programs_that_are_not_interpreters_or_wrappers_are_not_checked() {
    allowed(
        |t| {
            script_in_cwd(t, "data.txt", 0o666);
        },
        &["cat", "data.txt"],
    );
}

#[test]
fn the_script_shown_and_run_is_the_resolved_real_file_not_the_link() {
    let mut real = PathBuf::new();
    let (_, plan, broker) = allowed(
        |t| {
            real = fs::canonicalize(script_in_cwd(t, "real.sh", 0o644)).unwrap();
            symlink(&real, t.root.join("home/link.sh")).unwrap();
        },
        &["bash", "link.sh", "arg"],
    );
    let want = real.to_str().unwrap();
    let sent: serde_json::Value = serde_json::from_str(&broker.requests()[0].body).unwrap();
    let sent_args: Vec<&str> = sent["argv"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(sent_args, [want, "arg"]);
    assert_eq!(plan.args, [want, "arg"]);
}

#[test]
fn a_script_link_retargeted_while_waiting_is_not_run() {
    let t = Tree::new();
    with_interpreters(&t);
    script_in_cwd(&t, "a.sh", 0o644);
    script_in_cwd(&t, "b.sh", 0o644);
    let link = t.root.join("home/link.sh");
    symlink(t.root.join("home/a.sh"), &link).unwrap();
    let (l2, b) = (link.clone(), t.root.join("home/b.sh"));
    let broker = MockBroker::start_hooked(approve_replies(), move |n| {
        if n == 1 {
            fs::remove_file(&l2).unwrap();
            symlink(&b, &l2).unwrap();
        }
    });
    let e = run(&t, &broker, &["bash", "link.sh"]).unwrap_err();
    assert_eq!(e.code, 10, "{e:?}");
    assert!(e.message.contains("changed"), "{}", e.message);
}

#[test]
fn a_script_that_becomes_writable_while_waiting_is_not_run() {
    let t = Tree::new();
    with_interpreters(&t);
    let s = script_in_cwd(&t, "deploy.sh", 0o644);
    let s2 = s.clone();
    let broker = MockBroker::start_hooked(approve_replies(), move |n| {
        if n == 1 {
            chmod(&s2, 0o666);
        }
    });
    let e = run(&t, &broker, &["bash", "deploy.sh"]).unwrap_err();
    assert_eq!(e.code, 10, "{e:?}");
}
