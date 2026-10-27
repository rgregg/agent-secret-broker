use asb_client::mock::MockBroker;
use asb_client::{Client, Config, Error};
use asb_proto::SudoRequest;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/sudo/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn req() -> SudoRequest {
    serde_json::from_str(&fixture("request.json")).unwrap()
}

fn run(replies: Vec<(u16, String)>) -> (Result<(), Error>, MockBroker) {
    let broker = MockBroker::start(replies);
    let client = Client::new(Config {
        url: broker.url.clone(),
        key: "KEY-123".into(),
    });
    (client.approve_sudo(&req(), |_| {}), broker)
}

fn created() -> (u16, String) {
    (202, fixture("created.json").replace("REQUEST-ID", "rid_1"))
}

#[test]
fn a_clean_approval_succeeds_and_sends_the_fixture_with_the_key() {
    let (r, broker) = run(vec![created(), (200, fixture("approved.json"))]);
    assert_eq!(r, Ok(()));
    let seen = broker.requests();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/v1/requests")
    );
    let sent: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(
        sent,
        serde_json::from_str::<serde_json::Value>(&fixture("request.json")).unwrap()
    );
    assert_eq!(seen[0].key.as_deref(), Some("KEY-123"));
    let ua = seen[0].user_agent.as_deref().unwrap();
    assert!(
        ua.starts_with("asb-client/") && !ua.contains("ureq"),
        "{ua}"
    );
    assert_eq!(seen[1].path, "/v1/requests/rid_1?wait=25");
}

#[test]
fn pending_polls_continue_until_the_answer() {
    let pending = (200, r#"{"status":"pending","error":null}"#.to_string());
    let (r, _) = run(vec![
        created(),
        pending.clone(),
        pending,
        (200, fixture("approved.json")),
    ]);
    assert_eq!(r, Ok(()));
}

#[test]
fn denial_expiry_and_failure_are_errors_with_their_own_exit_codes() {
    let (r, _) = run(vec![created(), (200, fixture("denied.json"))]);
    assert_eq!(r, Err(Error::Denied));
    assert_eq!(Error::Denied.exit_code(), 4);
    let (r, _) = run(vec![
        created(),
        (200, r#"{"status":"expired","error":null}"#.into()),
    ]);
    assert_eq!(r, Err(Error::Expired));
    let (r, _) = run(vec![
        created(),
        (200, r#"{"status":"failed","error":"boom\u001b[1m"}"#.into()),
    ]);
    assert_eq!(r, Err(Error::Failed("boom?[1m".into())));
}

#[test]
fn anything_but_a_flagged_approval_fails_closed() {
    // approved with no flag
    let (r, _) = run(vec![created(), (200, r#"{"status":"approved"}"#.into())]);
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
    // already collected by someone else
    let (r, _) = run(vec![created(), (200, fixture("released.json"))]);
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
    // a status we do not know
    let (r, _) = run(vec![created(), (200, r#"{"status":"maybe"}"#.into())]);
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
    // junk
    let (r, _) = run(vec![created(), (200, "not json".into())]);
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
}

#[test]
fn a_refused_create_reports_the_brokers_reason_cleaned() {
    let (r, broker) = run(vec![(
        403,
        r#"{"error":"sudo requests are disabled\u001b[2J"}"#.into(),
    )]);
    assert_eq!(
        r,
        Err(Error::Refused {
            status: 403,
            message: "sudo requests are disabled?[2J".into()
        })
    );
    assert_eq!(broker.requests().len(), 1);
}

#[test]
fn a_hostile_request_id_is_rejected_before_it_reaches_a_path() {
    let (r, broker) = run(vec![(
        202,
        r#"{"id":"../../admin","status":"pending","error":null,"expires_in":300}"#.into(),
    )]);
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
    assert_eq!(broker.requests().len(), 1);
}

#[test]
fn an_unreachable_broker_is_an_error() {
    let client = Client::new(Config {
        url: "http://127.0.0.1:1".into(),
        key: "k".into(),
    });
    assert!(matches!(
        client.approve_sudo(&req(), |_| {}),
        Err(Error::Unreachable(_))
    ));
}
