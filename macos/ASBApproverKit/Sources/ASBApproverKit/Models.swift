import Foundation

// The broker's approver API, as `secret_broker/approver_api.py` emits it. Keys are snake_case on
// the wire; decode with `JSONDecoder.approverAPI()` (`.convertFromSnakeCase`).

extension JSONDecoder {
    /// A decoder for broker and identity-provider JSON: snake_case keys become camelCase.
    /// Note: this also rewrites the keys of free-form objects (`PendingRequest.details`).
    public static func approverAPI() -> JSONDecoder {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }
}

/// `GET /v1/approver/config`: `{"issuer", "client_id", "scopes", "api_version"}`.
public struct ApproverConfig: Codable, Equatable, Sendable {
    public var issuer: URL
    public var clientId: String
    public var scopes: [String]
    public var apiVersion: Int

    public init(issuer: URL, clientId: String, scopes: [String], apiVersion: Int) {
        self.issuer = issuer
        self.clientId = clientId
        self.scopes = scopes
        self.apiVersion = apiVersion
    }
}

/// A decision the app may offer and send. On the wire (a request's `actions` and `banner_actions`)
/// these are the action ids `approve`, `deny`, `grant:<minutes>`, `always` and `always_script`.
public enum Decision: Hashable, Sendable, Codable {
    case approve
    case deny
    case grant(minutes: Int)
    case always
    case alwaysScript

    /// Parses an action id; nil for anything this version does not know.
    public init?(actionID: String) {
        switch actionID {
        case "approve": self = .approve
        case "deny": self = .deny
        case "always": self = .always
        case "always_script": self = .alwaysScript
        default:
            let prefix = "grant:"
            guard actionID.hasPrefix(prefix) else { return nil }
            let rest = actionID.dropFirst(prefix.count)
            guard !rest.isEmpty, rest.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let minutes = Int(rest), minutes > 0 else { return nil }
            self = .grant(minutes: minutes)
        }
    }

    /// The wire action id.
    public var actionID: String {
        switch self {
        case .approve: return "approve"
        case .deny: return "deny"
        case .grant(let minutes): return "grant:\(minutes)"
        case .always: return "always"
        case .alwaysScript: return "always_script"
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let raw = try c.decode(String.self)
        guard let d = Decision(actionID: raw) else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "unknown action id")
        }
        self = d
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(actionID)
    }
}

/// `POST /v1/approver/decide` outcome. Statuses other than these throw (`APIError`).
public enum DecideResult: Equatable, Sendable {
    case ok             // 200
    case alreadyDecided // 410: decided elsewhere (phone, dashboard) or expired
    case notFound       // 404: unknown id
    case refused        // 400: malformed, or an action that request does not offer
}

/// Any JSON value (for the free-form `details` view).
public enum JSONValue: Codable, Equatable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? c.decode(Double.self) {
            self = .number(n)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else if let o = try? c.decode([String: JSONValue].self) {
            self = .object(o)
        } else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "not a JSON value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }
}

/// One pending request as `request_view` builds it. Every text field is attacker-influenced:
/// the broker strips control characters and caps lengths, and the app must show it as plain
/// `Text` only (never Markdown, attributed or HTML).
public struct PendingRequest: Codable, Identifiable, Equatable, Sendable {
    public struct Client: Codable, Equatable, Sendable {
        public var name: String?
        public var id: String?

        public init(name: String?, id: String?) {
            self.name = name
            self.id = id
        }
    }

    public struct Risk: Codable, Equatable, Sendable {
        public var level: String?
        public var reasons: [String]

        public init(level: String?, reasons: [String]) {
            self.level = level
            self.reasons = reasons
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            level = try c.decodeIfPresent(String.self, forKey: .level)
            reasons = try c.decodeIfPresent([String].self, forKey: .reasons) ?? []
        }
    }

    public var id: String
    public var mode: String
    /// Unix seconds.
    public var created: Double
    /// Unix seconds.
    public var expires: Double
    public var credentials: [String]
    public var client: Client
    public var summary: String?
    /// `"model"`, `"deterministic"` or nil.
    public var summarySource: String?
    public var risk: Risk?
    /// What the dashboard shows: method and URL, host, or argv.
    public var target: String?
    /// The masked request-details view, or nil. Free-form; its object keys went through
    /// `.convertFromSnakeCase` like everything else (e.g. `headers_total` -> `headersTotal`).
    public var details: JSONValue?
    /// True once a human is really being asked (the moment to post a banner).
    public var notified: Bool
    /// The actions the banner offered (unknown ids are dropped).
    public var bannerActions: [Decision]
    /// The decisions the app may offer, in the broker's order (unknown ids are dropped).
    public var actions: [Decision]
    public var browserUrl: URL?

    enum CodingKeys: String, CodingKey {
        case id, mode, created, expires, credentials, client, summary, summarySource, risk, target,
             details, notified, bannerActions, actions, browserUrl
    }

    public init(id: String, mode: String, created: Double, expires: Double, credentials: [String],
                client: Client, summary: String? = nil, summarySource: String? = nil, risk: Risk? = nil,
                target: String? = nil, details: JSONValue? = nil, notified: Bool = false,
                bannerActions: [Decision] = [], actions: [Decision] = [.deny], browserUrl: URL? = nil) {
        self.id = id
        self.mode = mode
        self.created = created
        self.expires = expires
        self.credentials = credentials
        self.client = client
        self.summary = summary
        self.summarySource = summarySource
        self.risk = risk
        self.target = target
        self.details = details
        self.notified = notified
        self.bannerActions = bannerActions
        self.actions = actions
        self.browserUrl = browserUrl
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        mode = try c.decode(String.self, forKey: .mode)
        created = try c.decode(Double.self, forKey: .created)
        expires = try c.decode(Double.self, forKey: .expires)
        credentials = try c.decodeIfPresent([String].self, forKey: .credentials) ?? []
        client = try c.decodeIfPresent(Client.self, forKey: .client) ?? Client(name: nil, id: nil)
        summary = try c.decodeIfPresent(String.self, forKey: .summary)
        summarySource = try c.decodeIfPresent(String.self, forKey: .summarySource)
        risk = try c.decodeIfPresent(Risk.self, forKey: .risk)
        target = try c.decodeIfPresent(String.self, forKey: .target)
        details = try c.decodeIfPresent(JSONValue.self, forKey: .details)
        notified = try c.decodeIfPresent(Bool.self, forKey: .notified) ?? false
        // Lossy: an action id a newer broker adds is skipped, not a decoding failure.
        bannerActions = (try c.decodeIfPresent([String].self, forKey: .bannerActions) ?? [])
            .compactMap(Decision.init(actionID:))
        actions = (try c.decodeIfPresent([String].self, forKey: .actions) ?? [])
            .compactMap(Decision.init(actionID:))
        browserUrl = try c.decodeIfPresent(URL.self, forKey: .browserUrl)
    }

    public var createdDate: Date { Date(timeIntervalSince1970: created) }
    public var expiresDate: Date { Date(timeIntervalSince1970: expires) }
}

/// `GET /v1/approver/pending`: `{"version": n, "requests": [...]}`, oldest first.
public struct PendingPage: Codable, Equatable, Sendable {
    public var version: Int
    public var requests: [PendingRequest]
    /// The response's `Retry-After` (seconds), when the broker asked the app to back off before
    /// polling again (the long-poll waiter cap). Not part of the JSON body.
    public var retryAfter: TimeInterval?

    enum CodingKeys: String, CodingKey {
        case version, requests
    }

    public init(version: Int, requests: [PendingRequest], retryAfter: TimeInterval? = nil) {
        self.version = version
        self.requests = requests
        self.retryAfter = retryAfter
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        requests = try c.decode([PendingRequest].self, forKey: .requests)
        retryAfter = nil
    }
}
