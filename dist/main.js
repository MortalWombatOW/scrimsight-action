import xs from "fs";
import Ut from "os";
import or from "http";
import Wg from "https";
import Ei from "net";
import jg from "tls";
import nr from "events";
import Me from "assert";
import LA from "util";
import lt from "stream";
import Gt from "buffer";
import xu from "querystring";
import ct from "stream/web";
import Js from "node:stream";
import ir from "node:util";
import $g from "node:events";
import Kg from "worker_threads";
import Ju from "perf_hooks";
import zg from "util/types";
import Vr from "async_hooks";
import Hu from "console";
import Vu from "url";
import qu from "zlib";
import Zg from "string_decoder";
import Xg from "diagnostics_channel";
import Wu from "crypto";
import qr from "path";
import ju from "child_process";
import $u from "timers";
var O = typeof globalThis < "u" ? globalThis : typeof window < "u" ? window : typeof global < "u" ? global : typeof self < "u" ? self : {};
function el(e) {
  return e && e.__esModule && Object.prototype.hasOwnProperty.call(e, "default") ? e.default : e;
}
function ui(e) {
  if (e.__esModule) return e;
  var A = e.default;
  if (typeof A == "function") {
    var t = function r() {
      return this instanceof r ? Reflect.construct(A, arguments, this.constructor) : A.apply(this, arguments);
    };
    t.prototype = A.prototype;
  } else t = {};
  return Object.defineProperty(t, "__esModule", { value: !0 }), Object.keys(e).forEach(function(r) {
    var s = Object.getOwnPropertyDescriptor(e, r);
    Object.defineProperty(t, r, s.get ? s : {
      enumerable: !0,
      get: function() {
        return e[r];
      }
    });
  }), t;
}
var Or = {}, Wr = {};
Object.defineProperty(Wr, "__esModule", { value: !0 });
Wr.Context = void 0;
const xi = xs, Ku = Ut;
let zu = class {
  /**
   * Hydrate the context from the environment
   */
  constructor() {
    var A, t, r;
    if (this.payload = {}, process.env.GITHUB_EVENT_PATH)
      if ((0, xi.existsSync)(process.env.GITHUB_EVENT_PATH))
        this.payload = JSON.parse((0, xi.readFileSync)(process.env.GITHUB_EVENT_PATH, { encoding: "utf8" }));
      else {
        const s = process.env.GITHUB_EVENT_PATH;
        process.stdout.write(`GITHUB_EVENT_PATH ${s} does not exist${Ku.EOL}`);
      }
    this.eventName = process.env.GITHUB_EVENT_NAME, this.sha = process.env.GITHUB_SHA, this.ref = process.env.GITHUB_REF, this.workflow = process.env.GITHUB_WORKFLOW, this.action = process.env.GITHUB_ACTION, this.actor = process.env.GITHUB_ACTOR, this.job = process.env.GITHUB_JOB, this.runNumber = parseInt(process.env.GITHUB_RUN_NUMBER, 10), this.runId = parseInt(process.env.GITHUB_RUN_ID, 10), this.apiUrl = (A = process.env.GITHUB_API_URL) !== null && A !== void 0 ? A : "https://api.github.com", this.serverUrl = (t = process.env.GITHUB_SERVER_URL) !== null && t !== void 0 ? t : "https://github.com", this.graphqlUrl = (r = process.env.GITHUB_GRAPHQL_URL) !== null && r !== void 0 ? r : "https://api.github.com/graphql";
  }
  get issue() {
    const A = this.payload;
    return Object.assign(Object.assign({}, this.repo), { number: (A.issue || A.pull_request || A).number });
  }
  get repo() {
    if (process.env.GITHUB_REPOSITORY) {
      const [A, t] = process.env.GITHUB_REPOSITORY.split("/");
      return { owner: A, repo: t };
    }
    if (this.payload.repository)
      return {
        owner: this.payload.repository.owner.login,
        repo: this.payload.repository.name
      };
    throw new Error("context.repo requires a GITHUB_REPOSITORY environment variable like 'owner/repo'");
  }
};
Wr.Context = zu;
var Al = {}, mA = {}, We = {}, Zt = {};
Object.defineProperty(Zt, "__esModule", { value: !0 });
Zt.checkBypass = Zt.getProxyUrl = void 0;
function Zu(e) {
  const A = e.protocol === "https:";
  if (tl(e))
    return;
  const t = A ? process.env.https_proxy || process.env.HTTPS_PROXY : process.env.http_proxy || process.env.HTTP_PROXY;
  if (t)
    try {
      return new Ji(t);
    } catch {
      if (!t.startsWith("http://") && !t.startsWith("https://"))
        return new Ji(`http://${t}`);
    }
  else
    return;
}
Zt.getProxyUrl = Zu;
function tl(e) {
  if (!e.hostname)
    return !1;
  const A = e.hostname;
  if (Xu(A))
    return !0;
  const t = process.env.no_proxy || process.env.NO_PROXY || "";
  if (!t)
    return !1;
  let r;
  e.port ? r = Number(e.port) : e.protocol === "http:" ? r = 80 : e.protocol === "https:" && (r = 443);
  const s = [e.hostname.toUpperCase()];
  typeof r == "number" && s.push(`${s[0]}:${r}`);
  for (const o of t.split(",").map((n) => n.trim().toUpperCase()).filter((n) => n))
    if (o === "*" || s.some((n) => n === o || n.endsWith(`.${o}`) || o.startsWith(".") && n.endsWith(`${o}`)))
      return !0;
  return !1;
}
Zt.checkBypass = tl;
function Xu(e) {
  const A = e.toLowerCase();
  return A === "localhost" || A.startsWith("127.") || A.startsWith("[::1]") || A.startsWith("[0:0:0:0:0:0:0:1]");
}
class Ji extends URL {
  constructor(A, t) {
    super(A, t), this._decodedUsername = decodeURIComponent(super.username), this._decodedPassword = decodeURIComponent(super.password);
  }
  get username() {
    return this._decodedUsername;
  }
  get password() {
    return this._decodedPassword;
  }
}
var ar = {}, eh = jg, hi = or, rl = Wg, Ah = nr, th = LA;
ar.httpOverHttp = rh;
ar.httpsOverHttp = sh;
ar.httpOverHttps = oh;
ar.httpsOverHttps = nh;
function rh(e) {
  var A = new WA(e);
  return A.request = hi.request, A;
}
function sh(e) {
  var A = new WA(e);
  return A.request = hi.request, A.createSocket = sl, A.defaultPort = 443, A;
}
function oh(e) {
  var A = new WA(e);
  return A.request = rl.request, A;
}
function nh(e) {
  var A = new WA(e);
  return A.request = rl.request, A.createSocket = sl, A.defaultPort = 443, A;
}
function WA(e) {
  var A = this;
  A.options = e || {}, A.proxyOptions = A.options.proxy || {}, A.maxSockets = A.options.maxSockets || hi.Agent.defaultMaxSockets, A.requests = [], A.sockets = [], A.on("free", function(r, s, o, n) {
    for (var i = ol(s, o, n), a = 0, g = A.requests.length; a < g; ++a) {
      var c = A.requests[a];
      if (c.host === i.host && c.port === i.port) {
        A.requests.splice(a, 1), c.request.onSocket(r);
        return;
      }
    }
    r.destroy(), A.removeSocket(r);
  });
}
th.inherits(WA, Ah.EventEmitter);
WA.prototype.addRequest = function(A, t, r, s) {
  var o = this, n = di({ request: A }, o.options, ol(t, r, s));
  if (o.sockets.length >= this.maxSockets) {
    o.requests.push(n);
    return;
  }
  o.createSocket(n, function(i) {
    i.on("free", a), i.on("close", g), i.on("agentRemove", g), A.onSocket(i);
    function a() {
      o.emit("free", i, n);
    }
    function g(c) {
      o.removeSocket(i), i.removeListener("free", a), i.removeListener("close", g), i.removeListener("agentRemove", g);
    }
  });
};
WA.prototype.createSocket = function(A, t) {
  var r = this, s = {};
  r.sockets.push(s);
  var o = di({}, r.proxyOptions, {
    method: "CONNECT",
    path: A.host + ":" + A.port,
    agent: !1,
    headers: {
      host: A.host + ":" + A.port
    }
  });
  A.localAddress && (o.localAddress = A.localAddress), o.proxyAuth && (o.headers = o.headers || {}, o.headers["Proxy-Authorization"] = "Basic " + new Buffer(o.proxyAuth).toString("base64")), tt("making CONNECT request");
  var n = r.request(o);
  n.useChunkedEncodingByDefault = !1, n.once("response", i), n.once("upgrade", a), n.once("connect", g), n.once("error", c), n.end();
  function i(E) {
    E.upgrade = !0;
  }
  function a(E, l, Q) {
    process.nextTick(function() {
      g(E, l, Q);
    });
  }
  function g(E, l, Q) {
    if (n.removeAllListeners(), l.removeAllListeners(), E.statusCode !== 200) {
      tt(
        "tunneling socket could not be established, statusCode=%d",
        E.statusCode
      ), l.destroy();
      var I = new Error("tunneling socket could not be established, statusCode=" + E.statusCode);
      I.code = "ECONNRESET", A.request.emit("error", I), r.removeSocket(s);
      return;
    }
    if (Q.length > 0) {
      tt("got illegal response body from proxy"), l.destroy();
      var I = new Error("got illegal response body from proxy");
      I.code = "ECONNRESET", A.request.emit("error", I), r.removeSocket(s);
      return;
    }
    return tt("tunneling connection has established"), r.sockets[r.sockets.indexOf(s)] = l, t(l);
  }
  function c(E) {
    n.removeAllListeners(), tt(
      `tunneling socket could not be established, cause=%s
`,
      E.message,
      E.stack
    );
    var l = new Error("tunneling socket could not be established, cause=" + E.message);
    l.code = "ECONNRESET", A.request.emit("error", l), r.removeSocket(s);
  }
};
WA.prototype.removeSocket = function(A) {
  var t = this.sockets.indexOf(A);
  if (t !== -1) {
    this.sockets.splice(t, 1);
    var r = this.requests.shift();
    r && this.createSocket(r, function(s) {
      r.request.onSocket(s);
    });
  }
};
function sl(e, A) {
  var t = this;
  WA.prototype.createSocket.call(t, e, function(r) {
    var s = e.request.getHeader("host"), o = di({}, t.options, {
      socket: r,
      servername: s ? s.replace(/:.*$/, "") : e.host
    }), n = eh.connect(0, o);
    t.sockets[t.sockets.indexOf(r)] = n, A(n);
  });
}
function ol(e, A, t) {
  return typeof e == "string" ? {
    host: e,
    port: A,
    localAddress: t
  } : e;
}
function di(e) {
  for (var A = 1, t = arguments.length; A < t; ++A) {
    var r = arguments[A];
    if (typeof r == "object")
      for (var s = Object.keys(r), o = 0, n = s.length; o < n; ++o) {
        var i = s[o];
        r[i] !== void 0 && (e[i] = r[i]);
      }
  }
  return e;
}
var tt;
process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG) ? tt = function() {
  var e = Array.prototype.slice.call(arguments);
  typeof e[0] == "string" ? e[0] = "TUNNEL: " + e[0] : e.unshift("TUNNEL:"), console.error.apply(console, e);
} : tt = function() {
};
ar.debug = tt;
var ih = ar, he = {}, Se = {
  kClose: Symbol("close"),
  kDestroy: Symbol("destroy"),
  kDispatch: Symbol("dispatch"),
  kUrl: Symbol("url"),
  kWriting: Symbol("writing"),
  kResuming: Symbol("resuming"),
  kQueue: Symbol("queue"),
  kConnect: Symbol("connect"),
  kConnecting: Symbol("connecting"),
  kHeadersList: Symbol("headers list"),
  kKeepAliveDefaultTimeout: Symbol("default keep alive timeout"),
  kKeepAliveMaxTimeout: Symbol("max keep alive timeout"),
  kKeepAliveTimeoutThreshold: Symbol("keep alive timeout threshold"),
  kKeepAliveTimeoutValue: Symbol("keep alive timeout"),
  kHeadersTimeout: Symbol("headers timeout"),
  kBodyTimeout: Symbol("body timeout"),
  kServerName: Symbol("server name"),
  kLocalAddress: Symbol("local address"),
  kHost: Symbol("host"),
  kNoRef: Symbol("no ref"),
  kBodyUsed: Symbol("used"),
  kRunning: Symbol("running"),
  kBlocking: Symbol("blocking"),
  kPending: Symbol("pending"),
  kSize: Symbol("size"),
  kBusy: Symbol("busy"),
  kQueued: Symbol("queued"),
  kFree: Symbol("free"),
  kConnected: Symbol("connected"),
  kNeedDrain: Symbol("need drain"),
  kReset: Symbol("reset"),
  kDestroyed: Symbol.for("nodejs.stream.destroyed"),
  kMaxHeadersSize: Symbol("max headers size"),
  kRunningIdx: Symbol("running index"),
  kPendingIdx: Symbol("pending index"),
  kError: Symbol("error"),
  kClients: Symbol("clients"),
  kClient: Symbol("client"),
  kParser: Symbol("parser"),
  kPipelining: Symbol("pipelining"),
  kSocket: Symbol("socket"),
  kHostHeader: Symbol("host header"),
  kConnector: Symbol("connector"),
  kStrictContentLength: Symbol("strict content length"),
  kMaxRedirections: Symbol("maxRedirections"),
  kMaxRequests: Symbol("maxRequestsPerClient"),
  kProxy: Symbol("proxy agent options"),
  kCounter: Symbol("socket request counter"),
  kInterceptors: Symbol("dispatch interceptors"),
  kMaxResponseSize: Symbol("max response size"),
  kHTTP2Session: Symbol("http2Session"),
  kHTTP2SessionState: Symbol("http2Session state"),
  kHTTP2BuildRequest: Symbol("http2 build request"),
  kHTTP1BuildRequest: Symbol("http1 build request"),
  kHTTP2CopyHeaders: Symbol("http2 copy headers"),
  kHTTPConnVersion: Symbol("http connection version"),
  kRetryHandlerDefaultRetry: Symbol("retry agent default retry"),
  kConstruct: Symbol("constructable")
};
let je = class extends Error {
  constructor(A) {
    super(A), this.name = "UndiciError", this.code = "UND_ERR";
  }
}, ah = class nl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, nl), this.name = "ConnectTimeoutError", this.message = A || "Connect Timeout Error", this.code = "UND_ERR_CONNECT_TIMEOUT";
  }
}, ch = class il extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, il), this.name = "HeadersTimeoutError", this.message = A || "Headers Timeout Error", this.code = "UND_ERR_HEADERS_TIMEOUT";
  }
}, gh = class al extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, al), this.name = "HeadersOverflowError", this.message = A || "Headers Overflow Error", this.code = "UND_ERR_HEADERS_OVERFLOW";
  }
}, lh = class cl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, cl), this.name = "BodyTimeoutError", this.message = A || "Body Timeout Error", this.code = "UND_ERR_BODY_TIMEOUT";
  }
}, Eh = class gl extends je {
  constructor(A, t, r, s) {
    super(A), Error.captureStackTrace(this, gl), this.name = "ResponseStatusCodeError", this.message = A || "Response Status Code Error", this.code = "UND_ERR_RESPONSE_STATUS_CODE", this.body = s, this.status = t, this.statusCode = t, this.headers = r;
  }
}, uh = class ll extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, ll), this.name = "InvalidArgumentError", this.message = A || "Invalid Argument Error", this.code = "UND_ERR_INVALID_ARG";
  }
}, hh = class El extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, El), this.name = "InvalidReturnValueError", this.message = A || "Invalid Return Value Error", this.code = "UND_ERR_INVALID_RETURN_VALUE";
  }
}, dh = class ul extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, ul), this.name = "AbortError", this.message = A || "Request aborted", this.code = "UND_ERR_ABORTED";
  }
}, Qh = class hl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, hl), this.name = "InformationalError", this.message = A || "Request information", this.code = "UND_ERR_INFO";
  }
}, Ch = class dl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, dl), this.name = "RequestContentLengthMismatchError", this.message = A || "Request body length does not match content-length header", this.code = "UND_ERR_REQ_CONTENT_LENGTH_MISMATCH";
  }
}, Bh = class Ql extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, Ql), this.name = "ResponseContentLengthMismatchError", this.message = A || "Response body length does not match content-length header", this.code = "UND_ERR_RES_CONTENT_LENGTH_MISMATCH";
  }
}, Ih = class Cl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, Cl), this.name = "ClientDestroyedError", this.message = A || "The client is destroyed", this.code = "UND_ERR_DESTROYED";
  }
}, ph = class Bl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, Bl), this.name = "ClientClosedError", this.message = A || "The client is closed", this.code = "UND_ERR_CLOSED";
  }
}, fh = class Il extends je {
  constructor(A, t) {
    super(A), Error.captureStackTrace(this, Il), this.name = "SocketError", this.message = A || "Socket error", this.code = "UND_ERR_SOCKET", this.socket = t;
  }
}, pl = class fl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, fl), this.name = "NotSupportedError", this.message = A || "Not supported error", this.code = "UND_ERR_NOT_SUPPORTED";
  }
}, mh = class extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, pl), this.name = "MissingUpstreamError", this.message = A || "No upstream has been added to the BalancedPool", this.code = "UND_ERR_BPL_MISSING_UPSTREAM";
  }
}, wh = class ml extends Error {
  constructor(A, t, r) {
    super(A), Error.captureStackTrace(this, ml), this.name = "HTTPParserError", this.code = t ? `HPE_${t}` : void 0, this.data = r ? r.toString() : void 0;
  }
}, yh = class wl extends je {
  constructor(A) {
    super(A), Error.captureStackTrace(this, wl), this.name = "ResponseExceededMaxSizeError", this.message = A || "Response content exceeded max size", this.code = "UND_ERR_RES_EXCEEDED_MAX_SIZE";
  }
}, bh = class yl extends je {
  constructor(A, t, { headers: r, data: s }) {
    super(A), Error.captureStackTrace(this, yl), this.name = "RequestRetryError", this.message = A || "Request retry error", this.code = "UND_ERR_REQ_RETRY", this.statusCode = t, this.data = s, this.headers = r;
  }
};
var Re = {
  HTTPParserError: wh,
  UndiciError: je,
  HeadersTimeoutError: ch,
  HeadersOverflowError: gh,
  BodyTimeoutError: lh,
  RequestContentLengthMismatchError: Ch,
  ConnectTimeoutError: ah,
  ResponseStatusCodeError: Eh,
  InvalidArgumentError: uh,
  InvalidReturnValueError: hh,
  RequestAbortedError: dh,
  ClientDestroyedError: Ih,
  ClientClosedError: ph,
  InformationalError: Qh,
  SocketError: fh,
  NotSupportedError: pl,
  ResponseContentLengthMismatchError: Bh,
  BalancedPoolMissingUpstreamError: mh,
  ResponseExceededMaxSizeError: yh,
  RequestRetryError: bh
};
const Ns = {}, Hi = [
  "Accept",
  "Accept-Encoding",
  "Accept-Language",
  "Accept-Ranges",
  "Access-Control-Allow-Credentials",
  "Access-Control-Allow-Headers",
  "Access-Control-Allow-Methods",
  "Access-Control-Allow-Origin",
  "Access-Control-Expose-Headers",
  "Access-Control-Max-Age",
  "Access-Control-Request-Headers",
  "Access-Control-Request-Method",
  "Age",
  "Allow",
  "Alt-Svc",
  "Alt-Used",
  "Authorization",
  "Cache-Control",
  "Clear-Site-Data",
  "Connection",
  "Content-Disposition",
  "Content-Encoding",
  "Content-Language",
  "Content-Length",
  "Content-Location",
  "Content-Range",
  "Content-Security-Policy",
  "Content-Security-Policy-Report-Only",
  "Content-Type",
  "Cookie",
  "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Date",
  "Device-Memory",
  "Downlink",
  "ECT",
  "ETag",
  "Expect",
  "Expect-CT",
  "Expires",
  "Forwarded",
  "From",
  "Host",
  "If-Match",
  "If-Modified-Since",
  "If-None-Match",
  "If-Range",
  "If-Unmodified-Since",
  "Keep-Alive",
  "Last-Modified",
  "Link",
  "Location",
  "Max-Forwards",
  "Origin",
  "Permissions-Policy",
  "Pragma",
  "Proxy-Authenticate",
  "Proxy-Authorization",
  "RTT",
  "Range",
  "Referer",
  "Referrer-Policy",
  "Refresh",
  "Retry-After",
  "Sec-WebSocket-Accept",
  "Sec-WebSocket-Extensions",
  "Sec-WebSocket-Key",
  "Sec-WebSocket-Protocol",
  "Sec-WebSocket-Version",
  "Server",
  "Server-Timing",
  "Service-Worker-Allowed",
  "Service-Worker-Navigation-Preload",
  "Set-Cookie",
  "SourceMap",
  "Strict-Transport-Security",
  "Supports-Loading-Mode",
  "TE",
  "Timing-Allow-Origin",
  "Trailer",
  "Transfer-Encoding",
  "Upgrade",
  "Upgrade-Insecure-Requests",
  "User-Agent",
  "Vary",
  "Via",
  "WWW-Authenticate",
  "X-Content-Type-Options",
  "X-DNS-Prefetch-Control",
  "X-Frame-Options",
  "X-Permitted-Cross-Domain-Policies",
  "X-Powered-By",
  "X-Requested-With",
  "X-XSS-Protection"
];
for (let e = 0; e < Hi.length; ++e) {
  const A = Hi[e], t = A.toLowerCase();
  Ns[A] = Ns[t] = t;
}
Object.setPrototypeOf(Ns, null);
var Rh = {
  headerNameLowerCasedRecord: Ns
};
const bl = Me, { kDestroyed: Rl, kBodyUsed: Vi } = Se, { IncomingMessage: Dh } = or, Xt = lt, Th = Ei, { InvalidArgumentError: ze } = Re, { Blob: qi } = Gt, vs = LA, { stringify: kh } = xu, { headerNameLowerCasedRecord: Fh } = Rh, [ao, Wi] = process.versions.node.split(".").map((e) => Number(e));
function Sh() {
}
function Qi(e) {
  return e && typeof e == "object" && typeof e.pipe == "function" && typeof e.on == "function";
}
function Dl(e) {
  return qi && e instanceof qi || e && typeof e == "object" && (typeof e.stream == "function" || typeof e.arrayBuffer == "function") && /^(Blob|File)$/.test(e[Symbol.toStringTag]);
}
function Uh(e, A) {
  if (e.includes("?") || e.includes("#"))
    throw new Error('Query params cannot be passed when url already contains "?" or "#".');
  const t = kh(A);
  return t && (e += "?" + t), e;
}
function Tl(e) {
  if (typeof e == "string") {
    if (e = new URL(e), !/^https?:/.test(e.origin || e.protocol))
      throw new ze("Invalid URL protocol: the URL must start with `http:` or `https:`.");
    return e;
  }
  if (!e || typeof e != "object")
    throw new ze("Invalid URL: The URL argument must be a non-null object.");
  if (!/^https?:/.test(e.origin || e.protocol))
    throw new ze("Invalid URL protocol: the URL must start with `http:` or `https:`.");
  if (!(e instanceof URL)) {
    if (e.port != null && e.port !== "" && !Number.isFinite(parseInt(e.port)))
      throw new ze("Invalid URL: port must be a valid integer or a string representation of an integer.");
    if (e.path != null && typeof e.path != "string")
      throw new ze("Invalid URL path: the path must be a string or null/undefined.");
    if (e.pathname != null && typeof e.pathname != "string")
      throw new ze("Invalid URL pathname: the pathname must be a string or null/undefined.");
    if (e.hostname != null && typeof e.hostname != "string")
      throw new ze("Invalid URL hostname: the hostname must be a string or null/undefined.");
    if (e.origin != null && typeof e.origin != "string")
      throw new ze("Invalid URL origin: the origin must be a string or null/undefined.");
    const A = e.port != null ? e.port : e.protocol === "https:" ? 443 : 80;
    let t = e.origin != null ? e.origin : `${e.protocol}//${e.hostname}:${A}`, r = e.path != null ? e.path : `${e.pathname || ""}${e.search || ""}`;
    t.endsWith("/") && (t = t.substring(0, t.length - 1)), r && !r.startsWith("/") && (r = `/${r}`), e = new URL(t + r);
  }
  return e;
}
function Gh(e) {
  if (e = Tl(e), e.pathname !== "/" || e.search || e.hash)
    throw new ze("invalid url");
  return e;
}
function _h(e) {
  if (e[0] === "[") {
    const t = e.indexOf("]");
    return bl(t !== -1), e.substring(1, t);
  }
  const A = e.indexOf(":");
  return A === -1 ? e : e.substring(0, A);
}
function Nh(e) {
  if (!e)
    return null;
  bl.strictEqual(typeof e, "string");
  const A = _h(e);
  return Th.isIP(A) ? "" : A;
}
function vh(e) {
  return JSON.parse(JSON.stringify(e));
}
function Lh(e) {
  return e != null && typeof e[Symbol.asyncIterator] == "function";
}
function Mh(e) {
  return e != null && (typeof e[Symbol.iterator] == "function" || typeof e[Symbol.asyncIterator] == "function");
}
function Oh(e) {
  if (e == null)
    return 0;
  if (Qi(e)) {
    const A = e._readableState;
    return A && A.objectMode === !1 && A.ended === !0 && Number.isFinite(A.length) ? A.length : null;
  } else {
    if (Dl(e))
      return e.size != null ? e.size : null;
    if (Fl(e))
      return e.byteLength;
  }
  return null;
}
function Ci(e) {
  return !e || !!(e.destroyed || e[Rl]);
}
function kl(e) {
  const A = e && e._readableState;
  return Ci(e) && A && !A.endEmitted;
}
function Ph(e, A) {
  e == null || !Qi(e) || Ci(e) || (typeof e.destroy == "function" ? (Object.getPrototypeOf(e).constructor === Dh && (e.socket = null), e.destroy(A)) : A && process.nextTick((t, r) => {
    t.emit("error", r);
  }, e, A), e.destroyed !== !0 && (e[Rl] = !0));
}
const Yh = /timeout=(\d+)/;
function xh(e) {
  const A = e.toString().match(Yh);
  return A ? parseInt(A[1], 10) * 1e3 : null;
}
function Jh(e) {
  return Fh[e] || e.toLowerCase();
}
function Hh(e, A = {}) {
  if (!Array.isArray(e)) return e;
  for (let t = 0; t < e.length; t += 2) {
    const r = e[t].toString().toLowerCase();
    let s = A[r];
    s ? (Array.isArray(s) || (s = [s], A[r] = s), s.push(e[t + 1].toString("utf8"))) : Array.isArray(e[t + 1]) ? A[r] = e[t + 1].map((o) => o.toString("utf8")) : A[r] = e[t + 1].toString("utf8");
  }
  return "content-length" in A && "content-disposition" in A && (A["content-disposition"] = Buffer.from(A["content-disposition"]).toString("latin1")), A;
}
function Vh(e) {
  const A = [];
  let t = !1, r = -1;
  for (let s = 0; s < e.length; s += 2) {
    const o = e[s + 0].toString(), n = e[s + 1].toString("utf8");
    o.length === 14 && (o === "content-length" || o.toLowerCase() === "content-length") ? (A.push(o, n), t = !0) : o.length === 19 && (o === "content-disposition" || o.toLowerCase() === "content-disposition") ? r = A.push(o, n) - 1 : A.push(o, n);
  }
  return t && r !== -1 && (A[r] = Buffer.from(A[r]).toString("latin1")), A;
}
function Fl(e) {
  return e instanceof Uint8Array || Buffer.isBuffer(e);
}
function qh(e, A, t) {
  if (!e || typeof e != "object")
    throw new ze("handler must be an object");
  if (typeof e.onConnect != "function")
    throw new ze("invalid onConnect method");
  if (typeof e.onError != "function")
    throw new ze("invalid onError method");
  if (typeof e.onBodySent != "function" && e.onBodySent !== void 0)
    throw new ze("invalid onBodySent method");
  if (t || A === "CONNECT") {
    if (typeof e.onUpgrade != "function")
      throw new ze("invalid onUpgrade method");
  } else {
    if (typeof e.onHeaders != "function")
      throw new ze("invalid onHeaders method");
    if (typeof e.onData != "function")
      throw new ze("invalid onData method");
    if (typeof e.onComplete != "function")
      throw new ze("invalid onComplete method");
  }
}
function Wh(e) {
  return !!(e && (Xt.isDisturbed ? Xt.isDisturbed(e) || e[Vi] : e[Vi] || e.readableDidRead || e._readableState && e._readableState.dataEmitted || kl(e)));
}
function jh(e) {
  return !!(e && (Xt.isErrored ? Xt.isErrored(e) : /state: 'errored'/.test(
    vs.inspect(e)
  )));
}
function $h(e) {
  return !!(e && (Xt.isReadable ? Xt.isReadable(e) : /state: 'readable'/.test(
    vs.inspect(e)
  )));
}
function Kh(e) {
  return {
    localAddress: e.localAddress,
    localPort: e.localPort,
    remoteAddress: e.remoteAddress,
    remotePort: e.remotePort,
    remoteFamily: e.remoteFamily,
    timeout: e.timeout,
    bytesWritten: e.bytesWritten,
    bytesRead: e.bytesRead
  };
}
async function* zh(e) {
  for await (const A of e)
    yield Buffer.isBuffer(A) ? A : Buffer.from(A);
}
let Qr;
function Zh(e) {
  if (Qr || (Qr = ct.ReadableStream), Qr.from)
    return Qr.from(zh(e));
  let A;
  return new Qr(
    {
      async start() {
        A = e[Symbol.asyncIterator]();
      },
      async pull(t) {
        const { done: r, value: s } = await A.next();
        if (r)
          queueMicrotask(() => {
            t.close();
          });
        else {
          const o = Buffer.isBuffer(s) ? s : Buffer.from(s);
          t.enqueue(new Uint8Array(o));
        }
        return t.desiredSize > 0;
      },
      async cancel(t) {
        await A.return();
      }
    },
    0
  );
}
function Xh(e) {
  return e && typeof e == "object" && typeof e.append == "function" && typeof e.delete == "function" && typeof e.get == "function" && typeof e.getAll == "function" && typeof e.has == "function" && typeof e.set == "function" && e[Symbol.toStringTag] === "FormData";
}
function ed(e) {
  if (e) {
    if (typeof e.throwIfAborted == "function")
      e.throwIfAborted();
    else if (e.aborted) {
      const A = new Error("The operation was aborted");
      throw A.name = "AbortError", A;
    }
  }
}
function Ad(e, A) {
  return "addEventListener" in e ? (e.addEventListener("abort", A, { once: !0 }), () => e.removeEventListener("abort", A)) : (e.addListener("abort", A), () => e.removeListener("abort", A));
}
const td = !!String.prototype.toWellFormed;
function rd(e) {
  return td ? `${e}`.toWellFormed() : vs.toUSVString ? vs.toUSVString(e) : `${e}`;
}
function sd(e) {
  if (e == null || e === "") return { start: 0, end: null, size: null };
  const A = e ? e.match(/^bytes (\d+)-(\d+)\/(\d+)?$/) : null;
  return A ? {
    start: parseInt(A[1]),
    end: A[2] ? parseInt(A[2]) : null,
    size: A[3] ? parseInt(A[3]) : null
  } : null;
}
const Sl = /* @__PURE__ */ Object.create(null);
Sl.enumerable = !0;
var we = {
  kEnumerableProperty: Sl,
  nop: Sh,
  isDisturbed: Wh,
  isErrored: jh,
  isReadable: $h,
  toUSVString: rd,
  isReadableAborted: kl,
  isBlobLike: Dl,
  parseOrigin: Gh,
  parseURL: Tl,
  getServerName: Nh,
  isStream: Qi,
  isIterable: Mh,
  isAsyncIterable: Lh,
  isDestroyed: Ci,
  headerNameToString: Jh,
  parseRawHeaders: Vh,
  parseHeaders: Hh,
  parseKeepAliveTimeout: xh,
  destroy: Ph,
  bodyLength: Oh,
  deepClone: vh,
  ReadableStreamFrom: Zh,
  isBuffer: Fl,
  validateHandler: qh,
  getSocketInfo: Kh,
  isFormDataLike: Xh,
  buildURL: Uh,
  throwIfAborted: ed,
  addAbortListener: Ad,
  parseRangeHeader: sd,
  nodeMajor: ao,
  nodeMinor: Wi,
  nodeHasAutoSelectFamily: ao > 18 || ao === 18 && Wi >= 13,
  safeHTTPMethods: ["GET", "HEAD", "OPTIONS", "TRACE"]
};
let co = Date.now(), XA;
const et = [];
function od() {
  co = Date.now();
  let e = et.length, A = 0;
  for (; A < e; ) {
    const t = et[A];
    t.state === 0 ? t.state = co + t.delay : t.state > 0 && co >= t.state && (t.state = -1, t.callback(t.opaque)), t.state === -1 ? (t.state = -2, A !== e - 1 ? et[A] = et.pop() : et.pop(), e -= 1) : A += 1;
  }
  et.length > 0 && Ul();
}
function Ul() {
  XA && XA.refresh ? XA.refresh() : (clearTimeout(XA), XA = setTimeout(od, 1e3), XA.unref && XA.unref());
}
class ji {
  constructor(A, t, r) {
    this.callback = A, this.delay = t, this.opaque = r, this.state = -2, this.refresh();
  }
  refresh() {
    this.state === -2 && (et.push(this), (!XA || et.length === 1) && Ul()), this.state = 0;
  }
  clear() {
    this.state = -1;
  }
}
var nd = {
  setTimeout(e, A, t) {
    return A < 1e3 ? setTimeout(e, A, t) : new ji(e, A, t);
  },
  clearTimeout(e) {
    e instanceof ji ? e.clear() : clearTimeout(e);
  }
}, Lt = { exports: {} }, go, $i;
function Gl() {
  if ($i) return go;
  $i = 1;
  const e = $g.EventEmitter, A = ir.inherits;
  function t(r) {
    if (typeof r == "string" && (r = Buffer.from(r)), !Buffer.isBuffer(r))
      throw new TypeError("The needle has to be a String or a Buffer.");
    const s = r.length;
    if (s === 0)
      throw new Error("The needle cannot be an empty String/Buffer.");
    if (s > 256)
      throw new Error("The needle cannot have a length bigger than 256.");
    this.maxMatches = 1 / 0, this.matches = 0, this._occ = new Array(256).fill(s), this._lookbehind_size = 0, this._needle = r, this._bufpos = 0, this._lookbehind = Buffer.alloc(s);
    for (var o = 0; o < s - 1; ++o)
      this._occ[r[o]] = s - 1 - o;
  }
  return A(t, e), t.prototype.reset = function() {
    this._lookbehind_size = 0, this.matches = 0, this._bufpos = 0;
  }, t.prototype.push = function(r, s) {
    Buffer.isBuffer(r) || (r = Buffer.from(r, "binary"));
    const o = r.length;
    this._bufpos = s || 0;
    let n;
    for (; n !== o && this.matches < this.maxMatches; )
      n = this._sbmh_feed(r);
    return n;
  }, t.prototype._sbmh_feed = function(r) {
    const s = r.length, o = this._needle, n = o.length, i = o[n - 1];
    let a = -this._lookbehind_size, g;
    if (a < 0) {
      for (; a < 0 && a <= s - n; ) {
        if (g = this._sbmh_lookup_char(r, a + n - 1), g === i && this._sbmh_memcmp(r, a, n - 1))
          return this._lookbehind_size = 0, ++this.matches, this.emit("info", !0), this._bufpos = a + n;
        a += this._occ[g];
      }
      if (a < 0)
        for (; a < 0 && !this._sbmh_memcmp(r, a, s - a); )
          ++a;
      if (a >= 0)
        this.emit("info", !1, this._lookbehind, 0, this._lookbehind_size), this._lookbehind_size = 0;
      else {
        const c = this._lookbehind_size + a;
        return c > 0 && this.emit("info", !1, this._lookbehind, 0, c), this._lookbehind.copy(
          this._lookbehind,
          0,
          c,
          this._lookbehind_size - c
        ), this._lookbehind_size -= c, r.copy(this._lookbehind, this._lookbehind_size), this._lookbehind_size += s, this._bufpos = s, s;
      }
    }
    if (a += (a >= 0) * this._bufpos, r.indexOf(o, a) !== -1)
      return a = r.indexOf(o, a), ++this.matches, a > 0 ? this.emit("info", !0, r, this._bufpos, a) : this.emit("info", !0), this._bufpos = a + n;
    for (a = s - n; a < s && (r[a] !== o[0] || Buffer.compare(
      r.subarray(a, a + s - a),
      o.subarray(0, s - a)
    ) !== 0); )
      ++a;
    return a < s && (r.copy(this._lookbehind, 0, a, a + (s - a)), this._lookbehind_size = s - a), a > 0 && this.emit("info", !1, r, this._bufpos, a < s ? a : s), this._bufpos = s, s;
  }, t.prototype._sbmh_lookup_char = function(r, s) {
    return s < 0 ? this._lookbehind[this._lookbehind_size + s] : r[s];
  }, t.prototype._sbmh_memcmp = function(r, s, o) {
    for (var n = 0; n < o; ++n)
      if (this._sbmh_lookup_char(r, s + n) !== this._needle[n])
        return !1;
    return !0;
  }, go = t, go;
}
var lo, Ki;
function id() {
  if (Ki) return lo;
  Ki = 1;
  const e = ir.inherits, A = Js.Readable;
  function t(r) {
    A.call(this, r);
  }
  return e(t, A), t.prototype._read = function(r) {
  }, lo = t, lo;
}
var Eo, zi;
function Bi() {
  return zi || (zi = 1, Eo = function(A, t, r) {
    if (!A || A[t] === void 0 || A[t] === null)
      return r;
    if (typeof A[t] != "number" || isNaN(A[t]))
      throw new TypeError("Limit " + t + " is not a valid number");
    return A[t];
  }), Eo;
}
var uo, Zi;
function ad() {
  if (Zi) return uo;
  Zi = 1;
  const e = $g.EventEmitter, A = ir.inherits, t = Bi(), r = Gl(), s = Buffer.from(`\r
\r
`), o = /\r\n/g, n = /^([^:]+):[ \t]?([\x00-\xFF]+)?$/;
  function i(a) {
    e.call(this), a = a || {};
    const g = this;
    this.nread = 0, this.maxed = !1, this.npairs = 0, this.maxHeaderPairs = t(a, "maxHeaderPairs", 2e3), this.maxHeaderSize = t(a, "maxHeaderSize", 80 * 1024), this.buffer = "", this.header = {}, this.finished = !1, this.ss = new r(s), this.ss.on("info", function(c, E, l, Q) {
      E && !g.maxed && (g.nread + Q - l >= g.maxHeaderSize ? (Q = g.maxHeaderSize - g.nread + l, g.nread = g.maxHeaderSize, g.maxed = !0) : g.nread += Q - l, g.buffer += E.toString("binary", l, Q)), c && g._finish();
    });
  }
  return A(i, e), i.prototype.push = function(a) {
    const g = this.ss.push(a);
    if (this.finished)
      return g;
  }, i.prototype.reset = function() {
    this.finished = !1, this.buffer = "", this.header = {}, this.ss.reset();
  }, i.prototype._finish = function() {
    this.buffer && this._parseHeader(), this.ss.matches = this.ss.maxMatches;
    const a = this.header;
    this.header = {}, this.buffer = "", this.finished = !0, this.nread = this.npairs = 0, this.maxed = !1, this.emit("header", a);
  }, i.prototype._parseHeader = function() {
    if (this.npairs === this.maxHeaderPairs)
      return;
    const a = this.buffer.split(o), g = a.length;
    let c, E;
    for (var l = 0; l < g; ++l) {
      if (a[l].length === 0)
        continue;
      if ((a[l][0] === "	" || a[l][0] === " ") && E) {
        this.header[E][this.header[E].length - 1] += a[l];
        continue;
      }
      const Q = a[l].indexOf(":");
      if (Q === -1 || Q === 0)
        return;
      if (c = n.exec(a[l]), E = c[1].toLowerCase(), this.header[E] = this.header[E] || [], this.header[E].push(c[2] || ""), ++this.npairs === this.maxHeaderPairs)
        break;
    }
  }, uo = i, uo;
}
var ho, Xi;
function _l() {
  if (Xi) return ho;
  Xi = 1;
  const e = Js.Writable, A = ir.inherits, t = Gl(), r = id(), s = ad(), o = 45, n = Buffer.from("-"), i = Buffer.from(`\r
`), a = function() {
  };
  function g(c) {
    if (!(this instanceof g))
      return new g(c);
    if (e.call(this, c), !c || !c.headerFirst && typeof c.boundary != "string")
      throw new TypeError("Boundary required");
    typeof c.boundary == "string" ? this.setBoundary(c.boundary) : this._bparser = void 0, this._headerFirst = c.headerFirst, this._dashes = 0, this._parts = 0, this._finished = !1, this._realFinish = !1, this._isPreamble = !0, this._justMatched = !1, this._firstWrite = !0, this._inHeader = !0, this._part = void 0, this._cb = void 0, this._ignoreData = !1, this._partOpts = { highWaterMark: c.partHwm }, this._pause = !1;
    const E = this;
    this._hparser = new s(c), this._hparser.on("header", function(l) {
      E._inHeader = !1, E._part.emit("header", l);
    });
  }
  return A(g, e), g.prototype.emit = function(c) {
    if (c === "finish" && !this._realFinish) {
      if (!this._finished) {
        const E = this;
        process.nextTick(function() {
          if (E.emit("error", new Error("Unexpected end of multipart data")), E._part && !E._ignoreData) {
            const l = E._isPreamble ? "Preamble" : "Part";
            E._part.emit("error", new Error(l + " terminated early due to unexpected end of multipart data")), E._part.push(null), process.nextTick(function() {
              E._realFinish = !0, E.emit("finish"), E._realFinish = !1;
            });
            return;
          }
          E._realFinish = !0, E.emit("finish"), E._realFinish = !1;
        });
      }
    } else
      e.prototype.emit.apply(this, arguments);
  }, g.prototype._write = function(c, E, l) {
    if (!this._hparser && !this._bparser)
      return l();
    if (this._headerFirst && this._isPreamble) {
      this._part || (this._part = new r(this._partOpts), this.listenerCount("preamble") !== 0 ? this.emit("preamble", this._part) : this._ignore());
      const Q = this._hparser.push(c);
      if (!this._inHeader && Q !== void 0 && Q < c.length)
        c = c.slice(Q);
      else
        return l();
    }
    this._firstWrite && (this._bparser.push(i), this._firstWrite = !1), this._bparser.push(c), this._pause ? this._cb = l : l();
  }, g.prototype.reset = function() {
    this._part = void 0, this._bparser = void 0, this._hparser = void 0;
  }, g.prototype.setBoundary = function(c) {
    const E = this;
    this._bparser = new t(`\r
--` + c), this._bparser.on("info", function(l, Q, I, d) {
      E._oninfo(l, Q, I, d);
    });
  }, g.prototype._ignore = function() {
    this._part && !this._ignoreData && (this._ignoreData = !0, this._part.on("error", a), this._part.resume());
  }, g.prototype._oninfo = function(c, E, l, Q) {
    let I;
    const d = this;
    let h = 0, C, u = !0;
    if (!this._part && this._justMatched && E) {
      for (; this._dashes < 2 && l + h < Q; )
        if (E[l + h] === o)
          ++h, ++this._dashes;
        else {
          this._dashes && (I = n), this._dashes = 0;
          break;
        }
      if (this._dashes === 2 && (l + h < Q && this.listenerCount("trailer") !== 0 && this.emit("trailer", E.slice(l + h, Q)), this.reset(), this._finished = !0, d._parts === 0 && (d._realFinish = !0, d.emit("finish"), d._realFinish = !1)), this._dashes)
        return;
    }
    this._justMatched && (this._justMatched = !1), this._part || (this._part = new r(this._partOpts), this._part._read = function(B) {
      d._unpause();
    }, this._isPreamble && this.listenerCount("preamble") !== 0 ? this.emit("preamble", this._part) : this._isPreamble !== !0 && this.listenerCount("part") !== 0 ? this.emit("part", this._part) : this._ignore(), this._isPreamble || (this._inHeader = !0)), E && l < Q && !this._ignoreData && (this._isPreamble || !this._inHeader ? (I && (u = this._part.push(I)), u = this._part.push(E.slice(l, Q)), u || (this._pause = !0)) : !this._isPreamble && this._inHeader && (I && this._hparser.push(I), C = this._hparser.push(E.slice(l, Q)), !this._inHeader && C !== void 0 && C < Q && this._oninfo(!1, E, l + C, Q))), c && (this._hparser.reset(), this._isPreamble ? this._isPreamble = !1 : l !== Q && (++this._parts, this._part.on("end", function() {
      --d._parts === 0 && (d._finished ? (d._realFinish = !0, d.emit("finish"), d._realFinish = !1) : d._unpause());
    })), this._part.push(null), this._part = void 0, this._ignoreData = !1, this._justMatched = !0, this._dashes = 0);
  }, g.prototype._unpause = function() {
    if (this._pause && (this._pause = !1, this._cb)) {
      const c = this._cb;
      this._cb = void 0, c();
    }
  }, ho = g, ho;
}
var Qo, ea;
function Ii() {
  if (ea) return Qo;
  ea = 1;
  const e = new TextDecoder("utf-8"), A = /* @__PURE__ */ new Map([
    ["utf-8", e],
    ["utf8", e]
  ]);
  function t(o) {
    let n;
    for (; ; )
      switch (o) {
        case "utf-8":
        case "utf8":
          return r.utf8;
        case "latin1":
        case "ascii":
        case "us-ascii":
        case "iso-8859-1":
        case "iso8859-1":
        case "iso88591":
        case "iso_8859-1":
        case "windows-1252":
        case "iso_8859-1:1987":
        case "cp1252":
        case "x-cp1252":
          return r.latin1;
        case "utf16le":
        case "utf-16le":
        case "ucs2":
        case "ucs-2":
          return r.utf16le;
        case "base64":
          return r.base64;
        default:
          if (n === void 0) {
            n = !0, o = o.toLowerCase();
            continue;
          }
          return r.other.bind(o);
      }
  }
  const r = {
    utf8: (o, n) => o.length === 0 ? "" : (typeof o == "string" && (o = Buffer.from(o, n)), o.utf8Slice(0, o.length)),
    latin1: (o, n) => o.length === 0 ? "" : typeof o == "string" ? o : o.latin1Slice(0, o.length),
    utf16le: (o, n) => o.length === 0 ? "" : (typeof o == "string" && (o = Buffer.from(o, n)), o.ucs2Slice(0, o.length)),
    base64: (o, n) => o.length === 0 ? "" : (typeof o == "string" && (o = Buffer.from(o, n)), o.base64Slice(0, o.length)),
    other: (o, n) => {
      if (o.length === 0)
        return "";
      if (typeof o == "string" && (o = Buffer.from(o, n)), A.has(this.toString()))
        try {
          return A.get(this).decode(o);
        } catch {
        }
      return typeof o == "string" ? o : o.toString();
    }
  };
  function s(o, n, i) {
    return o && t(i)(o, n);
  }
  return Qo = s, Qo;
}
var Co, Aa;
function Nl() {
  if (Aa) return Co;
  Aa = 1;
  const e = Ii(), A = /%[a-fA-F0-9][a-fA-F0-9]/g, t = {
    "%00": "\0",
    "%01": "",
    "%02": "",
    "%03": "",
    "%04": "",
    "%05": "",
    "%06": "",
    "%07": "\x07",
    "%08": "\b",
    "%09": "	",
    "%0a": `
`,
    "%0A": `
`,
    "%0b": "\v",
    "%0B": "\v",
    "%0c": "\f",
    "%0C": "\f",
    "%0d": "\r",
    "%0D": "\r",
    "%0e": "",
    "%0E": "",
    "%0f": "",
    "%0F": "",
    "%10": "",
    "%11": "",
    "%12": "",
    "%13": "",
    "%14": "",
    "%15": "",
    "%16": "",
    "%17": "",
    "%18": "",
    "%19": "",
    "%1a": "",
    "%1A": "",
    "%1b": "\x1B",
    "%1B": "\x1B",
    "%1c": "",
    "%1C": "",
    "%1d": "",
    "%1D": "",
    "%1e": "",
    "%1E": "",
    "%1f": "",
    "%1F": "",
    "%20": " ",
    "%21": "!",
    "%22": '"',
    "%23": "#",
    "%24": "$",
    "%25": "%",
    "%26": "&",
    "%27": "'",
    "%28": "(",
    "%29": ")",
    "%2a": "*",
    "%2A": "*",
    "%2b": "+",
    "%2B": "+",
    "%2c": ",",
    "%2C": ",",
    "%2d": "-",
    "%2D": "-",
    "%2e": ".",
    "%2E": ".",
    "%2f": "/",
    "%2F": "/",
    "%30": "0",
    "%31": "1",
    "%32": "2",
    "%33": "3",
    "%34": "4",
    "%35": "5",
    "%36": "6",
    "%37": "7",
    "%38": "8",
    "%39": "9",
    "%3a": ":",
    "%3A": ":",
    "%3b": ";",
    "%3B": ";",
    "%3c": "<",
    "%3C": "<",
    "%3d": "=",
    "%3D": "=",
    "%3e": ">",
    "%3E": ">",
    "%3f": "?",
    "%3F": "?",
    "%40": "@",
    "%41": "A",
    "%42": "B",
    "%43": "C",
    "%44": "D",
    "%45": "E",
    "%46": "F",
    "%47": "G",
    "%48": "H",
    "%49": "I",
    "%4a": "J",
    "%4A": "J",
    "%4b": "K",
    "%4B": "K",
    "%4c": "L",
    "%4C": "L",
    "%4d": "M",
    "%4D": "M",
    "%4e": "N",
    "%4E": "N",
    "%4f": "O",
    "%4F": "O",
    "%50": "P",
    "%51": "Q",
    "%52": "R",
    "%53": "S",
    "%54": "T",
    "%55": "U",
    "%56": "V",
    "%57": "W",
    "%58": "X",
    "%59": "Y",
    "%5a": "Z",
    "%5A": "Z",
    "%5b": "[",
    "%5B": "[",
    "%5c": "\\",
    "%5C": "\\",
    "%5d": "]",
    "%5D": "]",
    "%5e": "^",
    "%5E": "^",
    "%5f": "_",
    "%5F": "_",
    "%60": "`",
    "%61": "a",
    "%62": "b",
    "%63": "c",
    "%64": "d",
    "%65": "e",
    "%66": "f",
    "%67": "g",
    "%68": "h",
    "%69": "i",
    "%6a": "j",
    "%6A": "j",
    "%6b": "k",
    "%6B": "k",
    "%6c": "l",
    "%6C": "l",
    "%6d": "m",
    "%6D": "m",
    "%6e": "n",
    "%6E": "n",
    "%6f": "o",
    "%6F": "o",
    "%70": "p",
    "%71": "q",
    "%72": "r",
    "%73": "s",
    "%74": "t",
    "%75": "u",
    "%76": "v",
    "%77": "w",
    "%78": "x",
    "%79": "y",
    "%7a": "z",
    "%7A": "z",
    "%7b": "{",
    "%7B": "{",
    "%7c": "|",
    "%7C": "|",
    "%7d": "}",
    "%7D": "}",
    "%7e": "~",
    "%7E": "~",
    "%7f": "",
    "%7F": "",
    "%80": "",
    "%81": "",
    "%82": "",
    "%83": "",
    "%84": "",
    "%85": "",
    "%86": "",
    "%87": "",
    "%88": "",
    "%89": "",
    "%8a": "",
    "%8A": "",
    "%8b": "",
    "%8B": "",
    "%8c": "",
    "%8C": "",
    "%8d": "",
    "%8D": "",
    "%8e": "",
    "%8E": "",
    "%8f": "",
    "%8F": "",
    "%90": "",
    "%91": "",
    "%92": "",
    "%93": "",
    "%94": "",
    "%95": "",
    "%96": "",
    "%97": "",
    "%98": "",
    "%99": "",
    "%9a": "",
    "%9A": "",
    "%9b": "",
    "%9B": "",
    "%9c": "",
    "%9C": "",
    "%9d": "",
    "%9D": "",
    "%9e": "",
    "%9E": "",
    "%9f": "",
    "%9F": "",
    "%a0": " ",
    "%A0": " ",
    "%a1": "¡",
    "%A1": "¡",
    "%a2": "¢",
    "%A2": "¢",
    "%a3": "£",
    "%A3": "£",
    "%a4": "¤",
    "%A4": "¤",
    "%a5": "¥",
    "%A5": "¥",
    "%a6": "¦",
    "%A6": "¦",
    "%a7": "§",
    "%A7": "§",
    "%a8": "¨",
    "%A8": "¨",
    "%a9": "©",
    "%A9": "©",
    "%aa": "ª",
    "%Aa": "ª",
    "%aA": "ª",
    "%AA": "ª",
    "%ab": "«",
    "%Ab": "«",
    "%aB": "«",
    "%AB": "«",
    "%ac": "¬",
    "%Ac": "¬",
    "%aC": "¬",
    "%AC": "¬",
    "%ad": "­",
    "%Ad": "­",
    "%aD": "­",
    "%AD": "­",
    "%ae": "®",
    "%Ae": "®",
    "%aE": "®",
    "%AE": "®",
    "%af": "¯",
    "%Af": "¯",
    "%aF": "¯",
    "%AF": "¯",
    "%b0": "°",
    "%B0": "°",
    "%b1": "±",
    "%B1": "±",
    "%b2": "²",
    "%B2": "²",
    "%b3": "³",
    "%B3": "³",
    "%b4": "´",
    "%B4": "´",
    "%b5": "µ",
    "%B5": "µ",
    "%b6": "¶",
    "%B6": "¶",
    "%b7": "·",
    "%B7": "·",
    "%b8": "¸",
    "%B8": "¸",
    "%b9": "¹",
    "%B9": "¹",
    "%ba": "º",
    "%Ba": "º",
    "%bA": "º",
    "%BA": "º",
    "%bb": "»",
    "%Bb": "»",
    "%bB": "»",
    "%BB": "»",
    "%bc": "¼",
    "%Bc": "¼",
    "%bC": "¼",
    "%BC": "¼",
    "%bd": "½",
    "%Bd": "½",
    "%bD": "½",
    "%BD": "½",
    "%be": "¾",
    "%Be": "¾",
    "%bE": "¾",
    "%BE": "¾",
    "%bf": "¿",
    "%Bf": "¿",
    "%bF": "¿",
    "%BF": "¿",
    "%c0": "À",
    "%C0": "À",
    "%c1": "Á",
    "%C1": "Á",
    "%c2": "Â",
    "%C2": "Â",
    "%c3": "Ã",
    "%C3": "Ã",
    "%c4": "Ä",
    "%C4": "Ä",
    "%c5": "Å",
    "%C5": "Å",
    "%c6": "Æ",
    "%C6": "Æ",
    "%c7": "Ç",
    "%C7": "Ç",
    "%c8": "È",
    "%C8": "È",
    "%c9": "É",
    "%C9": "É",
    "%ca": "Ê",
    "%Ca": "Ê",
    "%cA": "Ê",
    "%CA": "Ê",
    "%cb": "Ë",
    "%Cb": "Ë",
    "%cB": "Ë",
    "%CB": "Ë",
    "%cc": "Ì",
    "%Cc": "Ì",
    "%cC": "Ì",
    "%CC": "Ì",
    "%cd": "Í",
    "%Cd": "Í",
    "%cD": "Í",
    "%CD": "Í",
    "%ce": "Î",
    "%Ce": "Î",
    "%cE": "Î",
    "%CE": "Î",
    "%cf": "Ï",
    "%Cf": "Ï",
    "%cF": "Ï",
    "%CF": "Ï",
    "%d0": "Ð",
    "%D0": "Ð",
    "%d1": "Ñ",
    "%D1": "Ñ",
    "%d2": "Ò",
    "%D2": "Ò",
    "%d3": "Ó",
    "%D3": "Ó",
    "%d4": "Ô",
    "%D4": "Ô",
    "%d5": "Õ",
    "%D5": "Õ",
    "%d6": "Ö",
    "%D6": "Ö",
    "%d7": "×",
    "%D7": "×",
    "%d8": "Ø",
    "%D8": "Ø",
    "%d9": "Ù",
    "%D9": "Ù",
    "%da": "Ú",
    "%Da": "Ú",
    "%dA": "Ú",
    "%DA": "Ú",
    "%db": "Û",
    "%Db": "Û",
    "%dB": "Û",
    "%DB": "Û",
    "%dc": "Ü",
    "%Dc": "Ü",
    "%dC": "Ü",
    "%DC": "Ü",
    "%dd": "Ý",
    "%Dd": "Ý",
    "%dD": "Ý",
    "%DD": "Ý",
    "%de": "Þ",
    "%De": "Þ",
    "%dE": "Þ",
    "%DE": "Þ",
    "%df": "ß",
    "%Df": "ß",
    "%dF": "ß",
    "%DF": "ß",
    "%e0": "à",
    "%E0": "à",
    "%e1": "á",
    "%E1": "á",
    "%e2": "â",
    "%E2": "â",
    "%e3": "ã",
    "%E3": "ã",
    "%e4": "ä",
    "%E4": "ä",
    "%e5": "å",
    "%E5": "å",
    "%e6": "æ",
    "%E6": "æ",
    "%e7": "ç",
    "%E7": "ç",
    "%e8": "è",
    "%E8": "è",
    "%e9": "é",
    "%E9": "é",
    "%ea": "ê",
    "%Ea": "ê",
    "%eA": "ê",
    "%EA": "ê",
    "%eb": "ë",
    "%Eb": "ë",
    "%eB": "ë",
    "%EB": "ë",
    "%ec": "ì",
    "%Ec": "ì",
    "%eC": "ì",
    "%EC": "ì",
    "%ed": "í",
    "%Ed": "í",
    "%eD": "í",
    "%ED": "í",
    "%ee": "î",
    "%Ee": "î",
    "%eE": "î",
    "%EE": "î",
    "%ef": "ï",
    "%Ef": "ï",
    "%eF": "ï",
    "%EF": "ï",
    "%f0": "ð",
    "%F0": "ð",
    "%f1": "ñ",
    "%F1": "ñ",
    "%f2": "ò",
    "%F2": "ò",
    "%f3": "ó",
    "%F3": "ó",
    "%f4": "ô",
    "%F4": "ô",
    "%f5": "õ",
    "%F5": "õ",
    "%f6": "ö",
    "%F6": "ö",
    "%f7": "÷",
    "%F7": "÷",
    "%f8": "ø",
    "%F8": "ø",
    "%f9": "ù",
    "%F9": "ù",
    "%fa": "ú",
    "%Fa": "ú",
    "%fA": "ú",
    "%FA": "ú",
    "%fb": "û",
    "%Fb": "û",
    "%fB": "û",
    "%FB": "û",
    "%fc": "ü",
    "%Fc": "ü",
    "%fC": "ü",
    "%FC": "ü",
    "%fd": "ý",
    "%Fd": "ý",
    "%fD": "ý",
    "%FD": "ý",
    "%fe": "þ",
    "%Fe": "þ",
    "%fE": "þ",
    "%FE": "þ",
    "%ff": "ÿ",
    "%Ff": "ÿ",
    "%fF": "ÿ",
    "%FF": "ÿ"
  };
  function r(g) {
    return t[g];
  }
  const s = 0, o = 1, n = 2, i = 3;
  function a(g) {
    const c = [];
    let E = s, l = "", Q = !1, I = !1, d = 0, h = "";
    const C = g.length;
    for (var u = 0; u < C; ++u) {
      const B = g[u];
      if (B === "\\" && Q)
        if (I)
          I = !1;
        else {
          I = !0;
          continue;
        }
      else if (B === '"')
        if (I)
          I = !1;
        else {
          Q ? (Q = !1, E = s) : Q = !0;
          continue;
        }
      else if (I && Q && (h += "\\"), I = !1, (E === n || E === i) && B === "'") {
        E === n ? (E = i, l = h.substring(1)) : E = o, h = "";
        continue;
      } else if (E === s && (B === "*" || B === "=") && c.length) {
        E = B === "*" ? n : o, c[d] = [h, void 0], h = "";
        continue;
      } else if (!Q && B === ";") {
        E = s, l ? (h.length && (h = e(
          h.replace(A, r),
          "binary",
          l
        )), l = "") : h.length && (h = e(h, "binary", "utf8")), c[d] === void 0 ? c[d] = h : c[d][1] = h, h = "", ++d;
        continue;
      } else if (!Q && (B === " " || B === "	"))
        continue;
      h += B;
    }
    return l && h.length ? h = e(
      h.replace(A, r),
      "binary",
      l
    ) : h && (h = e(h, "binary", "utf8")), c[d] === void 0 ? h && (c[d] = h) : c[d][1] = h, c;
  }
  return Co = a, Co;
}
var Bo, ta;
function cd() {
  return ta || (ta = 1, Bo = function(A) {
    if (typeof A != "string")
      return "";
    for (var t = A.length - 1; t >= 0; --t)
      switch (A.charCodeAt(t)) {
        case 47:
        case 92:
          return A = A.slice(t + 1), A === ".." || A === "." ? "" : A;
      }
    return A === ".." || A === "." ? "" : A;
  }), Bo;
}
var Io, ra;
function gd() {
  if (ra) return Io;
  ra = 1;
  const { Readable: e } = Js, { inherits: A } = ir, t = _l(), r = Nl(), s = Ii(), o = cd(), n = Bi(), i = /^boundary$/i, a = /^form-data$/i, g = /^charset$/i, c = /^filename$/i, E = /^name$/i;
  l.detect = /^multipart\/form-data/i;
  function l(d, h) {
    let C, u;
    const B = this;
    let m;
    const f = h.limits, y = h.isPartAFile || (($, X, z) => X === "application/octet-stream" || z !== void 0), b = h.parsedConType || [], w = h.defCharset || "utf8", S = h.preservePath, v = { highWaterMark: h.fileHwm };
    for (C = 0, u = b.length; C < u; ++C)
      if (Array.isArray(b[C]) && i.test(b[C][0])) {
        m = b[C][1];
        break;
      }
    function N() {
      Ae === 0 && R && !d._done && (R = !1, B.end());
    }
    if (typeof m != "string")
      throw new Error("Multipart: Boundary not found");
    const F = n(f, "fieldSize", 1 * 1024 * 1024), j = n(f, "fileSize", 1 / 0), M = n(f, "files", 1 / 0), K = n(f, "fields", 1 / 0), ee = n(f, "parts", 1 / 0), ie = n(f, "headerPairs", 2e3), re = n(f, "headerSize", 80 * 1024);
    let ge = 0, Y = 0, Ae = 0, ae, de, R = !1;
    this._needDrain = !1, this._pause = !1, this._cb = void 0, this._nparts = 0, this._boy = d;
    const H = {
      boundary: m,
      maxHeaderPairs: ie,
      maxHeaderSize: re,
      partHwm: v.highWaterMark,
      highWaterMark: h.highWaterMark
    };
    this.parser = new t(H), this.parser.on("drain", function() {
      if (B._needDrain = !1, B._cb && !B._pause) {
        const $ = B._cb;
        B._cb = void 0, $();
      }
    }).on("part", function $(X) {
      if (++B._nparts > ee)
        return B.parser.removeListener("part", $), B.parser.on("part", Q), d.hitPartsLimit = !0, d.emit("partsLimit"), Q(X);
      if (de) {
        const z = de;
        z.emit("end"), z.removeAllListeners("end");
      }
      X.on("header", function(z) {
        let W, P, le, Qe, Ee, Ge, De = 0;
        if (z["content-type"] && (le = r(z["content-type"][0]), le[0])) {
          for (W = le[0].toLowerCase(), C = 0, u = le.length; C < u; ++C)
            if (g.test(le[C][0])) {
              Qe = le[C][1].toLowerCase();
              break;
            }
        }
        if (W === void 0 && (W = "text/plain"), Qe === void 0 && (Qe = w), z["content-disposition"]) {
          if (le = r(z["content-disposition"][0]), !a.test(le[0]))
            return Q(X);
          for (C = 0, u = le.length; C < u; ++C)
            E.test(le[C][0]) ? P = le[C][1] : c.test(le[C][0]) && (Ge = le[C][1], S || (Ge = o(Ge)));
        } else
          return Q(X);
        z["content-transfer-encoding"] ? Ee = z["content-transfer-encoding"][0].toLowerCase() : Ee = "7bit";
        let Ue, ye;
        if (y(P, W, Ge)) {
          if (ge === M)
            return d.hitFilesLimit || (d.hitFilesLimit = !0, d.emit("filesLimit")), Q(X);
          if (++ge, d.listenerCount("file") === 0) {
            B.parser._ignore();
            return;
          }
          ++Ae;
          const Ce = new I(v);
          ae = Ce, Ce.on("end", function() {
            if (--Ae, B._pause = !1, N(), B._cb && !B._needDrain) {
              const Ie = B._cb;
              B._cb = void 0, Ie();
            }
          }), Ce._read = function(Ie) {
            if (B._pause && (B._pause = !1, B._cb && !B._needDrain)) {
              const me = B._cb;
              B._cb = void 0, me();
            }
          }, d.emit("file", P, Ce, Ge, Ee, W), Ue = function(Ie) {
            if ((De += Ie.length) > j) {
              const me = j - De + Ie.length;
              me > 0 && Ce.push(Ie.slice(0, me)), Ce.truncated = !0, Ce.bytesRead = j, X.removeAllListeners("data"), Ce.emit("limit");
              return;
            } else Ce.push(Ie) || (B._pause = !0);
            Ce.bytesRead = De;
          }, ye = function() {
            ae = void 0, Ce.push(null);
          };
        } else {
          if (Y === K)
            return d.hitFieldsLimit || (d.hitFieldsLimit = !0, d.emit("fieldsLimit")), Q(X);
          ++Y, ++Ae;
          let Ce = "", Ie = !1;
          de = X, Ue = function(me) {
            if ((De += me.length) > F) {
              const Ne = F - (De - me.length);
              Ce += me.toString("binary", 0, Ne), Ie = !0, X.removeAllListeners("data");
            } else
              Ce += me.toString("binary");
          }, ye = function() {
            de = void 0, Ce.length && (Ce = s(Ce, "binary", Qe)), d.emit("field", P, Ce, !1, Ie, Ee, W), --Ae, N();
          };
        }
        X._readableState.sync = !1, X.on("data", Ue), X.on("end", ye);
      }).on("error", function(z) {
        ae && ae.emit("error", z);
      });
    }).on("error", function($) {
      d.emit("error", $);
    }).on("finish", function() {
      R = !0, N();
    });
  }
  l.prototype.write = function(d, h) {
    const C = this.parser.write(d);
    C && !this._pause ? h() : (this._needDrain = !C, this._cb = h);
  }, l.prototype.end = function() {
    const d = this;
    d.parser.writable ? d.parser.end() : d._boy._done || process.nextTick(function() {
      d._boy._done = !0, d._boy.emit("finish");
    });
  };
  function Q(d) {
    d.resume();
  }
  function I(d) {
    e.call(this, d), this.bytesRead = 0, this.truncated = !1;
  }
  return A(I, e), I.prototype._read = function(d) {
  }, Io = l, Io;
}
var po, sa;
function ld() {
  if (sa) return po;
  sa = 1;
  const e = /\+/g, A = [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ];
  function t() {
    this.buffer = void 0;
  }
  return t.prototype.write = function(r) {
    r = r.replace(e, " ");
    let s = "", o = 0, n = 0;
    const i = r.length;
    for (; o < i; ++o)
      this.buffer !== void 0 ? A[r.charCodeAt(o)] ? (this.buffer += r[o], ++n, this.buffer.length === 2 && (s += String.fromCharCode(parseInt(this.buffer, 16)), this.buffer = void 0)) : (s += "%" + this.buffer, this.buffer = void 0, --o) : r[o] === "%" && (o > n && (s += r.substring(n, o), n = o), this.buffer = "", ++n);
    return n < i && this.buffer === void 0 && (s += r.substring(n)), s;
  }, t.prototype.reset = function() {
    this.buffer = void 0;
  }, po = t, po;
}
var fo, oa;
function Ed() {
  if (oa) return fo;
  oa = 1;
  const e = ld(), A = Ii(), t = Bi(), r = /^charset$/i;
  s.detect = /^application\/x-www-form-urlencoded/i;
  function s(o, n) {
    const i = n.limits, a = n.parsedConType;
    this.boy = o, this.fieldSizeLimit = t(i, "fieldSize", 1 * 1024 * 1024), this.fieldNameSizeLimit = t(i, "fieldNameSize", 100), this.fieldsLimit = t(i, "fields", 1 / 0);
    let g;
    for (var c = 0, E = a.length; c < E; ++c)
      if (Array.isArray(a[c]) && r.test(a[c][0])) {
        g = a[c][1].toLowerCase();
        break;
      }
    g === void 0 && (g = n.defCharset || "utf8"), this.decoder = new e(), this.charset = g, this._fields = 0, this._state = "key", this._checkingBytes = !0, this._bytesKey = 0, this._bytesVal = 0, this._key = "", this._val = "", this._keyTrunc = !1, this._valTrunc = !1, this._hitLimit = !1;
  }
  return s.prototype.write = function(o, n) {
    if (this._fields === this.fieldsLimit)
      return this.boy.hitFieldsLimit || (this.boy.hitFieldsLimit = !0, this.boy.emit("fieldsLimit")), n();
    let i, a, g, c = 0;
    const E = o.length;
    for (; c < E; )
      if (this._state === "key") {
        for (i = a = void 0, g = c; g < E; ++g) {
          if (this._checkingBytes || ++c, o[g] === 61) {
            i = g;
            break;
          } else if (o[g] === 38) {
            a = g;
            break;
          }
          if (this._checkingBytes && this._bytesKey === this.fieldNameSizeLimit) {
            this._hitLimit = !0;
            break;
          } else this._checkingBytes && ++this._bytesKey;
        }
        if (i !== void 0)
          i > c && (this._key += this.decoder.write(o.toString("binary", c, i))), this._state = "val", this._hitLimit = !1, this._checkingBytes = !0, this._val = "", this._bytesVal = 0, this._valTrunc = !1, this.decoder.reset(), c = i + 1;
        else if (a !== void 0) {
          ++this._fields;
          let l;
          const Q = this._keyTrunc;
          if (a > c ? l = this._key += this.decoder.write(o.toString("binary", c, a)) : l = this._key, this._hitLimit = !1, this._checkingBytes = !0, this._key = "", this._bytesKey = 0, this._keyTrunc = !1, this.decoder.reset(), l.length && this.boy.emit(
            "field",
            A(l, "binary", this.charset),
            "",
            Q,
            !1
          ), c = a + 1, this._fields === this.fieldsLimit)
            return n();
        } else this._hitLimit ? (g > c && (this._key += this.decoder.write(o.toString("binary", c, g))), c = g, (this._bytesKey = this._key.length) === this.fieldNameSizeLimit && (this._checkingBytes = !1, this._keyTrunc = !0)) : (c < E && (this._key += this.decoder.write(o.toString("binary", c))), c = E);
      } else {
        for (a = void 0, g = c; g < E; ++g) {
          if (this._checkingBytes || ++c, o[g] === 38) {
            a = g;
            break;
          }
          if (this._checkingBytes && this._bytesVal === this.fieldSizeLimit) {
            this._hitLimit = !0;
            break;
          } else this._checkingBytes && ++this._bytesVal;
        }
        if (a !== void 0) {
          if (++this._fields, a > c && (this._val += this.decoder.write(o.toString("binary", c, a))), this.boy.emit(
            "field",
            A(this._key, "binary", this.charset),
            A(this._val, "binary", this.charset),
            this._keyTrunc,
            this._valTrunc
          ), this._state = "key", this._hitLimit = !1, this._checkingBytes = !0, this._key = "", this._bytesKey = 0, this._keyTrunc = !1, this.decoder.reset(), c = a + 1, this._fields === this.fieldsLimit)
            return n();
        } else this._hitLimit ? (g > c && (this._val += this.decoder.write(o.toString("binary", c, g))), c = g, (this._val === "" && this.fieldSizeLimit === 0 || (this._bytesVal = this._val.length) === this.fieldSizeLimit) && (this._checkingBytes = !1, this._valTrunc = !0)) : (c < E && (this._val += this.decoder.write(o.toString("binary", c))), c = E);
      }
    n();
  }, s.prototype.end = function() {
    this.boy._done || (this._state === "key" && this._key.length > 0 ? this.boy.emit(
      "field",
      A(this._key, "binary", this.charset),
      "",
      this._keyTrunc,
      !1
    ) : this._state === "val" && this.boy.emit(
      "field",
      A(this._key, "binary", this.charset),
      A(this._val, "binary", this.charset),
      this._keyTrunc,
      this._valTrunc
    ), this.boy._done = !0, this.boy.emit("finish"));
  }, fo = s, fo;
}
var na;
function ud() {
  if (na) return Lt.exports;
  na = 1;
  const e = Js.Writable, { inherits: A } = ir, t = _l(), r = gd(), s = Ed(), o = Nl();
  function n(i) {
    if (!(this instanceof n))
      return new n(i);
    if (typeof i != "object")
      throw new TypeError("Busboy expected an options-Object.");
    if (typeof i.headers != "object")
      throw new TypeError("Busboy expected an options-Object with headers-attribute.");
    if (typeof i.headers["content-type"] != "string")
      throw new TypeError("Missing Content-Type-header.");
    const {
      headers: a,
      ...g
    } = i;
    this.opts = {
      autoDestroy: !1,
      ...g
    }, e.call(this, this.opts), this._done = !1, this._parser = this.getParserByHeaders(a), this._finished = !1;
  }
  return A(n, e), n.prototype.emit = function(i) {
    if (i === "finish") {
      if (this._done) {
        if (this._finished)
          return;
      } else {
        this._parser?.end();
        return;
      }
      this._finished = !0;
    }
    e.prototype.emit.apply(this, arguments);
  }, n.prototype.getParserByHeaders = function(i) {
    const a = o(i["content-type"]), g = {
      defCharset: this.opts.defCharset,
      fileHwm: this.opts.fileHwm,
      headers: i,
      highWaterMark: this.opts.highWaterMark,
      isPartAFile: this.opts.isPartAFile,
      limits: this.opts.limits,
      parsedConType: a,
      preservePath: this.opts.preservePath
    };
    if (r.detect.test(a[0]))
      return new r(this, g);
    if (s.detect.test(a[0]))
      return new s(this, g);
    throw new Error("Unsupported Content-Type.");
  }, n.prototype._write = function(i, a, g) {
    this._parser.write(i, g);
  }, Lt.exports = n, Lt.exports.default = n, Lt.exports.Busboy = n, Lt.exports.Dicer = t, Lt.exports;
}
var mo, ia;
function _t() {
  if (ia) return mo;
  ia = 1;
  const { MessageChannel: e, receiveMessageOnPort: A } = Kg, t = ["GET", "HEAD", "POST"], r = new Set(t), s = [101, 204, 205, 304], o = [301, 302, 303, 307, 308], n = new Set(o), i = [
    "1",
    "7",
    "9",
    "11",
    "13",
    "15",
    "17",
    "19",
    "20",
    "21",
    "22",
    "23",
    "25",
    "37",
    "42",
    "43",
    "53",
    "69",
    "77",
    "79",
    "87",
    "95",
    "101",
    "102",
    "103",
    "104",
    "109",
    "110",
    "111",
    "113",
    "115",
    "117",
    "119",
    "123",
    "135",
    "137",
    "139",
    "143",
    "161",
    "179",
    "389",
    "427",
    "465",
    "512",
    "513",
    "514",
    "515",
    "526",
    "530",
    "531",
    "532",
    "540",
    "548",
    "554",
    "556",
    "563",
    "587",
    "601",
    "636",
    "989",
    "990",
    "993",
    "995",
    "1719",
    "1720",
    "1723",
    "2049",
    "3659",
    "4045",
    "5060",
    "5061",
    "6000",
    "6566",
    "6665",
    "6666",
    "6667",
    "6668",
    "6669",
    "6697",
    "10080"
  ], a = new Set(i), g = [
    "",
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url"
  ], c = new Set(g), E = ["follow", "manual", "error"], l = ["GET", "HEAD", "OPTIONS", "TRACE"], Q = new Set(l), I = ["navigate", "same-origin", "no-cors", "cors"], d = ["omit", "same-origin", "include"], h = [
    "default",
    "no-store",
    "reload",
    "no-cache",
    "force-cache",
    "only-if-cached"
  ], C = [
    "content-encoding",
    "content-language",
    "content-location",
    "content-type",
    // See https://github.com/nodejs/undici/issues/2021
    // 'Content-Length' is a forbidden header name, which is typically
    // removed in the Headers implementation. However, undici doesn't
    // filter out headers, so we add it here.
    "content-length"
  ], u = [
    "half"
  ], B = ["CONNECT", "TRACE", "TRACK"], m = new Set(B), f = [
    "audio",
    "audioworklet",
    "font",
    "image",
    "manifest",
    "paintworklet",
    "script",
    "style",
    "track",
    "video",
    "xslt",
    ""
  ], y = new Set(f), b = globalThis.DOMException ?? (() => {
    try {
      atob("~");
    } catch (v) {
      return Object.getPrototypeOf(v).constructor;
    }
  })();
  let w;
  const S = globalThis.structuredClone ?? // https://github.com/nodejs/node/blob/b27ae24dcc4251bad726d9d84baf678d1f707fed/lib/internal/structured_clone.js
  // structuredClone was added in v17.0.0, but fetch supports v16.8
  function(N, F = void 0) {
    if (arguments.length === 0)
      throw new TypeError("missing argument");
    return w || (w = new e()), w.port1.unref(), w.port2.unref(), w.port1.postMessage(N, F?.transfer), A(w.port2).message;
  };
  return mo = {
    DOMException: b,
    structuredClone: S,
    subresource: f,
    forbiddenMethods: B,
    requestBodyHeader: C,
    referrerPolicy: g,
    requestRedirect: E,
    requestMode: I,
    requestCredentials: d,
    requestCache: h,
    redirectStatus: o,
    corsSafeListedMethods: t,
    nullBodyStatus: s,
    safeMethods: l,
    badPorts: i,
    requestDuplex: u,
    subresourceSet: y,
    badPortsSet: a,
    redirectStatusSet: n,
    corsSafeListedMethodsSet: r,
    safeMethodsSet: Q,
    forbiddenMethodsSet: m,
    referrerPolicySet: c
  }, mo;
}
var wo, aa;
function jr() {
  if (aa) return wo;
  aa = 1;
  const e = Symbol.for("undici.globalOrigin.1");
  function A() {
    return globalThis[e];
  }
  function t(r) {
    if (r === void 0) {
      Object.defineProperty(globalThis, e, {
        value: void 0,
        writable: !0,
        enumerable: !1,
        configurable: !1
      });
      return;
    }
    const s = new URL(r);
    if (s.protocol !== "http:" && s.protocol !== "https:")
      throw new TypeError(`Only http & https urls are allowed, received ${s.protocol}`);
    Object.defineProperty(globalThis, e, {
      value: s,
      writable: !0,
      enumerable: !1,
      configurable: !1
    });
  }
  return wo = {
    getGlobalOrigin: A,
    setGlobalOrigin: t
  }, wo;
}
var yo, ca;
function TA() {
  if (ca) return yo;
  ca = 1;
  const { redirectStatusSet: e, referrerPolicySet: A, badPortsSet: t } = _t(), { getGlobalOrigin: r } = jr(), { performance: s } = Ju, { isBlobLike: o, toUSVString: n, ReadableStreamFrom: i } = we, a = Me, { isUint8Array: g } = zg;
  let c = [], E;
  try {
    E = require("crypto");
    const T = ["sha256", "sha384", "sha512"];
    c = E.getHashes().filter((x) => T.includes(x));
  } catch {
  }
  function l(T) {
    const x = T.urlList, _ = x.length;
    return _ === 0 ? null : x[_ - 1].toString();
  }
  function Q(T, x) {
    if (!e.has(T.status))
      return null;
    let _ = T.headersList.get("location");
    return _ !== null && f(_) && (_ = new URL(_, l(T))), _ && !_.hash && (_.hash = x), _;
  }
  function I(T) {
    return T.urlList[T.urlList.length - 1];
  }
  function d(T) {
    const x = I(T);
    return $e(x) && t.has(x.port) ? "blocked" : "allowed";
  }
  function h(T) {
    return T instanceof Error || T?.constructor?.name === "Error" || T?.constructor?.name === "DOMException";
  }
  function C(T) {
    for (let x = 0; x < T.length; ++x) {
      const _ = T.charCodeAt(x);
      if (!(_ === 9 || // HTAB
      _ >= 32 && _ <= 126 || // SP / VCHAR
      _ >= 128 && _ <= 255))
        return !1;
    }
    return !0;
  }
  function u(T) {
    switch (T) {
      case 34:
      case 40:
      case 41:
      case 44:
      case 47:
      case 58:
      case 59:
      case 60:
      case 61:
      case 62:
      case 63:
      case 64:
      case 91:
      case 92:
      case 93:
      case 123:
      case 125:
        return !1;
      default:
        return T >= 33 && T <= 126;
    }
  }
  function B(T) {
    if (T.length === 0)
      return !1;
    for (let x = 0; x < T.length; ++x)
      if (!u(T.charCodeAt(x)))
        return !1;
    return !0;
  }
  function m(T) {
    return B(T);
  }
  function f(T) {
    return !(T.startsWith("	") || T.startsWith(" ") || T.endsWith("	") || T.endsWith(" ") || T.includes("\0") || T.includes("\r") || T.includes(`
`));
  }
  function y(T, x) {
    const { headersList: _ } = x, D = (_.get("referrer-policy") ?? "").split(",");
    let p = "";
    if (D.length > 0)
      for (let k = D.length; k !== 0; k--) {
        const G = D[k - 1].trim();
        if (A.has(G)) {
          p = G;
          break;
        }
      }
    p !== "" && (T.referrerPolicy = p);
  }
  function b() {
    return "allowed";
  }
  function w() {
    return "success";
  }
  function S() {
    return "success";
  }
  function v(T) {
    let x = null;
    x = T.mode, T.headersList.set("sec-fetch-mode", x);
  }
  function N(T) {
    let x = T.origin;
    if (T.responseTainting === "cors" || T.mode === "websocket")
      x && T.headersList.append("origin", x);
    else if (T.method !== "GET" && T.method !== "HEAD") {
      switch (T.referrerPolicy) {
        case "no-referrer":
          x = null;
          break;
        case "no-referrer-when-downgrade":
        case "strict-origin":
        case "strict-origin-when-cross-origin":
          T.origin && eA(T.origin) && !eA(I(T)) && (x = null);
          break;
        case "same-origin":
          $(T, I(T)) || (x = null);
          break;
      }
      x && T.headersList.append("origin", x);
    }
  }
  function F(T) {
    return s.now();
  }
  function j(T) {
    return {
      startTime: T.startTime ?? 0,
      redirectStartTime: 0,
      redirectEndTime: 0,
      postRedirectStartTime: T.startTime ?? 0,
      finalServiceWorkerStartTime: 0,
      finalNetworkResponseStartTime: 0,
      finalNetworkRequestStartTime: 0,
      endTime: 0,
      encodedBodySize: 0,
      decodedBodySize: 0,
      finalConnectionTimingInfo: null
    };
  }
  function M() {
    return {
      referrerPolicy: "strict-origin-when-cross-origin"
    };
  }
  function K(T) {
    return {
      referrerPolicy: T.referrerPolicy
    };
  }
  function ee(T) {
    const x = T.referrerPolicy;
    a(x);
    let _ = null;
    if (T.referrer === "client") {
      const L = r();
      if (!L || L.origin === "null")
        return "no-referrer";
      _ = new URL(L);
    } else T.referrer instanceof URL && (_ = T.referrer);
    let D = ie(_);
    const p = ie(_, !0);
    D.toString().length > 4096 && (D = p);
    const k = $(T, D), G = re(D) && !re(T.url);
    switch (x) {
      case "origin":
        return p ?? ie(_, !0);
      case "unsafe-url":
        return D;
      case "same-origin":
        return k ? p : "no-referrer";
      case "origin-when-cross-origin":
        return k ? D : p;
      case "strict-origin-when-cross-origin": {
        const L = I(T);
        return $(D, L) ? D : re(D) && !re(L) ? "no-referrer" : p;
      }
      case "strict-origin":
      case "no-referrer-when-downgrade":
      default:
        return G ? "no-referrer" : p;
    }
  }
  function ie(T, x) {
    return a(T instanceof URL), T.protocol === "file:" || T.protocol === "about:" || T.protocol === "blank:" ? "no-referrer" : (T.username = "", T.password = "", T.hash = "", x && (T.pathname = "", T.search = ""), T);
  }
  function re(T) {
    if (!(T instanceof URL))
      return !1;
    if (T.href === "about:blank" || T.href === "about:srcdoc" || T.protocol === "data:" || T.protocol === "file:") return !0;
    return x(T.origin);
    function x(_) {
      if (_ == null || _ === "null") return !1;
      const D = new URL(_);
      return !!(D.protocol === "https:" || D.protocol === "wss:" || /^127(?:\.[0-9]+){0,2}\.[0-9]+$|^\[(?:0*:)*?:?0*1\]$/.test(D.hostname) || D.hostname === "localhost" || D.hostname.includes("localhost.") || D.hostname.endsWith(".localhost"));
    }
  }
  function ge(T, x) {
    if (E === void 0)
      return !0;
    const _ = Ae(x);
    if (_ === "no metadata" || _.length === 0)
      return !0;
    const D = ae(_), p = de(_, D);
    for (const k of p) {
      const G = k.algo, L = k.hash;
      let V = E.createHash(G).update(T).digest("base64");
      if (V[V.length - 1] === "=" && (V[V.length - 2] === "=" ? V = V.slice(0, -2) : V = V.slice(0, -1)), R(V, L))
        return !0;
    }
    return !1;
  }
  const Y = /(?<algo>sha256|sha384|sha512)-((?<hash>[A-Za-z0-9+/]+|[A-Za-z0-9_-]+)={0,2}(?:\s|$)( +[!-~]*)?)?/i;
  function Ae(T) {
    const x = [];
    let _ = !0;
    for (const D of T.split(" ")) {
      _ = !1;
      const p = Y.exec(D);
      if (p === null || p.groups === void 0 || p.groups.algo === void 0)
        continue;
      const k = p.groups.algo.toLowerCase();
      c.includes(k) && x.push(p.groups);
    }
    return _ === !0 ? "no metadata" : x;
  }
  function ae(T) {
    let x = T[0].algo;
    if (x[3] === "5")
      return x;
    for (let _ = 1; _ < T.length; ++_) {
      const D = T[_];
      if (D.algo[3] === "5") {
        x = "sha512";
        break;
      } else {
        if (x[3] === "3")
          continue;
        D.algo[3] === "3" && (x = "sha384");
      }
    }
    return x;
  }
  function de(T, x) {
    if (T.length === 1)
      return T;
    let _ = 0;
    for (let D = 0; D < T.length; ++D)
      T[D].algo === x && (T[_++] = T[D]);
    return T.length = _, T;
  }
  function R(T, x) {
    if (T.length !== x.length)
      return !1;
    for (let _ = 0; _ < T.length; ++_)
      if (T[_] !== x[_]) {
        if (T[_] === "+" && x[_] === "-" || T[_] === "/" && x[_] === "_")
          continue;
        return !1;
      }
    return !0;
  }
  function H(T) {
  }
  function $(T, x) {
    return T.origin === x.origin && T.origin === "null" || T.protocol === x.protocol && T.hostname === x.hostname && T.port === x.port;
  }
  function X() {
    let T, x;
    return { promise: new Promise((D, p) => {
      T = D, x = p;
    }), resolve: T, reject: x };
  }
  function z(T) {
    return T.controller.state === "aborted";
  }
  function W(T) {
    return T.controller.state === "aborted" || T.controller.state === "terminated";
  }
  const P = {
    delete: "DELETE",
    DELETE: "DELETE",
    get: "GET",
    GET: "GET",
    head: "HEAD",
    HEAD: "HEAD",
    options: "OPTIONS",
    OPTIONS: "OPTIONS",
    post: "POST",
    POST: "POST",
    put: "PUT",
    PUT: "PUT"
  };
  Object.setPrototypeOf(P, null);
  function le(T) {
    return P[T.toLowerCase()] ?? T;
  }
  function Qe(T) {
    const x = JSON.stringify(T);
    if (x === void 0)
      throw new TypeError("Value is not JSON serializable");
    return a(typeof x == "string"), x;
  }
  const Ee = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));
  function Ge(T, x, _) {
    const D = {
      index: 0,
      kind: _,
      target: T
    }, p = {
      next() {
        if (Object.getPrototypeOf(this) !== p)
          throw new TypeError(
            `'next' called on an object that does not implement interface ${x} Iterator.`
          );
        const { index: k, kind: G, target: L } = D, V = L(), se = V.length;
        if (k >= se)
          return { value: void 0, done: !0 };
        const fe = V[k];
        return D.index = k + 1, De(fe, G);
      },
      // The class string of an iterator prototype object for a given interface is the
      // result of concatenating the identifier of the interface and the string " Iterator".
      [Symbol.toStringTag]: `${x} Iterator`
    };
    return Object.setPrototypeOf(p, Ee), Object.setPrototypeOf({}, p);
  }
  function De(T, x) {
    let _;
    switch (x) {
      case "key": {
        _ = T[0];
        break;
      }
      case "value": {
        _ = T[1];
        break;
      }
      case "key+value": {
        _ = T;
        break;
      }
    }
    return { value: _, done: !1 };
  }
  async function Ue(T, x, _) {
    const D = x, p = _;
    let k;
    try {
      k = T.stream.getReader();
    } catch (G) {
      p(G);
      return;
    }
    try {
      const G = await Be(k);
      D(G);
    } catch (G) {
      p(G);
    }
  }
  let ye = globalThis.ReadableStream;
  function Ce(T) {
    return ye || (ye = ct.ReadableStream), T instanceof ye || T[Symbol.toStringTag] === "ReadableStream" && typeof T.tee == "function";
  }
  const Ie = 65535;
  function me(T) {
    return T.length < Ie ? String.fromCharCode(...T) : T.reduce((x, _) => x + String.fromCharCode(_), "");
  }
  function Ne(T) {
    try {
      T.close();
    } catch (x) {
      if (!x.message.includes("Controller is already closed"))
        throw x;
    }
  }
  function oA(T) {
    for (let x = 0; x < T.length; x++)
      a(T.charCodeAt(x) <= 255);
    return T;
  }
  async function Be(T) {
    const x = [];
    let _ = 0;
    for (; ; ) {
      const { done: D, value: p } = await T.read();
      if (D)
        return Buffer.concat(x, _);
      if (!g(p))
        throw new TypeError("Received non-Uint8Array chunk");
      x.push(p), _ += p.length;
    }
  }
  function Te(T) {
    a("protocol" in T);
    const x = T.protocol;
    return x === "about:" || x === "blob:" || x === "data:";
  }
  function eA(T) {
    return typeof T == "string" ? T.startsWith("https:") : T.protocol === "https:";
  }
  function $e(T) {
    a("protocol" in T);
    const x = T.protocol;
    return x === "http:" || x === "https:";
  }
  const Nt = Object.hasOwn || ((T, x) => Object.prototype.hasOwnProperty.call(T, x));
  return yo = {
    isAborted: z,
    isCancelled: W,
    createDeferredPromise: X,
    ReadableStreamFrom: i,
    toUSVString: n,
    tryUpgradeRequestToAPotentiallyTrustworthyURL: H,
    coarsenedSharedCurrentTime: F,
    determineRequestsReferrer: ee,
    makePolicyContainer: M,
    clonePolicyContainer: K,
    appendFetchMetadata: v,
    appendRequestOriginHeader: N,
    TAOCheck: S,
    corsCheck: w,
    crossOriginResourcePolicyCheck: b,
    createOpaqueTimingInfo: j,
    setRequestReferrerPolicyOnRedirect: y,
    isValidHTTPToken: B,
    requestBadPort: d,
    requestCurrentURL: I,
    responseURL: l,
    responseLocationURL: Q,
    isBlobLike: o,
    isURLPotentiallyTrustworthy: re,
    isValidReasonPhrase: C,
    sameOrigin: $,
    normalizeMethod: le,
    serializeJavascriptValueToJSONString: Qe,
    makeIterator: Ge,
    isValidHeaderName: m,
    isValidHeaderValue: f,
    hasOwn: Nt,
    isErrorLike: h,
    fullyReadBody: Ue,
    bytesMatch: ge,
    isReadableStreamLike: Ce,
    readableStreamClose: Ne,
    isomorphicEncode: oA,
    isomorphicDecode: me,
    urlIsLocal: Te,
    urlHasHttpsScheme: eA,
    urlIsHttpHttpsScheme: $e,
    readAllBytes: Be,
    normalizeMethodRecord: P,
    parseMetadata: Ae
  }, yo;
}
var bo, ga;
function Et() {
  return ga || (ga = 1, bo = {
    kUrl: Symbol("url"),
    kHeaders: Symbol("headers"),
    kSignal: Symbol("signal"),
    kState: Symbol("state"),
    kGuard: Symbol("guard"),
    kRealm: Symbol("realm")
  }), bo;
}
var Ro, la;
function hA() {
  if (la) return Ro;
  la = 1;
  const { types: e } = LA, { hasOwn: A, toUSVString: t } = TA(), r = {};
  return r.converters = {}, r.util = {}, r.errors = {}, r.errors.exception = function(s) {
    return new TypeError(`${s.header}: ${s.message}`);
  }, r.errors.conversionFailed = function(s) {
    const o = s.types.length === 1 ? "" : " one of", n = `${s.argument} could not be converted to${o}: ${s.types.join(", ")}.`;
    return r.errors.exception({
      header: s.prefix,
      message: n
    });
  }, r.errors.invalidArgument = function(s) {
    return r.errors.exception({
      header: s.prefix,
      message: `"${s.value}" is an invalid ${s.type}.`
    });
  }, r.brandCheck = function(s, o, n = void 0) {
    if (n?.strict !== !1 && !(s instanceof o))
      throw new TypeError("Illegal invocation");
    return s?.[Symbol.toStringTag] === o.prototype[Symbol.toStringTag];
  }, r.argumentLengthCheck = function({ length: s }, o, n) {
    if (s < o)
      throw r.errors.exception({
        message: `${o} argument${o !== 1 ? "s" : ""} required, but${s ? " only" : ""} ${s} found.`,
        ...n
      });
  }, r.illegalConstructor = function() {
    throw r.errors.exception({
      header: "TypeError",
      message: "Illegal constructor"
    });
  }, r.util.Type = function(s) {
    switch (typeof s) {
      case "undefined":
        return "Undefined";
      case "boolean":
        return "Boolean";
      case "string":
        return "String";
      case "symbol":
        return "Symbol";
      case "number":
        return "Number";
      case "bigint":
        return "BigInt";
      case "function":
      case "object":
        return s === null ? "Null" : "Object";
    }
  }, r.util.ConvertToInt = function(s, o, n, i = {}) {
    let a, g;
    o === 64 ? (a = Math.pow(2, 53) - 1, n === "unsigned" ? g = 0 : g = Math.pow(-2, 53) + 1) : n === "unsigned" ? (g = 0, a = Math.pow(2, o) - 1) : (g = Math.pow(-2, o) - 1, a = Math.pow(2, o - 1) - 1);
    let c = Number(s);
    if (c === 0 && (c = 0), i.enforceRange === !0) {
      if (Number.isNaN(c) || c === Number.POSITIVE_INFINITY || c === Number.NEGATIVE_INFINITY)
        throw r.errors.exception({
          header: "Integer conversion",
          message: `Could not convert ${s} to an integer.`
        });
      if (c = r.util.IntegerPart(c), c < g || c > a)
        throw r.errors.exception({
          header: "Integer conversion",
          message: `Value must be between ${g}-${a}, got ${c}.`
        });
      return c;
    }
    return !Number.isNaN(c) && i.clamp === !0 ? (c = Math.min(Math.max(c, g), a), Math.floor(c) % 2 === 0 ? c = Math.floor(c) : c = Math.ceil(c), c) : Number.isNaN(c) || c === 0 && Object.is(0, c) || c === Number.POSITIVE_INFINITY || c === Number.NEGATIVE_INFINITY ? 0 : (c = r.util.IntegerPart(c), c = c % Math.pow(2, o), n === "signed" && c >= Math.pow(2, o) - 1 ? c - Math.pow(2, o) : c);
  }, r.util.IntegerPart = function(s) {
    const o = Math.floor(Math.abs(s));
    return s < 0 ? -1 * o : o;
  }, r.sequenceConverter = function(s) {
    return (o) => {
      if (r.util.Type(o) !== "Object")
        throw r.errors.exception({
          header: "Sequence",
          message: `Value of type ${r.util.Type(o)} is not an Object.`
        });
      const n = o?.[Symbol.iterator]?.(), i = [];
      if (n === void 0 || typeof n.next != "function")
        throw r.errors.exception({
          header: "Sequence",
          message: "Object is not an iterator."
        });
      for (; ; ) {
        const { done: a, value: g } = n.next();
        if (a)
          break;
        i.push(s(g));
      }
      return i;
    };
  }, r.recordConverter = function(s, o) {
    return (n) => {
      if (r.util.Type(n) !== "Object")
        throw r.errors.exception({
          header: "Record",
          message: `Value of type ${r.util.Type(n)} is not an Object.`
        });
      const i = {};
      if (!e.isProxy(n)) {
        const g = Object.keys(n);
        for (const c of g) {
          const E = s(c), l = o(n[c]);
          i[E] = l;
        }
        return i;
      }
      const a = Reflect.ownKeys(n);
      for (const g of a)
        if (Reflect.getOwnPropertyDescriptor(n, g)?.enumerable) {
          const E = s(g), l = o(n[g]);
          i[E] = l;
        }
      return i;
    };
  }, r.interfaceConverter = function(s) {
    return (o, n = {}) => {
      if (n.strict !== !1 && !(o instanceof s))
        throw r.errors.exception({
          header: s.name,
          message: `Expected ${o} to be an instance of ${s.name}.`
        });
      return o;
    };
  }, r.dictionaryConverter = function(s) {
    return (o) => {
      const n = r.util.Type(o), i = {};
      if (n === "Null" || n === "Undefined")
        return i;
      if (n !== "Object")
        throw r.errors.exception({
          header: "Dictionary",
          message: `Expected ${o} to be one of: Null, Undefined, Object.`
        });
      for (const a of s) {
        const { key: g, defaultValue: c, required: E, converter: l } = a;
        if (E === !0 && !A(o, g))
          throw r.errors.exception({
            header: "Dictionary",
            message: `Missing required key "${g}".`
          });
        let Q = o[g];
        const I = A(a, "defaultValue");
        if (I && Q !== null && (Q = Q ?? c), E || I || Q !== void 0) {
          if (Q = l(Q), a.allowedValues && !a.allowedValues.includes(Q))
            throw r.errors.exception({
              header: "Dictionary",
              message: `${Q} is not an accepted type. Expected one of ${a.allowedValues.join(", ")}.`
            });
          i[g] = Q;
        }
      }
      return i;
    };
  }, r.nullableConverter = function(s) {
    return (o) => o === null ? o : s(o);
  }, r.converters.DOMString = function(s, o = {}) {
    if (s === null && o.legacyNullToEmptyString)
      return "";
    if (typeof s == "symbol")
      throw new TypeError("Could not convert argument of type symbol to string.");
    return String(s);
  }, r.converters.ByteString = function(s) {
    const o = r.converters.DOMString(s);
    for (let n = 0; n < o.length; n++)
      if (o.charCodeAt(n) > 255)
        throw new TypeError(
          `Cannot convert argument to a ByteString because the character at index ${n} has a value of ${o.charCodeAt(n)} which is greater than 255.`
        );
    return o;
  }, r.converters.USVString = t, r.converters.boolean = function(s) {
    return !!s;
  }, r.converters.any = function(s) {
    return s;
  }, r.converters["long long"] = function(s) {
    return r.util.ConvertToInt(s, 64, "signed");
  }, r.converters["unsigned long long"] = function(s) {
    return r.util.ConvertToInt(s, 64, "unsigned");
  }, r.converters["unsigned long"] = function(s) {
    return r.util.ConvertToInt(s, 32, "unsigned");
  }, r.converters["unsigned short"] = function(s, o) {
    return r.util.ConvertToInt(s, 16, "unsigned", o);
  }, r.converters.ArrayBuffer = function(s, o = {}) {
    if (r.util.Type(s) !== "Object" || !e.isAnyArrayBuffer(s))
      throw r.errors.conversionFailed({
        prefix: `${s}`,
        argument: `${s}`,
        types: ["ArrayBuffer"]
      });
    if (o.allowShared === !1 && e.isSharedArrayBuffer(s))
      throw r.errors.exception({
        header: "ArrayBuffer",
        message: "SharedArrayBuffer is not allowed."
      });
    return s;
  }, r.converters.TypedArray = function(s, o, n = {}) {
    if (r.util.Type(s) !== "Object" || !e.isTypedArray(s) || s.constructor.name !== o.name)
      throw r.errors.conversionFailed({
        prefix: `${o.name}`,
        argument: `${s}`,
        types: [o.name]
      });
    if (n.allowShared === !1 && e.isSharedArrayBuffer(s.buffer))
      throw r.errors.exception({
        header: "ArrayBuffer",
        message: "SharedArrayBuffer is not allowed."
      });
    return s;
  }, r.converters.DataView = function(s, o = {}) {
    if (r.util.Type(s) !== "Object" || !e.isDataView(s))
      throw r.errors.exception({
        header: "DataView",
        message: "Object is not a DataView."
      });
    if (o.allowShared === !1 && e.isSharedArrayBuffer(s.buffer))
      throw r.errors.exception({
        header: "ArrayBuffer",
        message: "SharedArrayBuffer is not allowed."
      });
    return s;
  }, r.converters.BufferSource = function(s, o = {}) {
    if (e.isAnyArrayBuffer(s))
      return r.converters.ArrayBuffer(s, o);
    if (e.isTypedArray(s))
      return r.converters.TypedArray(s, s.constructor);
    if (e.isDataView(s))
      return r.converters.DataView(s, o);
    throw new TypeError(`Could not convert ${s} to a BufferSource.`);
  }, r.converters["sequence<ByteString>"] = r.sequenceConverter(
    r.converters.ByteString
  ), r.converters["sequence<sequence<ByteString>>"] = r.sequenceConverter(
    r.converters["sequence<ByteString>"]
  ), r.converters["record<ByteString, ByteString>"] = r.recordConverter(
    r.converters.ByteString,
    r.converters.ByteString
  ), Ro = {
    webidl: r
  }, Ro;
}
var Do, Ea;
function MA() {
  if (Ea) return Do;
  Ea = 1;
  const e = Me, { atob: A } = Gt, { isomorphicDecode: t } = TA(), r = new TextEncoder(), s = /^[!#$%&'*+-.^_|~A-Za-z0-9]+$/, o = /(\u000A|\u000D|\u0009|\u0020)/, n = /[\u0009|\u0020-\u007E|\u0080-\u00FF]/;
  function i(f) {
    e(f.protocol === "data:");
    let y = a(f, !0);
    y = y.slice(5);
    const b = { position: 0 };
    let w = c(
      ",",
      y,
      b
    );
    const S = w.length;
    if (w = m(w, !0, !0), b.position >= y.length)
      return "failure";
    b.position++;
    const v = y.slice(S + 1);
    let N = E(v);
    if (/;(\u0020){0,}base64$/i.test(w)) {
      const j = t(N);
      if (N = I(j), N === "failure")
        return "failure";
      w = w.slice(0, -6), w = w.replace(/(\u0020)+$/, ""), w = w.slice(0, -1);
    }
    w.startsWith(";") && (w = "text/plain" + w);
    let F = Q(w);
    return F === "failure" && (F = Q("text/plain;charset=US-ASCII")), { mimeType: F, body: N };
  }
  function a(f, y = !1) {
    if (!y)
      return f.href;
    const b = f.href, w = f.hash.length;
    return w === 0 ? b : b.substring(0, b.length - w);
  }
  function g(f, y, b) {
    let w = "";
    for (; b.position < y.length && f(y[b.position]); )
      w += y[b.position], b.position++;
    return w;
  }
  function c(f, y, b) {
    const w = y.indexOf(f, b.position), S = b.position;
    return w === -1 ? (b.position = y.length, y.slice(S)) : (b.position = w, y.slice(S, b.position));
  }
  function E(f) {
    const y = r.encode(f);
    return l(y);
  }
  function l(f) {
    const y = [];
    for (let b = 0; b < f.length; b++) {
      const w = f[b];
      if (w !== 37)
        y.push(w);
      else if (w === 37 && !/^[0-9A-Fa-f]{2}$/i.test(String.fromCharCode(f[b + 1], f[b + 2])))
        y.push(37);
      else {
        const S = String.fromCharCode(f[b + 1], f[b + 2]), v = Number.parseInt(S, 16);
        y.push(v), b += 2;
      }
    }
    return Uint8Array.from(y);
  }
  function Q(f) {
    f = u(f, !0, !0);
    const y = { position: 0 }, b = c(
      "/",
      f,
      y
    );
    if (b.length === 0 || !s.test(b) || y.position > f.length)
      return "failure";
    y.position++;
    let w = c(
      ";",
      f,
      y
    );
    if (w = u(w, !1, !0), w.length === 0 || !s.test(w))
      return "failure";
    const S = b.toLowerCase(), v = w.toLowerCase(), N = {
      type: S,
      subtype: v,
      /** @type {Map<string, string>} */
      parameters: /* @__PURE__ */ new Map(),
      // https://mimesniff.spec.whatwg.org/#mime-type-essence
      essence: `${S}/${v}`
    };
    for (; y.position < f.length; ) {
      y.position++, g(
        // https://fetch.spec.whatwg.org/#http-whitespace
        (M) => o.test(M),
        f,
        y
      );
      let F = g(
        (M) => M !== ";" && M !== "=",
        f,
        y
      );
      if (F = F.toLowerCase(), y.position < f.length) {
        if (f[y.position] === ";")
          continue;
        y.position++;
      }
      if (y.position > f.length)
        break;
      let j = null;
      if (f[y.position] === '"')
        j = d(f, y, !0), c(
          ";",
          f,
          y
        );
      else if (j = c(
        ";",
        f,
        y
      ), j = u(j, !1, !0), j.length === 0)
        continue;
      F.length !== 0 && s.test(F) && (j.length === 0 || n.test(j)) && !N.parameters.has(F) && N.parameters.set(F, j);
    }
    return N;
  }
  function I(f) {
    if (f = f.replace(/[\u0009\u000A\u000C\u000D\u0020]/g, ""), f.length % 4 === 0 && (f = f.replace(/=?=$/, "")), f.length % 4 === 1 || /[^+/0-9A-Za-z]/.test(f))
      return "failure";
    const y = A(f), b = new Uint8Array(y.length);
    for (let w = 0; w < y.length; w++)
      b[w] = y.charCodeAt(w);
    return b;
  }
  function d(f, y, b) {
    const w = y.position;
    let S = "";
    for (e(f[y.position] === '"'), y.position++; S += g(
      (N) => N !== '"' && N !== "\\",
      f,
      y
    ), !(y.position >= f.length); ) {
      const v = f[y.position];
      if (y.position++, v === "\\") {
        if (y.position >= f.length) {
          S += "\\";
          break;
        }
        S += f[y.position], y.position++;
      } else {
        e(v === '"');
        break;
      }
    }
    return b ? S : f.slice(w, y.position);
  }
  function h(f) {
    e(f !== "failure");
    const { parameters: y, essence: b } = f;
    let w = b;
    for (let [S, v] of y.entries())
      w += ";", w += S, w += "=", s.test(v) || (v = v.replace(/(\\|")/g, "\\$1"), v = '"' + v, v += '"'), w += v;
    return w;
  }
  function C(f) {
    return f === "\r" || f === `
` || f === "	" || f === " ";
  }
  function u(f, y = !0, b = !0) {
    let w = 0, S = f.length - 1;
    if (y)
      for (; w < f.length && C(f[w]); w++) ;
    if (b)
      for (; S > 0 && C(f[S]); S--) ;
    return f.slice(w, S + 1);
  }
  function B(f) {
    return f === "\r" || f === `
` || f === "	" || f === "\f" || f === " ";
  }
  function m(f, y = !0, b = !0) {
    let w = 0, S = f.length - 1;
    if (y)
      for (; w < f.length && B(f[w]); w++) ;
    if (b)
      for (; S > 0 && B(f[S]); S--) ;
    return f.slice(w, S + 1);
  }
  return Do = {
    dataURLProcessor: i,
    URLSerializer: a,
    collectASequenceOfCodePoints: g,
    collectASequenceOfCodePointsFast: c,
    stringPercentDecode: E,
    parseMIMEType: Q,
    collectAnHTTPQuotedString: d,
    serializeAMimeType: h
  }, Do;
}
var To, ua;
function pi() {
  if (ua) return To;
  ua = 1;
  const { Blob: e, File: A } = Gt, { types: t } = LA, { kState: r } = Et(), { isBlobLike: s } = TA(), { webidl: o } = hA(), { parseMIMEType: n, serializeAMimeType: i } = MA(), { kEnumerableProperty: a } = we, g = new TextEncoder();
  class c extends e {
    constructor(h, C, u = {}) {
      o.argumentLengthCheck(arguments, 2, { header: "File constructor" }), h = o.converters["sequence<BlobPart>"](h), C = o.converters.USVString(C), u = o.converters.FilePropertyBag(u);
      const B = C;
      let m = u.type, f;
      e: {
        if (m) {
          if (m = n(m), m === "failure") {
            m = "";
            break e;
          }
          m = i(m).toLowerCase();
        }
        f = u.lastModified;
      }
      super(l(h, u), { type: m }), this[r] = {
        name: B,
        lastModified: f,
        type: m
      };
    }
    get name() {
      return o.brandCheck(this, c), this[r].name;
    }
    get lastModified() {
      return o.brandCheck(this, c), this[r].lastModified;
    }
    get type() {
      return o.brandCheck(this, c), this[r].type;
    }
  }
  class E {
    constructor(h, C, u = {}) {
      const B = C, m = u.type, f = u.lastModified ?? Date.now();
      this[r] = {
        blobLike: h,
        name: B,
        type: m,
        lastModified: f
      };
    }
    stream(...h) {
      return o.brandCheck(this, E), this[r].blobLike.stream(...h);
    }
    arrayBuffer(...h) {
      return o.brandCheck(this, E), this[r].blobLike.arrayBuffer(...h);
    }
    slice(...h) {
      return o.brandCheck(this, E), this[r].blobLike.slice(...h);
    }
    text(...h) {
      return o.brandCheck(this, E), this[r].blobLike.text(...h);
    }
    get size() {
      return o.brandCheck(this, E), this[r].blobLike.size;
    }
    get type() {
      return o.brandCheck(this, E), this[r].blobLike.type;
    }
    get name() {
      return o.brandCheck(this, E), this[r].name;
    }
    get lastModified() {
      return o.brandCheck(this, E), this[r].lastModified;
    }
    get [Symbol.toStringTag]() {
      return "File";
    }
  }
  Object.defineProperties(c.prototype, {
    [Symbol.toStringTag]: {
      value: "File",
      configurable: !0
    },
    name: a,
    lastModified: a
  }), o.converters.Blob = o.interfaceConverter(e), o.converters.BlobPart = function(d, h) {
    if (o.util.Type(d) === "Object") {
      if (s(d))
        return o.converters.Blob(d, { strict: !1 });
      if (ArrayBuffer.isView(d) || t.isAnyArrayBuffer(d))
        return o.converters.BufferSource(d, h);
    }
    return o.converters.USVString(d, h);
  }, o.converters["sequence<BlobPart>"] = o.sequenceConverter(
    o.converters.BlobPart
  ), o.converters.FilePropertyBag = o.dictionaryConverter([
    {
      key: "lastModified",
      converter: o.converters["long long"],
      get defaultValue() {
        return Date.now();
      }
    },
    {
      key: "type",
      converter: o.converters.DOMString,
      defaultValue: ""
    },
    {
      key: "endings",
      converter: (d) => (d = o.converters.DOMString(d), d = d.toLowerCase(), d !== "native" && (d = "transparent"), d),
      defaultValue: "transparent"
    }
  ]);
  function l(d, h) {
    const C = [];
    for (const u of d)
      if (typeof u == "string") {
        let B = u;
        h.endings === "native" && (B = Q(B)), C.push(g.encode(B));
      } else t.isAnyArrayBuffer(u) || t.isTypedArray(u) ? u.buffer ? C.push(
        new Uint8Array(u.buffer, u.byteOffset, u.byteLength)
      ) : C.push(new Uint8Array(u)) : s(u) && C.push(u);
    return C;
  }
  function Q(d) {
    let h = `
`;
    return process.platform === "win32" && (h = `\r
`), d.replace(/\r?\n/g, h);
  }
  function I(d) {
    return A && d instanceof A || d instanceof c || d && (typeof d.stream == "function" || typeof d.arrayBuffer == "function") && d[Symbol.toStringTag] === "File";
  }
  return To = { File: c, FileLike: E, isFileLike: I }, To;
}
var ko, ha;
function fi() {
  if (ha) return ko;
  ha = 1;
  const { isBlobLike: e, toUSVString: A, makeIterator: t } = TA(), { kState: r } = Et(), { File: s, FileLike: o, isFileLike: n } = pi(), { webidl: i } = hA(), { Blob: a, File: g } = Gt, c = g ?? s;
  class E {
    constructor(I) {
      if (I !== void 0)
        throw i.errors.conversionFailed({
          prefix: "FormData constructor",
          argument: "Argument 1",
          types: ["undefined"]
        });
      this[r] = [];
    }
    append(I, d, h = void 0) {
      if (i.brandCheck(this, E), i.argumentLengthCheck(arguments, 2, { header: "FormData.append" }), arguments.length === 3 && !e(d))
        throw new TypeError(
          "Failed to execute 'append' on 'FormData': parameter 2 is not of type 'Blob'"
        );
      I = i.converters.USVString(I), d = e(d) ? i.converters.Blob(d, { strict: !1 }) : i.converters.USVString(d), h = arguments.length === 3 ? i.converters.USVString(h) : void 0;
      const C = l(I, d, h);
      this[r].push(C);
    }
    delete(I) {
      i.brandCheck(this, E), i.argumentLengthCheck(arguments, 1, { header: "FormData.delete" }), I = i.converters.USVString(I), this[r] = this[r].filter((d) => d.name !== I);
    }
    get(I) {
      i.brandCheck(this, E), i.argumentLengthCheck(arguments, 1, { header: "FormData.get" }), I = i.converters.USVString(I);
      const d = this[r].findIndex((h) => h.name === I);
      return d === -1 ? null : this[r][d].value;
    }
    getAll(I) {
      return i.brandCheck(this, E), i.argumentLengthCheck(arguments, 1, { header: "FormData.getAll" }), I = i.converters.USVString(I), this[r].filter((d) => d.name === I).map((d) => d.value);
    }
    has(I) {
      return i.brandCheck(this, E), i.argumentLengthCheck(arguments, 1, { header: "FormData.has" }), I = i.converters.USVString(I), this[r].findIndex((d) => d.name === I) !== -1;
    }
    set(I, d, h = void 0) {
      if (i.brandCheck(this, E), i.argumentLengthCheck(arguments, 2, { header: "FormData.set" }), arguments.length === 3 && !e(d))
        throw new TypeError(
          "Failed to execute 'set' on 'FormData': parameter 2 is not of type 'Blob'"
        );
      I = i.converters.USVString(I), d = e(d) ? i.converters.Blob(d, { strict: !1 }) : i.converters.USVString(d), h = arguments.length === 3 ? A(h) : void 0;
      const C = l(I, d, h), u = this[r].findIndex((B) => B.name === I);
      u !== -1 ? this[r] = [
        ...this[r].slice(0, u),
        C,
        ...this[r].slice(u + 1).filter((B) => B.name !== I)
      ] : this[r].push(C);
    }
    entries() {
      return i.brandCheck(this, E), t(
        () => this[r].map((I) => [I.name, I.value]),
        "FormData",
        "key+value"
      );
    }
    keys() {
      return i.brandCheck(this, E), t(
        () => this[r].map((I) => [I.name, I.value]),
        "FormData",
        "key"
      );
    }
    values() {
      return i.brandCheck(this, E), t(
        () => this[r].map((I) => [I.name, I.value]),
        "FormData",
        "value"
      );
    }
    /**
     * @param {(value: string, key: string, self: FormData) => void} callbackFn
     * @param {unknown} thisArg
     */
    forEach(I, d = globalThis) {
      if (i.brandCheck(this, E), i.argumentLengthCheck(arguments, 1, { header: "FormData.forEach" }), typeof I != "function")
        throw new TypeError(
          "Failed to execute 'forEach' on 'FormData': parameter 1 is not of type 'Function'."
        );
      for (const [h, C] of this)
        I.apply(d, [C, h, this]);
    }
  }
  E.prototype[Symbol.iterator] = E.prototype.entries, Object.defineProperties(E.prototype, {
    [Symbol.toStringTag]: {
      value: "FormData",
      configurable: !0
    }
  });
  function l(Q, I, d) {
    if (Q = Buffer.from(Q).toString("utf8"), typeof I == "string")
      I = Buffer.from(I).toString("utf8");
    else if (n(I) || (I = I instanceof a ? new c([I], "blob", { type: I.type }) : new o(I, "blob", { type: I.type })), d !== void 0) {
      const h = {
        type: I.type,
        lastModified: I.lastModified
      };
      I = g && I instanceof g || I instanceof s ? new c([I], d, h) : new o(I, d, h);
    }
    return { name: Q, value: I };
  }
  return ko = { FormData: E }, ko;
}
var Fo, da;
function Hs() {
  if (da) return Fo;
  da = 1;
  const e = ud(), A = we, {
    ReadableStreamFrom: t,
    isBlobLike: r,
    isReadableStreamLike: s,
    readableStreamClose: o,
    createDeferredPromise: n,
    fullyReadBody: i
  } = TA(), { FormData: a } = fi(), { kState: g } = Et(), { webidl: c } = hA(), { DOMException: E, structuredClone: l } = _t(), { Blob: Q, File: I } = Gt, { kBodyUsed: d } = Se, h = Me, { isErrored: C } = we, { isUint8Array: u, isArrayBuffer: B } = zg, { File: m } = pi(), { parseMIMEType: f, serializeAMimeType: y } = MA();
  let b;
  try {
    const R = require("node:crypto");
    b = (H) => R.randomInt(0, H);
  } catch {
    b = (R) => Math.floor(Math.random(R));
  }
  let w = globalThis.ReadableStream;
  const S = I ?? m, v = new TextEncoder(), N = new TextDecoder();
  function F(R, H = !1) {
    w || (w = ct.ReadableStream);
    let $ = null;
    R instanceof w ? $ = R : r(R) ? $ = R.stream() : $ = new w({
      async pull(Qe) {
        Qe.enqueue(
          typeof z == "string" ? v.encode(z) : z
        ), queueMicrotask(() => o(Qe));
      },
      start() {
      },
      type: void 0
    }), h(s($));
    let X = null, z = null, W = null, P = null;
    if (typeof R == "string")
      z = R, P = "text/plain;charset=UTF-8";
    else if (R instanceof URLSearchParams)
      z = R.toString(), P = "application/x-www-form-urlencoded;charset=UTF-8";
    else if (B(R))
      z = new Uint8Array(R.slice());
    else if (ArrayBuffer.isView(R))
      z = new Uint8Array(R.buffer.slice(R.byteOffset, R.byteOffset + R.byteLength));
    else if (A.isFormDataLike(R)) {
      const Qe = `----formdata-undici-0${`${b(1e11)}`.padStart(11, "0")}`, Ee = `--${Qe}\r
Content-Disposition: form-data`;
      /*! formdata-polyfill. MIT License. Jimmy Wärting <https://jimmy.warting.se/opensource> */
      const Ge = (me) => me.replace(/\n/g, "%0A").replace(/\r/g, "%0D").replace(/"/g, "%22"), De = (me) => me.replace(/\r?\n|\r/g, `\r
`), Ue = [], ye = new Uint8Array([13, 10]);
      W = 0;
      let Ce = !1;
      for (const [me, Ne] of R)
        if (typeof Ne == "string") {
          const oA = v.encode(Ee + `; name="${Ge(De(me))}"\r
\r
${De(Ne)}\r
`);
          Ue.push(oA), W += oA.byteLength;
        } else {
          const oA = v.encode(`${Ee}; name="${Ge(De(me))}"` + (Ne.name ? `; filename="${Ge(Ne.name)}"` : "") + `\r
Content-Type: ${Ne.type || "application/octet-stream"}\r
\r
`);
          Ue.push(oA, Ne, ye), typeof Ne.size == "number" ? W += oA.byteLength + Ne.size + ye.byteLength : Ce = !0;
        }
      const Ie = v.encode(`--${Qe}--`);
      Ue.push(Ie), W += Ie.byteLength, Ce && (W = null), z = R, X = async function* () {
        for (const me of Ue)
          me.stream ? yield* me.stream() : yield me;
      }, P = "multipart/form-data; boundary=" + Qe;
    } else if (r(R))
      z = R, W = R.size, R.type && (P = R.type);
    else if (typeof R[Symbol.asyncIterator] == "function") {
      if (H)
        throw new TypeError("keepalive");
      if (A.isDisturbed(R) || R.locked)
        throw new TypeError(
          "Response body object should not be disturbed or locked"
        );
      $ = R instanceof w ? R : t(R);
    }
    if ((typeof z == "string" || A.isBuffer(z)) && (W = Buffer.byteLength(z)), X != null) {
      let Qe;
      $ = new w({
        async start() {
          Qe = X(R)[Symbol.asyncIterator]();
        },
        async pull(Ee) {
          const { value: Ge, done: De } = await Qe.next();
          return De ? queueMicrotask(() => {
            Ee.close();
          }) : C($) || Ee.enqueue(new Uint8Array(Ge)), Ee.desiredSize > 0;
        },
        async cancel(Ee) {
          await Qe.return();
        },
        type: void 0
      });
    }
    return [{ stream: $, source: z, length: W }, P];
  }
  function j(R, H = !1) {
    return w || (w = ct.ReadableStream), R instanceof w && (h(!A.isDisturbed(R), "The body has already been consumed."), h(!R.locked, "The stream is locked.")), F(R, H);
  }
  function M(R) {
    const [H, $] = R.stream.tee(), X = l($, { transfer: [$] }), [, z] = X.tee();
    return R.stream = H, {
      stream: z,
      length: R.length,
      source: R.source
    };
  }
  async function* K(R) {
    if (R)
      if (u(R))
        yield R;
      else {
        const H = R.stream;
        if (A.isDisturbed(H))
          throw new TypeError("The body has already been consumed.");
        if (H.locked)
          throw new TypeError("The stream is locked.");
        H[d] = !0, yield* H;
      }
  }
  function ee(R) {
    if (R.aborted)
      throw new E("The operation was aborted.", "AbortError");
  }
  function ie(R) {
    return {
      blob() {
        return ge(this, ($) => {
          let X = de(this);
          return X === "failure" ? X = "" : X && (X = y(X)), new Q([$], { type: X });
        }, R);
      },
      arrayBuffer() {
        return ge(this, ($) => new Uint8Array($).buffer, R);
      },
      text() {
        return ge(this, Ae, R);
      },
      json() {
        return ge(this, ae, R);
      },
      async formData() {
        c.brandCheck(this, R), ee(this[g]);
        const $ = this.headers.get("Content-Type");
        if (/multipart\/form-data/.test($)) {
          const X = {};
          for (const [le, Qe] of this.headers) X[le.toLowerCase()] = Qe;
          const z = new a();
          let W;
          try {
            W = new e({
              headers: X,
              preservePath: !0
            });
          } catch (le) {
            throw new E(`${le}`, "AbortError");
          }
          W.on("field", (le, Qe) => {
            z.append(le, Qe);
          }), W.on("file", (le, Qe, Ee, Ge, De) => {
            const Ue = [];
            if (Ge === "base64" || Ge.toLowerCase() === "base64") {
              let ye = "";
              Qe.on("data", (Ce) => {
                ye += Ce.toString().replace(/[\r\n]/gm, "");
                const Ie = ye.length - ye.length % 4;
                Ue.push(Buffer.from(ye.slice(0, Ie), "base64")), ye = ye.slice(Ie);
              }), Qe.on("end", () => {
                Ue.push(Buffer.from(ye, "base64")), z.append(le, new S(Ue, Ee, { type: De }));
              });
            } else
              Qe.on("data", (ye) => {
                Ue.push(ye);
              }), Qe.on("end", () => {
                z.append(le, new S(Ue, Ee, { type: De }));
              });
          });
          const P = new Promise((le, Qe) => {
            W.on("finish", le), W.on("error", (Ee) => Qe(new TypeError(Ee)));
          });
          if (this.body !== null) for await (const le of K(this[g].body)) W.write(le);
          return W.end(), await P, z;
        } else if (/application\/x-www-form-urlencoded/.test($)) {
          let X;
          try {
            let W = "";
            const P = new TextDecoder("utf-8", { ignoreBOM: !0 });
            for await (const le of K(this[g].body)) {
              if (!u(le))
                throw new TypeError("Expected Uint8Array chunk");
              W += P.decode(le, { stream: !0 });
            }
            W += P.decode(), X = new URLSearchParams(W);
          } catch (W) {
            throw Object.assign(new TypeError(), { cause: W });
          }
          const z = new a();
          for (const [W, P] of X)
            z.append(W, P);
          return z;
        } else
          throw await Promise.resolve(), ee(this[g]), c.errors.exception({
            header: `${R.name}.formData`,
            message: "Could not parse content as FormData."
          });
      }
    };
  }
  function re(R) {
    Object.assign(R.prototype, ie(R));
  }
  async function ge(R, H, $) {
    if (c.brandCheck(R, $), ee(R[g]), Y(R[g].body))
      throw new TypeError("Body is unusable");
    const X = n(), z = (P) => X.reject(P), W = (P) => {
      try {
        X.resolve(H(P));
      } catch (le) {
        z(le);
      }
    };
    return R[g].body == null ? (W(new Uint8Array()), X.promise) : (await i(R[g].body, W, z), X.promise);
  }
  function Y(R) {
    return R != null && (R.stream.locked || A.isDisturbed(R.stream));
  }
  function Ae(R) {
    return R.length === 0 ? "" : (R[0] === 239 && R[1] === 187 && R[2] === 191 && (R = R.subarray(3)), N.decode(R));
  }
  function ae(R) {
    return JSON.parse(Ae(R));
  }
  function de(R) {
    const { headersList: H } = R[g], $ = H.get("content-type");
    return $ === null ? "failure" : f($);
  }
  return Fo = {
    extractBody: F,
    safelyExtractBody: j,
    cloneBody: M,
    mixinBody: re
  }, Fo;
}
const {
  InvalidArgumentError: be,
  NotSupportedError: hd
} = Re, OA = Me, { kHTTP2BuildRequest: dd, kHTTP2CopyHeaders: Qd, kHTTP1BuildRequest: Cd } = Se, EA = we, vl = /^[\^_`a-zA-Z\-0-9!#$%&'*+.|~]+$/, Ll = /[^\t\x20-\x7e\x80-\xff]/, Bd = /[^\u0021-\u00ff]/, bA = Symbol("handler"), He = {};
let So;
try {
  const e = require("diagnostics_channel");
  He.create = e.channel("undici:request:create"), He.bodySent = e.channel("undici:request:bodySent"), He.headers = e.channel("undici:request:headers"), He.trailers = e.channel("undici:request:trailers"), He.error = e.channel("undici:request:error");
} catch {
  He.create = { hasSubscribers: !1 }, He.bodySent = { hasSubscribers: !1 }, He.headers = { hasSubscribers: !1 }, He.trailers = { hasSubscribers: !1 }, He.error = { hasSubscribers: !1 };
}
let Id = class Wn {
  constructor(A, {
    path: t,
    method: r,
    body: s,
    headers: o,
    query: n,
    idempotent: i,
    blocking: a,
    upgrade: g,
    headersTimeout: c,
    bodyTimeout: E,
    reset: l,
    throwOnError: Q,
    expectContinue: I
  }, d) {
    if (typeof t != "string")
      throw new be("path must be a string");
    if (t[0] !== "/" && !(t.startsWith("http://") || t.startsWith("https://")) && r !== "CONNECT")
      throw new be("path must be an absolute URL or start with a slash");
    if (Bd.exec(t) !== null)
      throw new be("invalid request path");
    if (typeof r != "string")
      throw new be("method must be a string");
    if (vl.exec(r) === null)
      throw new be("invalid request method");
    if (g && typeof g != "string")
      throw new be("upgrade must be a string");
    if (c != null && (!Number.isFinite(c) || c < 0))
      throw new be("invalid headersTimeout");
    if (E != null && (!Number.isFinite(E) || E < 0))
      throw new be("invalid bodyTimeout");
    if (l != null && typeof l != "boolean")
      throw new be("invalid reset");
    if (I != null && typeof I != "boolean")
      throw new be("invalid expectContinue");
    if (this.headersTimeout = c, this.bodyTimeout = E, this.throwOnError = Q === !0, this.method = r, this.abort = null, s == null)
      this.body = null;
    else if (EA.isStream(s)) {
      this.body = s;
      const h = this.body._readableState;
      (!h || !h.autoDestroy) && (this.endHandler = function() {
        EA.destroy(this);
      }, this.body.on("end", this.endHandler)), this.errorHandler = (C) => {
        this.abort ? this.abort(C) : this.error = C;
      }, this.body.on("error", this.errorHandler);
    } else if (EA.isBuffer(s))
      this.body = s.byteLength ? s : null;
    else if (ArrayBuffer.isView(s))
      this.body = s.buffer.byteLength ? Buffer.from(s.buffer, s.byteOffset, s.byteLength) : null;
    else if (s instanceof ArrayBuffer)
      this.body = s.byteLength ? Buffer.from(s) : null;
    else if (typeof s == "string")
      this.body = s.length ? Buffer.from(s) : null;
    else if (EA.isFormDataLike(s) || EA.isIterable(s) || EA.isBlobLike(s))
      this.body = s;
    else
      throw new be("body must be a string, a Buffer, a Readable stream, an iterable, or an async iterable");
    if (this.completed = !1, this.aborted = !1, this.upgrade = g || null, this.path = n ? EA.buildURL(t, n) : t, this.origin = A, this.idempotent = i ?? (r === "HEAD" || r === "GET"), this.blocking = a ?? !1, this.reset = l ?? null, this.host = null, this.contentLength = null, this.contentType = null, this.headers = "", this.expectContinue = I ?? !1, Array.isArray(o)) {
      if (o.length % 2 !== 0)
        throw new be("headers array must be even");
      for (let h = 0; h < o.length; h += 2)
        Cr(this, o[h], o[h + 1]);
    } else if (o && typeof o == "object") {
      const h = Object.keys(o);
      for (let C = 0; C < h.length; C++) {
        const u = h[C];
        Cr(this, u, o[u]);
      }
    } else if (o != null)
      throw new be("headers must be an object or an array");
    if (EA.isFormDataLike(this.body)) {
      if (EA.nodeMajor < 16 || EA.nodeMajor === 16 && EA.nodeMinor < 8)
        throw new be("Form-Data bodies are only supported in node v16.8 and newer.");
      So || (So = Hs().extractBody);
      const [h, C] = So(s);
      this.contentType == null && (this.contentType = C, this.headers += `content-type: ${C}\r
`), this.body = h.stream, this.contentLength = h.length;
    } else EA.isBlobLike(s) && this.contentType == null && s.type && (this.contentType = s.type, this.headers += `content-type: ${s.type}\r
`);
    EA.validateHandler(d, r, g), this.servername = EA.getServerName(this.host), this[bA] = d, He.create.hasSubscribers && He.create.publish({ request: this });
  }
  onBodySent(A) {
    if (this[bA].onBodySent)
      try {
        return this[bA].onBodySent(A);
      } catch (t) {
        this.abort(t);
      }
  }
  onRequestSent() {
    if (He.bodySent.hasSubscribers && He.bodySent.publish({ request: this }), this[bA].onRequestSent)
      try {
        return this[bA].onRequestSent();
      } catch (A) {
        this.abort(A);
      }
  }
  onConnect(A) {
    if (OA(!this.aborted), OA(!this.completed), this.error)
      A(this.error);
    else
      return this.abort = A, this[bA].onConnect(A);
  }
  onHeaders(A, t, r, s) {
    OA(!this.aborted), OA(!this.completed), He.headers.hasSubscribers && He.headers.publish({ request: this, response: { statusCode: A, headers: t, statusText: s } });
    try {
      return this[bA].onHeaders(A, t, r, s);
    } catch (o) {
      this.abort(o);
    }
  }
  onData(A) {
    OA(!this.aborted), OA(!this.completed);
    try {
      return this[bA].onData(A);
    } catch (t) {
      return this.abort(t), !1;
    }
  }
  onUpgrade(A, t, r) {
    return OA(!this.aborted), OA(!this.completed), this[bA].onUpgrade(A, t, r);
  }
  onComplete(A) {
    this.onFinally(), OA(!this.aborted), this.completed = !0, He.trailers.hasSubscribers && He.trailers.publish({ request: this, trailers: A });
    try {
      return this[bA].onComplete(A);
    } catch (t) {
      this.onError(t);
    }
  }
  onError(A) {
    if (this.onFinally(), He.error.hasSubscribers && He.error.publish({ request: this, error: A }), !this.aborted)
      return this.aborted = !0, this[bA].onError(A);
  }
  onFinally() {
    this.errorHandler && (this.body.off("error", this.errorHandler), this.errorHandler = null), this.endHandler && (this.body.off("end", this.endHandler), this.endHandler = null);
  }
  // TODO: adjust to support H2
  addHeader(A, t) {
    return Cr(this, A, t), this;
  }
  static [Cd](A, t, r) {
    return new Wn(A, t, r);
  }
  static [dd](A, t, r) {
    const s = t.headers;
    t = { ...t, headers: null };
    const o = new Wn(A, t, r);
    if (o.headers = {}, Array.isArray(s)) {
      if (s.length % 2 !== 0)
        throw new be("headers array must be even");
      for (let n = 0; n < s.length; n += 2)
        Cr(o, s[n], s[n + 1], !0);
    } else if (s && typeof s == "object") {
      const n = Object.keys(s);
      for (let i = 0; i < n.length; i++) {
        const a = n[i];
        Cr(o, a, s[a], !0);
      }
    } else if (s != null)
      throw new be("headers must be an object or an array");
    return o;
  }
  static [Qd](A) {
    const t = A.split(`\r
`), r = {};
    for (const s of t) {
      const [o, n] = s.split(": ");
      n == null || n.length === 0 || (r[o] ? r[o] += `,${n}` : r[o] = n);
    }
    return r;
  }
};
function ht(e, A, t) {
  if (A && typeof A == "object")
    throw new be(`invalid ${e} header`);
  if (A = A != null ? `${A}` : "", Ll.exec(A) !== null)
    throw new be(`invalid ${e} header`);
  return t ? A : `${e}: ${A}\r
`;
}
function Cr(e, A, t, r = !1) {
  if (t && typeof t == "object" && !Array.isArray(t))
    throw new be(`invalid ${A} header`);
  if (t === void 0)
    return;
  if (e.host === null && A.length === 4 && A.toLowerCase() === "host") {
    if (Ll.exec(t) !== null)
      throw new be(`invalid ${A} header`);
    e.host = t;
  } else if (e.contentLength === null && A.length === 14 && A.toLowerCase() === "content-length") {
    if (e.contentLength = parseInt(t, 10), !Number.isFinite(e.contentLength))
      throw new be("invalid content-length header");
  } else if (e.contentType === null && A.length === 12 && A.toLowerCase() === "content-type")
    e.contentType = t, r ? e.headers[A] = ht(A, t, r) : e.headers += ht(A, t);
  else {
    if (A.length === 17 && A.toLowerCase() === "transfer-encoding")
      throw new be("invalid transfer-encoding header");
    if (A.length === 10 && A.toLowerCase() === "connection") {
      const s = typeof t == "string" ? t.toLowerCase() : null;
      if (s !== "close" && s !== "keep-alive")
        throw new be("invalid connection header");
      s === "close" && (e.reset = !0);
    } else {
      if (A.length === 10 && A.toLowerCase() === "keep-alive")
        throw new be("invalid keep-alive header");
      if (A.length === 7 && A.toLowerCase() === "upgrade")
        throw new be("invalid upgrade header");
      if (A.length === 6 && A.toLowerCase() === "expect")
        throw new hd("expect header not supported");
      if (vl.exec(A) === null)
        throw new be("invalid header key");
      if (Array.isArray(t))
        for (let s = 0; s < t.length; s++)
          r ? e.headers[A] ? e.headers[A] += `,${ht(A, t[s], r)}` : e.headers[A] = ht(A, t[s], r) : e.headers += ht(A, t[s]);
      else
        r ? e.headers[A] = ht(A, t, r) : e.headers += ht(A, t);
    }
  }
}
var pd = Id;
const fd = nr;
let md = class extends fd {
  dispatch() {
    throw new Error("not implemented");
  }
  close() {
    throw new Error("not implemented");
  }
  destroy() {
    throw new Error("not implemented");
  }
};
var mi = md;
const wd = mi, {
  ClientDestroyedError: Uo,
  ClientClosedError: yd,
  InvalidArgumentError: Mt
} = Re, { kDestroy: bd, kClose: Rd, kDispatch: Go, kInterceptors: dt } = Se, Ot = Symbol("destroyed"), Br = Symbol("closed"), PA = Symbol("onDestroyed"), Pt = Symbol("onClosed"), ns = Symbol("Intercepted Dispatch");
let Dd = class extends wd {
  constructor() {
    super(), this[Ot] = !1, this[PA] = null, this[Br] = !1, this[Pt] = [];
  }
  get destroyed() {
    return this[Ot];
  }
  get closed() {
    return this[Br];
  }
  get interceptors() {
    return this[dt];
  }
  set interceptors(A) {
    if (A) {
      for (let t = A.length - 1; t >= 0; t--)
        if (typeof this[dt][t] != "function")
          throw new Mt("interceptor must be an function");
    }
    this[dt] = A;
  }
  close(A) {
    if (A === void 0)
      return new Promise((r, s) => {
        this.close((o, n) => o ? s(o) : r(n));
      });
    if (typeof A != "function")
      throw new Mt("invalid callback");
    if (this[Ot]) {
      queueMicrotask(() => A(new Uo(), null));
      return;
    }
    if (this[Br]) {
      this[Pt] ? this[Pt].push(A) : queueMicrotask(() => A(null, null));
      return;
    }
    this[Br] = !0, this[Pt].push(A);
    const t = () => {
      const r = this[Pt];
      this[Pt] = null;
      for (let s = 0; s < r.length; s++)
        r[s](null, null);
    };
    this[Rd]().then(() => this.destroy()).then(() => {
      queueMicrotask(t);
    });
  }
  destroy(A, t) {
    if (typeof A == "function" && (t = A, A = null), t === void 0)
      return new Promise((s, o) => {
        this.destroy(A, (n, i) => n ? (
          /* istanbul ignore next: should never error */
          o(n)
        ) : s(i));
      });
    if (typeof t != "function")
      throw new Mt("invalid callback");
    if (this[Ot]) {
      this[PA] ? this[PA].push(t) : queueMicrotask(() => t(null, null));
      return;
    }
    A || (A = new Uo()), this[Ot] = !0, this[PA] = this[PA] || [], this[PA].push(t);
    const r = () => {
      const s = this[PA];
      this[PA] = null;
      for (let o = 0; o < s.length; o++)
        s[o](null, null);
    };
    this[bd](A).then(() => {
      queueMicrotask(r);
    });
  }
  [ns](A, t) {
    if (!this[dt] || this[dt].length === 0)
      return this[ns] = this[Go], this[Go](A, t);
    let r = this[Go].bind(this);
    for (let s = this[dt].length - 1; s >= 0; s--)
      r = this[dt][s](r);
    return this[ns] = r, r(A, t);
  }
  dispatch(A, t) {
    if (!t || typeof t != "object")
      throw new Mt("handler must be an object");
    try {
      if (!A || typeof A != "object")
        throw new Mt("opts must be an object.");
      if (this[Ot] || this[PA])
        throw new Uo();
      if (this[Br])
        throw new yd();
      return this[ns](A, t);
    } catch (r) {
      if (typeof t.onError != "function")
        throw new Mt("invalid onError method");
      return t.onError(r), !1;
    }
  }
};
var Vs = Dd;
const Td = Ei, Qa = Me, Ml = we, { InvalidArgumentError: kd, ConnectTimeoutError: Fd } = Re;
let _o, jn;
O.FinalizationRegistry && !process.env.NODE_V8_COVERAGE ? jn = class {
  constructor(A) {
    this._maxCachedSessions = A, this._sessionCache = /* @__PURE__ */ new Map(), this._sessionRegistry = new O.FinalizationRegistry((t) => {
      if (this._sessionCache.size < this._maxCachedSessions)
        return;
      const r = this._sessionCache.get(t);
      r !== void 0 && r.deref() === void 0 && this._sessionCache.delete(t);
    });
  }
  get(A) {
    const t = this._sessionCache.get(A);
    return t ? t.deref() : null;
  }
  set(A, t) {
    this._maxCachedSessions !== 0 && (this._sessionCache.set(A, new WeakRef(t)), this._sessionRegistry.register(t, A));
  }
} : jn = class {
  constructor(A) {
    this._maxCachedSessions = A, this._sessionCache = /* @__PURE__ */ new Map();
  }
  get(A) {
    return this._sessionCache.get(A);
  }
  set(A, t) {
    if (this._maxCachedSessions !== 0) {
      if (this._sessionCache.size >= this._maxCachedSessions) {
        const { value: r } = this._sessionCache.keys().next();
        this._sessionCache.delete(r);
      }
      this._sessionCache.set(A, t);
    }
  }
};
function Sd({ allowH2: e, maxCachedSessions: A, socketPath: t, timeout: r, ...s }) {
  if (A != null && (!Number.isInteger(A) || A < 0))
    throw new kd("maxCachedSessions must be a positive integer or zero");
  const o = { path: t, ...s }, n = new jn(A ?? 100);
  return r = r ?? 1e4, e = e ?? !1, function({ hostname: a, host: g, protocol: c, port: E, servername: l, localAddress: Q, httpSocket: I }, d) {
    let h;
    if (c === "https:") {
      _o || (_o = jg), l = l || o.servername || Ml.getServerName(g) || null;
      const u = l || a, B = n.get(u) || null;
      Qa(u), h = _o.connect({
        highWaterMark: 16384,
        // TLS in node can't have bigger HWM anyway...
        ...o,
        servername: l,
        session: B,
        localAddress: Q,
        // TODO(HTTP/2): Add support for h2c
        ALPNProtocols: e ? ["http/1.1", "h2"] : ["http/1.1"],
        socket: I,
        // upgrade socket connection
        port: E || 443,
        host: a
      }), h.on("session", function(m) {
        n.set(u, m);
      });
    } else
      Qa(!I, "httpSocket can only be sent on TLS update"), h = Td.connect({
        highWaterMark: 64 * 1024,
        // Same as nodejs fs streams.
        ...o,
        localAddress: Q,
        port: E || 80,
        host: a
      });
    if (o.keepAlive == null || o.keepAlive) {
      const u = o.keepAliveInitialDelay === void 0 ? 6e4 : o.keepAliveInitialDelay;
      h.setKeepAlive(!0, u);
    }
    const C = Ud(() => Gd(h), r);
    return h.setNoDelay(!0).once(c === "https:" ? "secureConnect" : "connect", function() {
      if (C(), d) {
        const u = d;
        d = null, u(null, this);
      }
    }).on("error", function(u) {
      if (C(), d) {
        const B = d;
        d = null, B(u);
      }
    }), h;
  };
}
function Ud(e, A) {
  if (!A)
    return () => {
    };
  let t = null, r = null;
  const s = setTimeout(() => {
    t = setImmediate(() => {
      process.platform === "win32" ? r = setImmediate(() => e()) : e();
    });
  }, A);
  return () => {
    clearTimeout(s), clearImmediate(t), clearImmediate(r);
  };
}
function Gd(e) {
  Ml.destroy(e, new Fd());
}
var qs = Sd, No = {}, Ir = {}, Ca;
function _d() {
  if (Ca) return Ir;
  Ca = 1, Object.defineProperty(Ir, "__esModule", { value: !0 }), Ir.enumToMap = void 0;
  function e(A) {
    const t = {};
    return Object.keys(A).forEach((r) => {
      const s = A[r];
      typeof s == "number" && (t[r] = s);
    }), t;
  }
  return Ir.enumToMap = e, Ir;
}
var Ba;
function Nd() {
  return Ba || (Ba = 1, function(e) {
    Object.defineProperty(e, "__esModule", { value: !0 }), e.SPECIAL_HEADERS = e.HEADER_STATE = e.MINOR = e.MAJOR = e.CONNECTION_TOKEN_CHARS = e.HEADER_CHARS = e.TOKEN = e.STRICT_TOKEN = e.HEX = e.URL_CHAR = e.STRICT_URL_CHAR = e.USERINFO_CHARS = e.MARK = e.ALPHANUM = e.NUM = e.HEX_MAP = e.NUM_MAP = e.ALPHA = e.FINISH = e.H_METHOD_MAP = e.METHOD_MAP = e.METHODS_RTSP = e.METHODS_ICE = e.METHODS_HTTP = e.METHODS = e.LENIENT_FLAGS = e.FLAGS = e.TYPE = e.ERROR = void 0;
    const A = _d();
    (function(s) {
      s[s.OK = 0] = "OK", s[s.INTERNAL = 1] = "INTERNAL", s[s.STRICT = 2] = "STRICT", s[s.LF_EXPECTED = 3] = "LF_EXPECTED", s[s.UNEXPECTED_CONTENT_LENGTH = 4] = "UNEXPECTED_CONTENT_LENGTH", s[s.CLOSED_CONNECTION = 5] = "CLOSED_CONNECTION", s[s.INVALID_METHOD = 6] = "INVALID_METHOD", s[s.INVALID_URL = 7] = "INVALID_URL", s[s.INVALID_CONSTANT = 8] = "INVALID_CONSTANT", s[s.INVALID_VERSION = 9] = "INVALID_VERSION", s[s.INVALID_HEADER_TOKEN = 10] = "INVALID_HEADER_TOKEN", s[s.INVALID_CONTENT_LENGTH = 11] = "INVALID_CONTENT_LENGTH", s[s.INVALID_CHUNK_SIZE = 12] = "INVALID_CHUNK_SIZE", s[s.INVALID_STATUS = 13] = "INVALID_STATUS", s[s.INVALID_EOF_STATE = 14] = "INVALID_EOF_STATE", s[s.INVALID_TRANSFER_ENCODING = 15] = "INVALID_TRANSFER_ENCODING", s[s.CB_MESSAGE_BEGIN = 16] = "CB_MESSAGE_BEGIN", s[s.CB_HEADERS_COMPLETE = 17] = "CB_HEADERS_COMPLETE", s[s.CB_MESSAGE_COMPLETE = 18] = "CB_MESSAGE_COMPLETE", s[s.CB_CHUNK_HEADER = 19] = "CB_CHUNK_HEADER", s[s.CB_CHUNK_COMPLETE = 20] = "CB_CHUNK_COMPLETE", s[s.PAUSED = 21] = "PAUSED", s[s.PAUSED_UPGRADE = 22] = "PAUSED_UPGRADE", s[s.PAUSED_H2_UPGRADE = 23] = "PAUSED_H2_UPGRADE", s[s.USER = 24] = "USER";
    })(e.ERROR || (e.ERROR = {})), function(s) {
      s[s.BOTH = 0] = "BOTH", s[s.REQUEST = 1] = "REQUEST", s[s.RESPONSE = 2] = "RESPONSE";
    }(e.TYPE || (e.TYPE = {})), function(s) {
      s[s.CONNECTION_KEEP_ALIVE = 1] = "CONNECTION_KEEP_ALIVE", s[s.CONNECTION_CLOSE = 2] = "CONNECTION_CLOSE", s[s.CONNECTION_UPGRADE = 4] = "CONNECTION_UPGRADE", s[s.CHUNKED = 8] = "CHUNKED", s[s.UPGRADE = 16] = "UPGRADE", s[s.CONTENT_LENGTH = 32] = "CONTENT_LENGTH", s[s.SKIPBODY = 64] = "SKIPBODY", s[s.TRAILING = 128] = "TRAILING", s[s.TRANSFER_ENCODING = 512] = "TRANSFER_ENCODING";
    }(e.FLAGS || (e.FLAGS = {})), function(s) {
      s[s.HEADERS = 1] = "HEADERS", s[s.CHUNKED_LENGTH = 2] = "CHUNKED_LENGTH", s[s.KEEP_ALIVE = 4] = "KEEP_ALIVE";
    }(e.LENIENT_FLAGS || (e.LENIENT_FLAGS = {}));
    var t;
    (function(s) {
      s[s.DELETE = 0] = "DELETE", s[s.GET = 1] = "GET", s[s.HEAD = 2] = "HEAD", s[s.POST = 3] = "POST", s[s.PUT = 4] = "PUT", s[s.CONNECT = 5] = "CONNECT", s[s.OPTIONS = 6] = "OPTIONS", s[s.TRACE = 7] = "TRACE", s[s.COPY = 8] = "COPY", s[s.LOCK = 9] = "LOCK", s[s.MKCOL = 10] = "MKCOL", s[s.MOVE = 11] = "MOVE", s[s.PROPFIND = 12] = "PROPFIND", s[s.PROPPATCH = 13] = "PROPPATCH", s[s.SEARCH = 14] = "SEARCH", s[s.UNLOCK = 15] = "UNLOCK", s[s.BIND = 16] = "BIND", s[s.REBIND = 17] = "REBIND", s[s.UNBIND = 18] = "UNBIND", s[s.ACL = 19] = "ACL", s[s.REPORT = 20] = "REPORT", s[s.MKACTIVITY = 21] = "MKACTIVITY", s[s.CHECKOUT = 22] = "CHECKOUT", s[s.MERGE = 23] = "MERGE", s[s["M-SEARCH"] = 24] = "M-SEARCH", s[s.NOTIFY = 25] = "NOTIFY", s[s.SUBSCRIBE = 26] = "SUBSCRIBE", s[s.UNSUBSCRIBE = 27] = "UNSUBSCRIBE", s[s.PATCH = 28] = "PATCH", s[s.PURGE = 29] = "PURGE", s[s.MKCALENDAR = 30] = "MKCALENDAR", s[s.LINK = 31] = "LINK", s[s.UNLINK = 32] = "UNLINK", s[s.SOURCE = 33] = "SOURCE", s[s.PRI = 34] = "PRI", s[s.DESCRIBE = 35] = "DESCRIBE", s[s.ANNOUNCE = 36] = "ANNOUNCE", s[s.SETUP = 37] = "SETUP", s[s.PLAY = 38] = "PLAY", s[s.PAUSE = 39] = "PAUSE", s[s.TEARDOWN = 40] = "TEARDOWN", s[s.GET_PARAMETER = 41] = "GET_PARAMETER", s[s.SET_PARAMETER = 42] = "SET_PARAMETER", s[s.REDIRECT = 43] = "REDIRECT", s[s.RECORD = 44] = "RECORD", s[s.FLUSH = 45] = "FLUSH";
    })(t = e.METHODS || (e.METHODS = {})), e.METHODS_HTTP = [
      t.DELETE,
      t.GET,
      t.HEAD,
      t.POST,
      t.PUT,
      t.CONNECT,
      t.OPTIONS,
      t.TRACE,
      t.COPY,
      t.LOCK,
      t.MKCOL,
      t.MOVE,
      t.PROPFIND,
      t.PROPPATCH,
      t.SEARCH,
      t.UNLOCK,
      t.BIND,
      t.REBIND,
      t.UNBIND,
      t.ACL,
      t.REPORT,
      t.MKACTIVITY,
      t.CHECKOUT,
      t.MERGE,
      t["M-SEARCH"],
      t.NOTIFY,
      t.SUBSCRIBE,
      t.UNSUBSCRIBE,
      t.PATCH,
      t.PURGE,
      t.MKCALENDAR,
      t.LINK,
      t.UNLINK,
      t.PRI,
      // TODO(indutny): should we allow it with HTTP?
      t.SOURCE
    ], e.METHODS_ICE = [
      t.SOURCE
    ], e.METHODS_RTSP = [
      t.OPTIONS,
      t.DESCRIBE,
      t.ANNOUNCE,
      t.SETUP,
      t.PLAY,
      t.PAUSE,
      t.TEARDOWN,
      t.GET_PARAMETER,
      t.SET_PARAMETER,
      t.REDIRECT,
      t.RECORD,
      t.FLUSH,
      // For AirPlay
      t.GET,
      t.POST
    ], e.METHOD_MAP = A.enumToMap(t), e.H_METHOD_MAP = {}, Object.keys(e.METHOD_MAP).forEach((s) => {
      /^H/.test(s) && (e.H_METHOD_MAP[s] = e.METHOD_MAP[s]);
    }), function(s) {
      s[s.SAFE = 0] = "SAFE", s[s.SAFE_WITH_CB = 1] = "SAFE_WITH_CB", s[s.UNSAFE = 2] = "UNSAFE";
    }(e.FINISH || (e.FINISH = {})), e.ALPHA = [];
    for (let s = 65; s <= 90; s++)
      e.ALPHA.push(String.fromCharCode(s)), e.ALPHA.push(String.fromCharCode(s + 32));
    e.NUM_MAP = {
      0: 0,
      1: 1,
      2: 2,
      3: 3,
      4: 4,
      5: 5,
      6: 6,
      7: 7,
      8: 8,
      9: 9
    }, e.HEX_MAP = {
      0: 0,
      1: 1,
      2: 2,
      3: 3,
      4: 4,
      5: 5,
      6: 6,
      7: 7,
      8: 8,
      9: 9,
      A: 10,
      B: 11,
      C: 12,
      D: 13,
      E: 14,
      F: 15,
      a: 10,
      b: 11,
      c: 12,
      d: 13,
      e: 14,
      f: 15
    }, e.NUM = [
      "0",
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9"
    ], e.ALPHANUM = e.ALPHA.concat(e.NUM), e.MARK = ["-", "_", ".", "!", "~", "*", "'", "(", ")"], e.USERINFO_CHARS = e.ALPHANUM.concat(e.MARK).concat(["%", ";", ":", "&", "=", "+", "$", ","]), e.STRICT_URL_CHAR = [
      "!",
      '"',
      "$",
      "%",
      "&",
      "'",
      "(",
      ")",
      "*",
      "+",
      ",",
      "-",
      ".",
      "/",
      ":",
      ";",
      "<",
      "=",
      ">",
      "@",
      "[",
      "\\",
      "]",
      "^",
      "_",
      "`",
      "{",
      "|",
      "}",
      "~"
    ].concat(e.ALPHANUM), e.URL_CHAR = e.STRICT_URL_CHAR.concat(["	", "\f"]);
    for (let s = 128; s <= 255; s++)
      e.URL_CHAR.push(s);
    e.HEX = e.NUM.concat(["a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F"]), e.STRICT_TOKEN = [
      "!",
      "#",
      "$",
      "%",
      "&",
      "'",
      "*",
      "+",
      "-",
      ".",
      "^",
      "_",
      "`",
      "|",
      "~"
    ].concat(e.ALPHANUM), e.TOKEN = e.STRICT_TOKEN.concat([" "]), e.HEADER_CHARS = ["	"];
    for (let s = 32; s <= 255; s++)
      s !== 127 && e.HEADER_CHARS.push(s);
    e.CONNECTION_TOKEN_CHARS = e.HEADER_CHARS.filter((s) => s !== 44), e.MAJOR = e.NUM_MAP, e.MINOR = e.MAJOR;
    var r;
    (function(s) {
      s[s.GENERAL = 0] = "GENERAL", s[s.CONNECTION = 1] = "CONNECTION", s[s.CONTENT_LENGTH = 2] = "CONTENT_LENGTH", s[s.TRANSFER_ENCODING = 3] = "TRANSFER_ENCODING", s[s.UPGRADE = 4] = "UPGRADE", s[s.CONNECTION_KEEP_ALIVE = 5] = "CONNECTION_KEEP_ALIVE", s[s.CONNECTION_CLOSE = 6] = "CONNECTION_CLOSE", s[s.CONNECTION_UPGRADE = 7] = "CONNECTION_UPGRADE", s[s.TRANSFER_ENCODING_CHUNKED = 8] = "TRANSFER_ENCODING_CHUNKED";
    })(r = e.HEADER_STATE || (e.HEADER_STATE = {})), e.SPECIAL_HEADERS = {
      connection: r.CONNECTION,
      "content-length": r.CONTENT_LENGTH,
      "proxy-connection": r.CONNECTION,
      "transfer-encoding": r.TRANSFER_ENCODING,
      upgrade: r.UPGRADE
    };
  }(No)), No;
}
const JA = we, { kBodyUsed: Nr } = Se, wi = Me, { InvalidArgumentError: vd } = Re, Ld = nr, Md = [300, 301, 302, 303, 307, 308], Ia = Symbol("body");
class pa {
  constructor(A) {
    this[Ia] = A, this[Nr] = !1;
  }
  async *[Symbol.asyncIterator]() {
    wi(!this[Nr], "disturbed"), this[Nr] = !0, yield* this[Ia];
  }
}
let Od = class {
  constructor(A, t, r, s) {
    if (t != null && (!Number.isInteger(t) || t < 0))
      throw new vd("maxRedirections must be a positive number");
    JA.validateHandler(s, r.method, r.upgrade), this.dispatch = A, this.location = null, this.abort = null, this.opts = { ...r, maxRedirections: 0 }, this.maxRedirections = t, this.handler = s, this.history = [], JA.isStream(this.opts.body) ? (JA.bodyLength(this.opts.body) === 0 && this.opts.body.on("data", function() {
      wi(!1);
    }), typeof this.opts.body.readableDidRead != "boolean" && (this.opts.body[Nr] = !1, Ld.prototype.on.call(this.opts.body, "data", function() {
      this[Nr] = !0;
    }))) : this.opts.body && typeof this.opts.body.pipeTo == "function" ? this.opts.body = new pa(this.opts.body) : this.opts.body && typeof this.opts.body != "string" && !ArrayBuffer.isView(this.opts.body) && JA.isIterable(this.opts.body) && (this.opts.body = new pa(this.opts.body));
  }
  onConnect(A) {
    this.abort = A, this.handler.onConnect(A, { history: this.history });
  }
  onUpgrade(A, t, r) {
    this.handler.onUpgrade(A, t, r);
  }
  onError(A) {
    this.handler.onError(A);
  }
  onHeaders(A, t, r, s) {
    if (this.location = this.history.length >= this.maxRedirections || JA.isDisturbed(this.opts.body) ? null : Pd(A, t), this.opts.origin && this.history.push(new URL(this.opts.path, this.opts.origin)), !this.location)
      return this.handler.onHeaders(A, t, r, s);
    const { origin: o, pathname: n, search: i } = JA.parseURL(new URL(this.location, this.opts.origin && new URL(this.opts.path, this.opts.origin))), a = i ? `${n}${i}` : n;
    this.opts.headers = Yd(this.opts.headers, A === 303, this.opts.origin !== o), this.opts.path = a, this.opts.origin = o, this.opts.maxRedirections = 0, this.opts.query = null, A === 303 && this.opts.method !== "HEAD" && (this.opts.method = "GET", this.opts.body = null);
  }
  onData(A) {
    if (!this.location) return this.handler.onData(A);
  }
  onComplete(A) {
    this.location ? (this.location = null, this.abort = null, this.dispatch(this.opts, this)) : this.handler.onComplete(A);
  }
  onBodySent(A) {
    this.handler.onBodySent && this.handler.onBodySent(A);
  }
};
function Pd(e, A) {
  if (Md.indexOf(e) === -1)
    return null;
  for (let t = 0; t < A.length; t += 2)
    if (A[t].toString().toLowerCase() === "location")
      return A[t + 1];
}
function fa(e, A, t) {
  if (e.length === 4)
    return JA.headerNameToString(e) === "host";
  if (A && JA.headerNameToString(e).startsWith("content-"))
    return !0;
  if (t && (e.length === 13 || e.length === 6 || e.length === 19)) {
    const r = JA.headerNameToString(e);
    return r === "authorization" || r === "cookie" || r === "proxy-authorization";
  }
  return !1;
}
function Yd(e, A, t) {
  const r = [];
  if (Array.isArray(e))
    for (let s = 0; s < e.length; s += 2)
      fa(e[s], A, t) || r.push(e[s], e[s + 1]);
  else if (e && typeof e == "object")
    for (const s of Object.keys(e))
      fa(s, A, t) || r.push(s, e[s]);
  else
    wi(e == null, "headers must be an object or an array");
  return r;
}
var Ol = Od;
const xd = Ol;
function Jd({ maxRedirections: e }) {
  return (A) => function(r, s) {
    const { maxRedirections: o = e } = r;
    if (!o)
      return A(r, s);
    const n = new xd(A, o, r, s);
    return r = { ...r, maxRedirections: 0 }, A(r, n);
  };
}
var yi = Jd, vo, ma;
function wa() {
  return ma || (ma = 1, vo = "AGFzbQEAAAABMAhgAX8Bf2ADf39/AX9gBH9/f38Bf2AAAGADf39/AGABfwBgAn9/AGAGf39/f39/AALLAQgDZW52GHdhc21fb25faGVhZGVyc19jb21wbGV0ZQACA2VudhV3YXNtX29uX21lc3NhZ2VfYmVnaW4AAANlbnYLd2FzbV9vbl91cmwAAQNlbnYOd2FzbV9vbl9zdGF0dXMAAQNlbnYUd2FzbV9vbl9oZWFkZXJfZmllbGQAAQNlbnYUd2FzbV9vbl9oZWFkZXJfdmFsdWUAAQNlbnYMd2FzbV9vbl9ib2R5AAEDZW52GHdhc21fb25fbWVzc2FnZV9jb21wbGV0ZQAAA0ZFAwMEAAAFAAAAAAAABQEFAAUFBQAABgAAAAAGBgYGAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAAABAQcAAAUFAwABBAUBcAESEgUDAQACBggBfwFBgNQECwfRBSIGbWVtb3J5AgALX2luaXRpYWxpemUACRlfX2luZGlyZWN0X2Z1bmN0aW9uX3RhYmxlAQALbGxodHRwX2luaXQAChhsbGh0dHBfc2hvdWxkX2tlZXBfYWxpdmUAQQxsbGh0dHBfYWxsb2MADAZtYWxsb2MARgtsbGh0dHBfZnJlZQANBGZyZWUASA9sbGh0dHBfZ2V0X3R5cGUADhVsbGh0dHBfZ2V0X2h0dHBfbWFqb3IADxVsbGh0dHBfZ2V0X2h0dHBfbWlub3IAEBFsbGh0dHBfZ2V0X21ldGhvZAARFmxsaHR0cF9nZXRfc3RhdHVzX2NvZGUAEhJsbGh0dHBfZ2V0X3VwZ3JhZGUAEwxsbGh0dHBfcmVzZXQAFA5sbGh0dHBfZXhlY3V0ZQAVFGxsaHR0cF9zZXR0aW5nc19pbml0ABYNbGxodHRwX2ZpbmlzaAAXDGxsaHR0cF9wYXVzZQAYDWxsaHR0cF9yZXN1bWUAGRtsbGh0dHBfcmVzdW1lX2FmdGVyX3VwZ3JhZGUAGhBsbGh0dHBfZ2V0X2Vycm5vABsXbGxodHRwX2dldF9lcnJvcl9yZWFzb24AHBdsbGh0dHBfc2V0X2Vycm9yX3JlYXNvbgAdFGxsaHR0cF9nZXRfZXJyb3JfcG9zAB4RbGxodHRwX2Vycm5vX25hbWUAHxJsbGh0dHBfbWV0aG9kX25hbWUAIBJs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ADcDACAAQShqQgA3AwAgAEEgakIANwMAIABBEGpCADcDACAAQQhqQgA3AwAgAEHdATYCHEEAC3sBAX8CQCAAKAIMIgMNAAJAIAAoAgRFDQAgACABNgIECwJAIAAgASACEMSAgIAAIgMNACAAKAIMDwsgACADNgIcQQAhAyAAKAIEIgFFDQAgACABIAIgACgCCBGBgICAAAAiAUUNACAAIAI2AhQgACABNgIMIAEhAwsgAwvk8wEDDn8DfgR/I4CAgIAAQRBrIgMkgICAgAAgASEEIAEhBSABIQYgASEHIAEhCCABIQkgASEKIAEhCyABIQwgASENIAEhDiABIQ8CQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgACgCHCIQQX9qDt0B2gEB2QECAwQFBgcICQoLDA0O2AEPENcBERLWARMUFRYXGBkaG+AB3wEcHR7VAR8gISIjJCXUASYnKCkqKyzTAdIBLS7RAdABLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVG2wFHSElKzwHOAUvNAUzMAU1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4ABgQGCAYMBhAGFAYYBhwGIAYkB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QAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAC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FCAAIBA2AgxBACEQDLIBCyAAKAIEIRAgAEEANgIEAkAgACAQIAEQp4CAgAAiEA0AIAEhAQxNCyAAQdMANgIcIAAgATYCFCAAIBA2AgxBACEQDLEBCyAAKAIEIRAgAEEANgIEAkAgACAQIAEQp4CAgAAiEA0AIAEhAQxRCyAAQeUANgIcIAAgATYCFCAAIBA2AgxBACEQDLABCyAAQQA2AhwgACABNgIUIABBxoqAgAA2AhAgAEEHNgIMQQAhEAyvAQsgACgCBCEQIABBADYCBAJAIAAgECABEKeAgIAAIhANACABIQEMSQsgAEHSADYCHCAAIAE2AhQgACAQNgIMQQAhEAyuAQsgACgCBCEQIABBADYCBAJAIAAgECABEKeAgIAAIhANACABIQEMSQsgAEHTADYCHCAAIAE2AhQgACAQNgIMQQAhEAytAQsgACgCBCEQIABBADYCBAJAIAAgECABEKeAgIAAIhANACABIQEMTQsgAEHlADYCHCAAIAE2AhQgACAQNgIMQQAhEAysAQsgAEEANgIcIAAgATYCFCAAQdyIgIAANgIQIABBBzYCDEEAIRAMqwELIBBBP0cNASABQQFqIQELQQUhEAyQAQtBACEQIABBADYCHCAAIAE2AhQgAEH9koCAADYCECAAQQc2AgwMqAELIAAoAgQhECAAQQA2AgQCQCAAIBAgARCngICAACIQDQAgASEBDEILIABB0gA2AhwgACABNgIUIAAgEDYCDEEAIRAMpwELIAAoAgQhECAAQQA2AgQCQCAAIBAgARCngICAACIQDQAgASEBDEILIABB0wA2AhwgACABNgIUIAAgEDYCDEEAIRAMpgELIAAoAgQhECAAQQA2AgQCQCAAIBAgARCngICAACIQDQAgASEBDEYLIABB5QA2AhwgACABNgIUIAAgEDYCDEEAIRAMpQELIAAoAgQhASAAQQA2AgQCQCAAIAEgFBCngICAACIBDQAgFCEBDD8LIABB0gA2AhwgACAUNgIUIAAgATYCDEEAIRAMpAELIAAoAgQhASAAQQA2AgQCQCAAIAEgFBCngICAACIBDQAgFCEBDD8LIABB0wA2AhwgACAUNgIUIAAgATYCDEEAIRAMowELIAAoAgQhASAAQQA2AgQCQCAAIAEgFBCngICAACIBDQAgFCEBDEMLIABB5QA2AhwgACAU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YWdlX2JlZ2luYCBjYWxsYmFjayBlcnJvcgBgb25fY2h1bmtfZXh0ZW5zaW9uX3ZhbHVlYCBjYWxsYmFjayBlcnJvcgBgb25fc3RhdHVzX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fdmVyc2lvbl9jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX3VybF9jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX2NodW5rX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25faGVhZGVyX3ZhbHVlX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fbWVzc2FnZV9jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX21ldGhvZF9jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX2hlYWRlcl9maWVsZF9jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX2NodW5rX2V4dGVuc2lvbl9uYW1lYCBjYWxsYmFjayBlcnJvcgBVbmV4cGVjdGVkIGNoYXIgaW4gdXJsIHNlcnZlcgBJbnZhbGlkIGhlYWRlciB2YWx1ZSBjaGFyAEludmFsaWQgaGVhZGVyIGZpZWxkIGNoYXIAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl92ZXJzaW9uAEludmFsaWQgbWlub3IgdmVyc2lvbgBJbnZhbGlkIG1ham9yIHZlcnNpb24ARXhwZWN0ZWQgc3BhY2UgYWZ0ZXIgdmVyc2lvbgBFeHBlY3RlZCBDUkxGIGFmdGVyIHZlcnNpb24ASW52YWxpZCBIVFRQIHZlcnNpb24ASW52YWxpZCBoZWFkZXIgdG9rZW4AU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl91cmwASW52YWxpZCBjaGFyYWN0ZXJzIGluIHVybABVbmV4cGVjdGVkIHN0YXJ0IGNoYXIgaW4gdXJsAERvdWJsZSBAIGluIHVybABFbXB0eSBDb250ZW50LUxlbmd0aABJbnZhbGlkIGNoYXJhY3RlciBpbiBDb250ZW50LUxlbmd0aABEdXBsaWNhdGUgQ29udGVudC1MZW5ndGgASW52YWxpZCBjaGFyIGluIHVybCBwYXRoAENvbnRlbnQtTGVuZ3RoIGNhbid0IGJlIHByZXNlbnQgd2l0aCBUcmFuc2Zlci1FbmNvZGluZwBJbnZhbGlkIGNoYXJhY3RlciBpbiBjaHVuayBzaXplAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25faGVhZGVyX3ZhbHVlAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25fY2h1bmtfZXh0ZW5zaW9uX3ZhbHVlAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIGV4dGVuc2lvbnMgdmFsdWUATWlzc2luZyBleHBlY3RlZCBMRiBhZnRlciBoZWFkZXIgdmFsdWUASW52YWxpZCBgVHJhbnNmZXItRW5jb2RpbmdgIGhlYWRlciB2YWx1ZQBJbnZhbGlkIGNoYXJhY3RlciBpbiBjaHVuayBleHRlbnNpb25zIHF1b3RlIHZhbHVlAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIGV4dGVuc2lvbnMgcXVvdGVkIHZhbHVlAFBhdXNlZCBieSBvbl9oZWFkZXJzX2NvbXBsZXRlAEludmFsaWQgRU9GIHN0YXRlAG9uX3Jlc2V0IHBhdXNlAG9uX2NodW5rX2hlYWRlciBwYXVzZQBvbl9tZXNzYWdlX2JlZ2luIHBhdXNlAG9uX2NodW5rX2V4dGVuc2lvbl92YWx1ZSBwYXVzZQBvbl9zdGF0dXNfY29tcGxldGUgcGF1c2UAb25fdmVyc2lvbl9jb21wbGV0ZSBwYXVzZQBvbl91cmxfY29tcGxldGUgcGF1c2UAb25fY2h1bmtfY29tcGxldGUgcGF1c2UAb25faGVhZGVyX3ZhbHVlX2NvbXBsZXRlIHBhdXNlAG9uX21lc3NhZ2VfY29tcGxldGUgcGF1c2UAb25fbWV0aG9kX2NvbXBsZXRlIHBhdXNlAG9uX2hlYWRlcl9maWVsZF9jb21wbGV0ZSBwYXVzZQBvbl9jaHVua19leHRlbnNpb25fbmFtZSBwYXVzZQBVbmV4cGVjdGVkIHNwYWNlIGFmdGVyIHN0YXJ0IGxpbmUAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9jaHVua19leHRlbnNpb25fbmFtZQBJbnZhbGlkIGNoYXJhY3RlciBpbiBjaHVuayBleHRlbnNpb25zIG5hbWUAUGF1c2Ugb24gQ09OTkVDVC9VcGdyYWRlAFBhdXNlIG9uIFBSSS9VcGdyYWRlAEV4cGVjdGVkIEhUVFAvMiBDb25uZWN0aW9uIFByZWZhY2UAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9tZXRob2QARXhwZWN0ZWQgc3BhY2UgYWZ0ZXIgbWV0aG9kAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25faGVhZGVyX2ZpZWxkAFBhdXNlZABJbnZhbGlkIHdvcmQgZW5jb3VudGVyZWQASW52YWxpZCBtZXRob2QgZW5jb3VudGVyZWQAVW5leHBlY3RlZCBjaGFyIGluIHVybCBzY2hlbWEAUmVxdWVzdCBoYXMgaW52YWxpZCBgVHJhbnNmZXItRW5jb2RpbmdgAFNXSVRDSF9QUk9YWQBVU0VfUFJPWFkATUtBQ1RJVklUWQBVTlBST0NFU1NBQkxFX0VOVElUWQBDT1BZAE1PVkVEX1BFUk1BTkVOVExZAFRPT19FQVJMWQBOT1RJRlkARkFJTEVEX0RFUEVOREVOQ1kAQkFEX0dBVEVXQVkAUExBWQBQVVQAQ0hFQ0tPVVQAR0FURVdBWV9USU1FT1VUAFJFUVVFU1RfVElNRU9VVABORVRXT1JLX0NPTk5FQ1RfVElNRU9VVABDT05ORUNUSU9OX1RJTUVPVVQATE9HSU5fVElNRU9VVABORVRXT1JLX1JFQURfVElNRU9VVABQT1NUAE1JU0RJUkVDVEVEX1JFUVVFU1QAQ0xJRU5UX0NMT1NFRF9SRVFVRVNUAENMSUVOVF9DTE9TRURfTE9BRF9CQUxBTkNFRF9SRVFVRVNUAEJBRF9SRVFVRVNUAEhUVFBfUkVRVUVTVF9TRU5UX1RPX0hUVFBTX1BPUlQAUkVQT1JUAElNX0FfVEVBUE9UAFJFU0VUX0NPTlRFTlQATk9fQ09OVEVOVABQQVJUSUFMX0NPTlRFTlQASFBFX0lOVkFMSURfQ09OU1RBTlQASFBFX0NCX1JFU0VUAEdFVABIUEVfU1RSSUNUAENPTkZMSUNUAFRFTVBPUkFSWV9SRURJUkVDVABQRVJNQU5FTlRfUkVESVJFQ1QAQ09OTkVDVABNVUxUSV9TVEFUVVMASFBFX0lOVkFMSURfU1RBVFVTAFRPT19NQU5ZX1JFUVVFU1RTAEVBUkxZX0hJTlRTAFVOQVZBSUxBQkxFX0ZPUl9MRUdBTF9SRUFTT05TAE9QVElPTlMAU1dJVENISU5HX1BST1RPQ09MUwBWQVJJQU5UX0FMU09fTkVHT1RJQVRFUwBNVUxUSVBMRV9DSE9JQ0VTAElOVEVSTkFMX1NFUlZFUl9FUlJPUgBXRUJfU0VSVkVSX1VOS05PV05fRVJST1IAUkFJTEdVTl9FUlJPUgBJREVOVElUWV9QUk9WSURFUl9BVVRIRU5USUNBVElPTl9FUlJPUgBTU0xfQ0VSVElGSUNBVEVfRVJST1IASU5WQUxJRF9YX0ZPUldBUkRFRF9GT1IAU0VUX1BBUkFNRVRFUgBHRVRfUEFSQU1FVEVSAEhQRV9VU0VSAFNFRV9PVEhFUgBIUEVfQ0JfQ0hVTktfSEVBREVSAE1LQ0FMRU5EQVIAU0VUVVAAV0VCX1NFUlZFUl9JU19ET1dOAFRFQVJET1dOAEhQRV9DTE9TRURfQ09OTkVDVElPTgBIRVVSSVNUSUNfRVhQSVJBVElPTgBESVNDT05ORUNURURfT1BFUkFUSU9OAE5PTl9BVVRIT1JJVEFUSVZFX0lORk9STUFUSU9OAEhQRV9JTlZBTElEX1ZFUlNJT04ASFBFX0NCX01FU1NBR0VfQkVHSU4AU0lURV9JU19GUk9aRU4ASFBFX0lOVkFMSURfSEVBREVSX1RPS0VOAElOVkFMSURfVE9LRU4ARk9SQklEREVOAEVOSEFOQ0VfWU9VUl9DQUxNAEhQRV9JTlZBTElEX1VSTABCTE9DS0VEX0JZX1BBUkVOVEFMX0NPTlRST0wATUtDT0wAQUNMAEhQRV9JTlRFUk5BTABSRVFVRVNUX0hFQURFUl9GSUVMRFNfVE9PX0xBUkdFX1VOT0ZGSUNJQUwASFBFX09LAFVOTElOSwBVTkxPQ0sAUFJJAFJFVFJZX1dJVEgASFBFX0lOVkFMSURfQ09OVEVOVF9MRU5HVEgASFBFX1VORVhQRUNURURfQ09OVEVOVF9MRU5HVEgARkxVU0gAUFJPUFBBVENIAE0tU0VBUkNIAFVSSV9UT09fTE9ORwBQUk9DRVNTSU5HAE1JU0NFTExBTkVPVVNfUEVSU0lTVEVOVF9XQVJOSU5HAE1JU0NFTExBTkVPVVNfV0FSTklORwBIUEVfSU5WQUxJRF9UUkFOU0ZFUl9FTkNPRElORwBFeHBlY3RlZCBDUkxGAEhQRV9JTlZBTElEX0NIVU5LX1NJWkUATU9WRQBDT05USU5VRQBIUEVfQ0JfU1RBVFVTX0NPTVBMRVRFAEhQRV9DQl9IRUFERVJTX0NPTVBMRVRFAEhQRV9DQl9WRVJTSU9OX0NPTVBMRVRFAEhQRV9DQl9VUkxfQ09NUExFVEUASFBFX0NCX0NIVU5LX0NPTVBMRVRFAEhQRV9DQl9IRUFERVJfVkFMVUVfQ09NUExFVEUASFBFX0NCX0NIVU5LX0VYVEVOU0lPTl9WQUxVRV9DT01QTEVURQBIUEVfQ0JfQ0hVTktfRVhURU5TSU9OX05BTUVfQ09NUExFVEUASFBFX0NCX01FU1NBR0VfQ09NUExFVEUASFBFX0NCX01FVEhPRF9DT01QTEVURQBIUEVfQ0JfSEVBREVSX0ZJRUxEX0NPTVBMRVRFAERFTEVURQBIUEVfSU5WQUxJRF9FT0ZfU1RBVEUASU5WQUxJRF9TU0xfQ0VSVElGSUNBVEUAUEFVU0UATk9fUkVTUE9OU0UAVU5TVVBQT1JURURfTUVESUFfVFlQRQBHT05FAE5PVF9BQ0NFUFRBQkxFAFNFUlZJQ0VfVU5BVkFJTEFCTEUAUkFOR0VfTk9UX1NBVElTRklBQkxFAE9SSUdJTl9JU19VTlJFQUNIQUJMRQBSRVNQT05TRV9JU19TVEFMRQBQVVJHRQBNRVJHRQBSRVFVRVNUX0hFQURFUl9GSUVMRFNfVE9PX0xBUkdFAFJFUVVFU1RfSEVBREVSX1RPT19MQVJHRQBQQVlMT0FEX1RPT19MQVJHRQBJTlNVRkZJQ0lFTlRfU1RPUkFHRQBIUEVfUEFVU0VEX1VQR1JBREUASFBFX1BBVVNFRF9IMl9VUEdSQURFAFNPVVJDRQBBTk5PVU5DRQBUUkFDRQBIUEVfVU5FWFBFQ1RFRF9TUEFDRQBERVNDUklCRQBVTlNVQlNDUklCRQBSRUNPUkQASFBFX0lOVkFMSURfTUVUSE9EAE5PVF9GT1VORABQUk9QRklORABVTkJJTkQAUkVCSU5EAFVOQVVUSE9SSVpFRABNRVRIT0RfTk9UX0FMTE9XRUQASFRUUF9WRVJTSU9OX05PVF9TVVBQT1JURUQAQUxSRUFEWV9SRVBPUlRFRABBQ0NFUFRFRABOT1RfSU1QTEVNRU5URUQATE9PUF9ERVRFQ1RFRABIUEVfQ1JfRVhQRUNURUQASFBFX0xGX0VYUEVDVEVEAENSRUFURUQASU1fVVNFRABIUEVfUEFVU0VEAFRJTUVPVVRfT0NDVVJFRABQQVlNRU5UX1JFUVVJUkVEAFBSRUNPTkRJVElPTl9SRVFVSVJFRABQUk9YWV9BVVRIRU5USUNBVElPTl9SRVFVSVJFRABORVRXT1JLX0FVVEhFTlRJQ0FUSU9OX1JFUVVJUkVEAExFTkdUSF9SRVFVSVJFRABTU0xfQ0VSVElGSUNBVEVfUkVRVUlSRUQAVVBHUkFERV9SRVFVSVJFRABQQUdFX0VYUElSRUQAUFJFQ09ORElUSU9OX0ZBSUxFRABFWFBFQ1RBVElPTl9GQUlMRUQAUkVWQUxJREFUSU9OX0ZBSUxFRABTU0xfSEFORFNIQUtFX0ZBSUxFRABMT0NLRUQAVFJBTlNGT1JNQVRJT05fQVBQTElFRABOT1RfTU9ESUZJRUQATk9UX0VYVEVOREVEAEJBTkRXSURUSF9MSU1JVF9FWENFRURFRABTSVRFX0lTX09WRVJMT0FERUQASEVBRABFeHBlY3RlZCBIVFRQLwAAXhMAACYTAAAwEAAA8BcAAJ0TAAAVEgAAORcAAPASAAAKEAAAdRIAAK0SAACCEwAATxQAAH8QAACgFQAAIxQAAIkSAACLFAAATRUAANQRAADPFAAAEBgAAMkWAADcFgAAwREAAOAXAAC7FAAAdBQAAHwVAADlFAAACBcAAB8QAABlFQAAoxQAACgVAAACFQAAmRUAACwQAACLGQAATw8AANQOAABqEAAAzhAAAAIXAACJDgAAbhMAABwTAABmFAAAVhcAAMETAADNEwAAbBMAAGgXAABmFwAAXxcAACITAADODwAAaQ4AANgOAABjFgAAyxMAAKoOAAAoFwAAJhcAAMUTAABdFgAA6BEAAGcTAABlEwAA8hYAAHMTAAAdFwAA+RYAAPMRAADPDgAAzhUAAAwSAACzEQAApREAAGEQAAAyFwAAuxMAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQIBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAIDAgICAgIAAAICAAICAAICAgICAgICAgIABAAAAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgACAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAACAAICAgICAAACAgACAgACAgICAgICAgICAAMABAAAAAICAgICAgICAgICAgICAgICAgICAgICAgICAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAgACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbG9zZWVlcC1hbGl2ZQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQEBAQIBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBY2h1bmtlZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEAAQEBAQEAAAEBAAEBAAEBAQEBAQEBAQEAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABlY3Rpb25lbnQtbGVuZ3Rob25yb3h5LWNvbm5lY3Rpb24AAAAAAAAAAAAAAAAAAAByYW5zZmVyLWVuY29kaW5ncGdyYWRlDQoNCg0KU00NCg0KVFRQL0NFL1RTUC8AAAAAAAAAAAAAAAABAgABAwAAAAAAAAAAAAAAAAAAAAAAAAQBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAAAAAQIAAQMAAAAAAAAAAAAAAAAAAAAAAAAEAQEFAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAAAAAAAAAEAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAAAAAAAAQAAAgAAAAAAAAAAAAAAAAAAAAAAAAMEAAAEBAQEBAQEBAQEBAUEBAQEBAQEBAQEBAQABAAGBwQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEAAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAEAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAAAAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAABAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAIAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAAAAAAAADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABOT1VOQ0VFQ0tPVVRORUNURVRFQ1JJQkVMVVNIRVRFQURTRUFSQ0hSR0VDVElWSVRZTEVOREFSVkVPVElGWVBUSU9OU0NIU0VBWVNUQVRDSEdFT1JESVJFQ1RPUlRSQ0hQQVJBTUVURVJVUkNFQlNDUklCRUFSRE9XTkFDRUlORE5LQ0tVQlNDUklCRUhUVFAvQURUUC8="), vo;
}
var Lo, ya;
function Hd() {
  return ya || (ya = 1, Lo = "AGFzbQEAAAABMAhgAX8Bf2ADf39/AX9gBH9/f38Bf2AAAGADf39/AGABfwBgAn9/AGAGf39/f39/AALLAQgDZW52GHdhc21fb25faGVhZGVyc19jb21wbGV0ZQACA2VudhV3YXNtX29uX21lc3NhZ2VfYmVnaW4AAANlbnYLd2FzbV9vbl91cmwAAQNlbnYOd2FzbV9vbl9zdGF0dXMAAQNlbnYUd2FzbV9vbl9oZWFkZXJfZmllbGQAAQNlbnYUd2FzbV9vbl9oZWFkZXJfdmFsdWUAAQNlbnYMd2FzbV9vbl9ib2R5AAEDZW52GHdhc21fb25fbWVzc2FnZV9jb21wbGV0ZQAAA0ZFAwMEAAAFAAAAAAAABQEFAAUFBQAABgAAAAAGBgYGAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAAABAQcAAAUFAwABBAUBcAESEgUDAQACBggBfwFBgNQECwfRBSIGbWVtb3J5AgALX2luaXRpYWxpemUACRlfX2luZGlyZWN0X2Z1bmN0aW9uX3RhYmxlAQALbGxodHRwX2luaXQAChhsbGh0dHBfc2hvdWxkX2tlZXBfYWxpdmUAQQxsbGh0dHBfYWxsb2MADAZtYWxsb2MARgtsbGh0dHBfZnJlZQANBGZyZWUASA9sbGh0dHBfZ2V0X3R5cGUADhVsbGh0dHBfZ2V0X2h0dHBfbWFqb3IADxVsbGh0dHBfZ2V0X2h0dHBfbWlub3IAEBFsbGh0dHBfZ2V0X21ldGhvZAARFmxsaHR0cF9nZXRfc3RhdHVzX2NvZGUAEhJsbGh0dHBfZ2V0X3VwZ3JhZGUAEwxsbGh0dHBfcmVzZXQAFA5sbGh0dHBfZXhlY3V0ZQAVFGxsaHR0cF9zZXR0aW5nc19pbml0ABYNbGxodHRwX2ZpbmlzaAAXDGxsaHR0cF9wYXVzZQAYDWxsaHR0cF9yZXN1bWUAGRtsbGh0dHBfcmVzdW1lX2FmdGVyX3VwZ3JhZGUAGhBsbGh0dHBfZ2V0X2Vycm5vABsXbGxodHRwX2dldF9lcnJvcl9yZWFzb24AHBdsbGh0dHBfc2V0X2Vycm9yX3JlYXNvbgAdFGxsaHR0cF9nZXRfZXJyb3JfcG9zAB4RbGxodHRwX2Vycm5vX25hbWUAHxJsbGh0dHBfbWV0aG9kX25hbWUAIBJs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IAH9CwMAIABBMGogAf0LAwAgAEEgaiAB/QsDACAAQd0BNgIcQQALewEBfwJAIAAoAgwiAw0AAkAgACgCBEUNACAAIAE2AgQLAkAgACABIAIQxICAgAAiAw0AIAAoAgwPCyAAIAM2AhxBACEDIAAoAgQiAUUNACAAIAEgAiAAKAIIEYGAgIAAACIBRQ0AIAAgAjYCFCAAIAE2AgwgASEDCyADC+TzAQMOfwN+BH8jgICAgABBEGsiAySAgICAACABIQQgASEFIAEhBiABIQcgASEIIAEhCSABIQogASELIAEhDCABIQ0gASEOIAEhDwJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQCAAKAIcIhBBf2oO3QHaAQHZAQIDBAUGBwgJCgsMDQ7YAQ8Q1wEREtYBExQVFhcYGRob4AHfARwdHtUBHyAhIiMkJdQBJicoKSorLNMB0gEtLtEB0AEvMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUbbAUdISUrPAc4BS80BTMwBTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gAGBAYIBgwGEAYUBhgGHAYgBiQGKAYsBjAGNAY4BjwGQAZEB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QAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAIBAOxwEAAQID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YWNrIGVycm9yAGBvbl9jaHVua19leHRlbnNpb25fdmFsdWVgIGNhbGxiYWNrIGVycm9yAGBvbl9zdGF0dXNfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl92ZXJzaW9uX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fdXJsX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fY2h1bmtfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9oZWFkZXJfdmFsdWVfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9tZXNzYWdlX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fbWV0aG9kX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25faGVhZGVyX2ZpZWxkX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fY2h1bmtfZXh0ZW5zaW9uX25hbWVgIGNhbGxiYWNrIGVycm9yAFVuZXhwZWN0ZWQgY2hhciBpbiB1cmwgc2VydmVyAEludmFsaWQgaGVhZGVyIHZhbHVlIGNoYXIASW52YWxpZCBoZWFkZXIgZmllbGQgY2hhcgBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX3ZlcnNpb24ASW52YWxpZCBtaW5vciB2ZXJzaW9uAEludmFsaWQgbWFqb3IgdmVyc2lvbgBFeHBlY3RlZCBzcGFjZSBhZnRlciB2ZXJzaW9uAEV4cGVjdGVkIENSTEYgYWZ0ZXIgdmVyc2lvbgBJbnZhbGlkIEhUVFAgdmVyc2lvbgBJbnZhbGlkIGhlYWRlciB0b2tlbgBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX3VybABJbnZhbGlkIGNoYXJhY3RlcnMgaW4gdXJsAFVuZXhwZWN0ZWQgc3RhcnQgY2hhciBpbiB1cmwARG91YmxlIEAgaW4gdXJsAEVtcHR5IENvbnRlbnQtTGVuZ3RoAEludmFsaWQgY2hhcmFjdGVyIGluIENvbnRlbnQtTGVuZ3RoAER1cGxpY2F0ZSBDb250ZW50LUxlbmd0aABJbnZhbGlkIGNoYXIgaW4gdXJsIHBhdGgAQ29udGVudC1MZW5ndGggY2FuJ3QgYmUgcHJlc2VudCB3aXRoIFRyYW5zZmVyLUVuY29kaW5nAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIHNpemUAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9oZWFkZXJfdmFsdWUAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9jaHVua19leHRlbnNpb25fdmFsdWUASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucyB2YWx1ZQBNaXNzaW5nIGV4cGVjdGVkIExGIGFmdGVyIGhlYWRlciB2YWx1ZQBJbnZhbGlkIGBUcmFuc2Zlci1FbmNvZGluZ2AgaGVhZGVyIHZhbHVlAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIGV4dGVuc2lvbnMgcXVvdGUgdmFsdWUASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucyBxdW90ZWQgdmFsdWUAUGF1c2VkIGJ5IG9uX2hlYWRlcnNfY29tcGxldGUASW52YWxpZCBFT0Ygc3RhdGUAb25fcmVzZXQgcGF1c2UAb25fY2h1bmtfaGVhZGVyIHBhdXNlAG9uX21lc3NhZ2VfYmVnaW4gcGF1c2UAb25fY2h1bmtfZXh0ZW5zaW9uX3ZhbHVlIHBhdXNlAG9uX3N0YXR1c19jb21wbGV0ZSBwYXVzZQBvbl92ZXJzaW9uX2NvbXBsZXRlIHBhdXNlAG9uX3VybF9jb21wbGV0ZSBwYXVzZQBvbl9jaHVua19jb21wbGV0ZSBwYXVzZQBvbl9oZWFkZXJfdmFsdWVfY29tcGxldGUgcGF1c2UAb25fbWVzc2FnZV9jb21wbGV0ZSBwYXVzZQBvbl9tZXRob2RfY29tcGxldGUgcGF1c2UAb25faGVhZGVyX2ZpZWxkX2NvbXBsZXRlIHBhdXNlAG9uX2NodW5rX2V4dGVuc2lvbl9uYW1lIHBhdXNlAFVuZXhwZWN0ZWQgc3BhY2UgYWZ0ZXIgc3RhcnQgbGluZQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX2NodW5rX2V4dGVuc2lvbl9uYW1lAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIGV4dGVuc2lvbnMgbmFtZQBQYXVzZSBvbiBDT05ORUNUL1VwZ3JhZGUAUGF1c2Ugb24gUFJJL1VwZ3JhZGUARXhwZWN0ZWQgSFRUUC8yIENvbm5lY3Rpb24gUHJlZmFjZQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX21ldGhvZABFeHBlY3RlZCBzcGFjZSBhZnRlciBtZXRob2QAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9oZWFkZXJfZmllbGQAUGF1c2VkAEludmFsaWQgd29yZCBlbmNvdW50ZXJlZABJbnZhbGlkIG1ldGhvZCBlbmNvdW50ZXJlZABVbmV4cGVjdGVkIGNoYXIgaW4gdXJsIHNjaGVtYQBSZXF1ZXN0IGhhcyBpbnZhbGlkIGBUcmFuc2Zlci1FbmNvZGluZ2AAU1dJVENIX1BST1hZAFVTRV9QUk9YWQBNS0FDVElWSVRZAFVOUFJPQ0VTU0FCTEVfRU5USVRZAENPUFkATU9WRURfUEVSTUFORU5UTFkAVE9PX0VBUkxZAE5PVElGWQBGQUlMRURfREVQRU5ERU5DWQBCQURfR0FURVdBWQBQTEFZAFBVVABDSEVDS09VVABHQVRFV0FZX1RJTUVPVVQAUkVRVUVTVF9USU1FT1VUAE5FVFdPUktfQ09OTkVDVF9USU1FT1VUAENPTk5FQ1RJT05fVElNRU9VVABMT0dJTl9USU1FT1VUAE5FVFdPUktfUkVBRF9USU1FT1VUAFBPU1QATUlTRElSRUNURURfUkVRVUVTVABDTElFTlRfQ0xPU0VEX1JFUVVFU1QAQ0xJRU5UX0NMT1NFRF9MT0FEX0JBTEFOQ0VEX1JFUVVFU1QAQkFEX1JFUVVFU1QASFRUUF9SRVFVRVNUX1NFTlRfVE9fSFRUUFNfUE9SVABSRVBPUlQASU1fQV9URUFQT1QAUkVTRVRfQ09OVEVOVABOT19DT05URU5UAFBBUlRJQUxfQ09OVEVOVABIUEVfSU5WQUxJRF9DT05TVEFOVABIUEVfQ0JfUkVTRVQAR0VUAEhQRV9TVFJJQ1QAQ09ORkxJQ1QAVEVNUE9SQVJZX1JFRElSRUNUAFBFUk1BTkVOVF9SRURJUkVDVABDT05ORUNUAE1VTFRJX1NUQVRVUwBIUEVfSU5WQUxJRF9TVEFUVVMAVE9PX01BTllfUkVRVUVTVFMARUFSTFlfSElOVFMAVU5BVkFJTEFCTEVfRk9SX0xFR0FMX1JFQVNPTlMAT1BUSU9OUwBTV0lUQ0hJTkdfUFJPVE9DT0xTAFZBUklBTlRfQUxTT19ORUdPVElBVEVTAE1VTFRJUExFX0NIT0lDRVMASU5URVJOQUxfU0VSVkVSX0VSUk9SAFdFQl9TRVJWRVJfVU5LTk9XTl9FUlJPUgBSQUlMR1VOX0VSUk9SAElERU5USVRZX1BST1ZJREVSX0FVVEhFTlRJQ0FUSU9OX0VSUk9SAFNTTF9DRVJUSUZJQ0FURV9FUlJPUgBJTlZBTElEX1hfRk9SV0FSREVEX0ZPUgBTRVRfUEFSQU1FVEVSAEdFVF9QQVJBTUVURVIASFBFX1VTRVIAU0VFX09USEVSAEhQRV9DQl9DSFVOS19IRUFERVIATUtDQUxFTkRBUgBTRVRVUABXRUJfU0VSVkVSX0lTX0RPV04AVEVBUkRPV04ASFBFX0NMT1NFRF9DT05ORUNUSU9OAEhFVVJJU1RJQ19FWFBJUkFUSU9OAERJU0NPTk5FQ1RFRF9PUEVSQVRJT04ATk9OX0FVVEhPUklUQVRJVkVfSU5GT1JNQVRJT04ASFBFX0lOVkFMSURfVkVSU0lPTgBIUEVfQ0JfTUVTU0FHRV9CRUdJTgBTSVRFX0lTX0ZST1pFTgBIUEVfSU5WQUxJRF9IRUFERVJfVE9LRU4ASU5WQUxJRF9UT0tFTgBGT1JCSURERU4ARU5IQU5DRV9ZT1VSX0NBTE0ASFBFX0lOVkFMSURfVVJMAEJMT0NLRURfQllfUEFSRU5UQUxfQ09OVFJPTABNS0NPTABBQ0wASFBFX0lOVEVSTkFMAFJFUVVFU1RfSEVBREVSX0ZJRUxEU19UT09fTEFSR0VfVU5PRkZJQ0lBTABIUEVfT0sAVU5MSU5LAFVOTE9DSwBQUkkAUkVUUllfV0lUSABIUEVfSU5WQUxJRF9DT05URU5UX0xFTkdUSABIUEVfVU5FWFBFQ1RFRF9DT05URU5UX0xFTkdUSABGTFVTSABQUk9QUEFUQ0gATS1TRUFSQ0gAVVJJX1RPT19MT05HAFBST0NFU1NJTkcATUlTQ0VMTEFORU9VU19QRVJTSVNURU5UX1dBUk5JTkcATUlTQ0VMTEFORU9VU19XQVJOSU5HAEhQRV9JTlZBTElEX1RSQU5TRkVSX0VOQ09ESU5HAEV4cGVjdGVkIENSTEYASFBFX0lOVkFMSURfQ0hVTktfU0laRQBNT1ZFAENPTlRJTlVFAEhQRV9DQl9TVEFUVVNfQ09NUExFVEUASFBFX0NCX0hFQURFUlNfQ09NUExFVEUASFBFX0NCX1ZFUlNJT05fQ09NUExFVEUASFBFX0NCX1VSTF9DT01QTEVURQBIUEVfQ0JfQ0hVTktfQ09NUExFVEUASFBFX0NCX0hFQURFUl9WQUxVRV9DT01QTEVURQBIUEVfQ0JfQ0hVTktfRVhURU5TSU9OX1ZBTFVFX0NPTVBMRVRFAEhQRV9DQl9DSFVOS19FWFRFTlNJT05fTkFNRV9DT01QTEVURQBIUEVfQ0JfTUVTU0FHRV9DT01QTEVURQBIUEVfQ0JfTUVUSE9EX0NPTVBMRVRFAEhQRV9DQl9IRUFERVJfRklFTERfQ09NUExFVEUAREVMRVRFAEhQRV9JTlZBTElEX0VPRl9TVEFURQBJTlZBTElEX1NTTF9DRVJUSUZJQ0FURQBQQVVTRQBOT19SRVNQT05TRQBVTlNVUFBPUlRFRF9NRURJQV9UWVBFAEdPTkUATk9UX0FDQ0VQVEFCTEUAU0VSVklDRV9VTkFWQUlMQUJMRQBSQU5HRV9OT1RfU0FUSVNGSUFCTEUAT1JJR0lOX0lTX1VOUkVBQ0hBQkxFAFJFU1BPTlNFX0lTX1NUQUxFAFBVUkdFAE1FUkdFAFJFUVVFU1RfSEVBREVSX0ZJRUxEU19UT09fTEFSR0UAUkVRVUVTVF9IRUFERVJfVE9PX0xBUkdFAFBBWUxPQURfVE9PX0xBUkdFAElOU1VGRklDSUVOVF9TVE9SQUdFAEhQRV9QQVVTRURfVVBHUkFERQBIUEVfUEFVU0VEX0gyX1VQR1JBREUAU09VUkNFAEFOTk9VTkNFAFRSQUNFAEhQRV9VTkVYUEVDVEVEX1NQQUNFAERFU0NSSUJFAFVOU1VCU0NSSUJFAFJFQ09SRABIUEVfSU5WQUxJRF9NRVRIT0QATk9UX0ZPVU5EAFBST1BGSU5EAFVOQklORABSRUJJTkQAVU5BVVRIT1JJWkVEAE1FVEhPRF9OT1RfQUxMT1dFRABIVFRQX1ZFUlNJT05fTk9UX1NVUFBPUlRFRABBTFJFQURZX1JFUE9SVEVEAEFDQ0VQVEVEAE5PVF9JTVBMRU1FTlRFRABMT09QX0RFVEVDVEVEAEhQRV9DUl9FWFBFQ1RFRABIUEVfTEZfRVhQRUNURUQAQ1JFQVRFRABJTV9VU0VEAEhQRV9QQVVTRUQAVElNRU9VVF9PQ0NVUkVEAFBBWU1FTlRfUkVRVUlSRUQAUFJFQ09ORElUSU9OX1JFUVVJUkVEAFBST1hZX0FVVEhFTlRJQ0FUSU9OX1JFUVVJUkVEAE5FVFdPUktfQVVUSEVOVElDQVRJT05fUkVRVUlSRUQATEVOR1RIX1JFUVVJUkVEAFNTTF9DRVJUSUZJQ0FURV9SRVFVSVJFRABVUEdSQURFX1JFUVVJUkVEAFBBR0VfRVhQSVJFRABQUkVDT05ESVRJT05fRkFJTEVEAEVYUEVDVEFUSU9OX0ZBSUxFRABSRVZBTElEQVRJT05fRkFJTEVEAFNTTF9IQU5EU0hBS0VfRkFJTEVEAExPQ0tFRABUUkFOU0ZPUk1BVElPTl9BUFBMSUVEAE5PVF9NT0RJRklFRABOT1RfRVhURU5ERUQAQkFORFdJRFRIX0xJTUlUX0VYQ0VFREVEAFNJVEVfSVNfT1ZFUkxPQURFRABIRUFEAEV4cGVjdGVkIEhUVFAvAABeEwAAJhMAADAQAADwFwAAnRMAABUSAAA5FwAA8BIAAAoQAAB1EgAArRIAAIITAABPFAAAfxAAAKAVAAAjFAAAiRIAAIsUAABNFQAA1BEAAM8UAAAQGAAAyRYAANwWAADBEQAA4BcAALsUAAB0FAAAfBUAAOUUAAAIFwAAHxAAAGUVAACjFAAAKBUAAAIVAACZFQAALBAAAIsZAABPDwAA1A4AAGoQAADOEAAAAhcAAIkOAABuEwAAHBMAAGYUAABWFwAAwRMAAM0TAABsEwAAaBcAAGYXAABfFwAAIhMAAM4PAABpDgAA2A4AAGMWAADLEwAAqg4AACgXAAAmFwAAxRMAAF0WAADoEQAAZxMAAGUTAADyFgAAcxMAAB0XAAD5FgAA8xEAAM8OAADOFQAADBIAALMRAAClEQAAYRAAADIXAAC7EwAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAgMCAgICAgAAAgIAAgIAAgICAgICAgICAgAEAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAAIAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgICAgIAAAICAAICAAICAgICAgICAgIAAwAEAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgACAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsb3NlZWVwLWFsaXZlAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFjaHVua2VkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQABAQEBAQAAAQEAAQEAAQEBAQEBAQEBAQAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVjdGlvbmVudC1sZW5ndGhvbnJveHktY29ubmVjdGlvbgAAAAAAAAAAAAAAAAAAAHJhbnNmZXItZW5jb2RpbmdwZ3JhZGUNCg0KDQpTTQ0KDQpUVFAvQ0UvVFNQLwAAAAAAAAAAAAAAAAECAAEDAAAAAAAAAAAAAAAAAAAAAAAABAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAAAAAABAgABAwAAAAAAAAAAAAAAAAAAAAAAAAQBAQUBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAAAAAQAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAAAAAAAAAABAAACAAAAAAAAAAAAAAAAAAAAAAAAAwQAAAQEBAQEBAQEBAQEBQQEBAQEBAQEBAQEBAAEAAYHBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQABAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAQAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAAAAAAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAEAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAgAAAAACAAAAAAAAAAAAAAAAAAAAAAADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAAAAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE5PVU5DRUVDS09VVE5FQ1RFVEVDUklCRUxVU0hFVEVBRFNFQVJDSFJHRUNUSVZJVFlMRU5EQVJWRU9USUZZUFRJT05TQ0hTRUFZU1RBVENIR0VPUkRJUkVDVE9SVFJDSFBBUkFNRVRFUlVSQ0VCU0NSSUJFQVJET1dOQUNFSU5ETktDS1VCU0NSSUJFSFRUUC9BRFRQLw=="), Lo;
}
const oe = Me, Pl = Ei, Vd = or, { pipeline: qd } = lt, ce = we, Mo = nd, $n = pd, Wd = Vs, {
  RequestContentLengthMismatchError: HA,
  ResponseContentLengthMismatchError: jd,
  InvalidArgumentError: Pe,
  RequestAbortedError: bi,
  HeadersTimeoutError: $d,
  HeadersOverflowError: Kd,
  SocketError: er,
  InformationalError: _A,
  BodyTimeoutError: zd,
  HTTPParserError: Zd,
  ResponseExceededMaxSizeError: Xd,
  ClientDestroyedError: eQ
} = Re, AQ = qs, {
  kUrl: Ze,
  kReset: cA,
  kServerName: rt,
  kClient: NA,
  kBusy: Kn,
  kParser: ve,
  kConnect: tQ,
  kBlocking: Ar,
  kResuming: yt,
  kRunning: _e,
  kPending: Ft,
  kSize: Rt,
  kWriting: VA,
  kQueue: ke,
  kConnected: rQ,
  kConnecting: Vt,
  kNeedDrain: nt,
  kNoRef: Fr,
  kKeepAliveDefaultTimeout: zn,
  kHostHeader: Yl,
  kPendingIdx: CA,
  kRunningIdx: Fe,
  kError: Xe,
  kPipelining: it,
  kSocket: Le,
  kKeepAliveTimeoutValue: Pr,
  kMaxHeadersSize: ks,
  kKeepAliveMaxTimeout: xl,
  kKeepAliveTimeoutThreshold: Jl,
  kHeadersTimeout: Hl,
  kBodyTimeout: Vl,
  kStrictContentLength: Yr,
  kConnector: Sr,
  kMaxRedirections: sQ,
  kMaxRequests: xr,
  kCounter: ql,
  kClose: oQ,
  kDestroy: nQ,
  kDispatch: iQ,
  kInterceptors: aQ,
  kLocalAddress: Ur,
  kMaxResponseSize: Wl,
  kHTTPConnVersion: vA,
  // HTTP2
  kHost: jl,
  kHTTP2Session: BA,
  kHTTP2SessionState: Ls,
  kHTTP2BuildRequest: cQ,
  kHTTP2CopyHeaders: gQ,
  kHTTP1BuildRequest: lQ
} = Se;
let Ms;
try {
  Ms = require("http2");
} catch {
  Ms = { constants: {} };
}
const {
  constants: {
    HTTP2_HEADER_AUTHORITY: EQ,
    HTTP2_HEADER_METHOD: uQ,
    HTTP2_HEADER_PATH: hQ,
    HTTP2_HEADER_SCHEME: dQ,
    HTTP2_HEADER_CONTENT_LENGTH: QQ,
    HTTP2_HEADER_EXPECT: CQ,
    HTTP2_HEADER_STATUS: BQ
  }
} = Ms;
let ba = !1;
const is = Buffer[Symbol.species], st = Symbol("kClosedResolve"), sA = {};
try {
  const e = require("diagnostics_channel");
  sA.sendHeaders = e.channel("undici:client:sendHeaders"), sA.beforeConnect = e.channel("undici:client:beforeConnect"), sA.connectError = e.channel("undici:client:connectError"), sA.connected = e.channel("undici:client:connected");
} catch {
  sA.sendHeaders = { hasSubscribers: !1 }, sA.beforeConnect = { hasSubscribers: !1 }, sA.connectError = { hasSubscribers: !1 }, sA.connected = { hasSubscribers: !1 };
}
let IQ = class extends Wd {
  /**
   *
   * @param {string|URL} url
   * @param {import('../types/client').Client.Options} options
   */
  constructor(A, {
    interceptors: t,
    maxHeaderSize: r,
    headersTimeout: s,
    socketTimeout: o,
    requestTimeout: n,
    connectTimeout: i,
    bodyTimeout: a,
    idleTimeout: g,
    keepAlive: c,
    keepAliveTimeout: E,
    maxKeepAliveTimeout: l,
    keepAliveMaxTimeout: Q,
    keepAliveTimeoutThreshold: I,
    socketPath: d,
    pipelining: h,
    tls: C,
    strictContentLength: u,
    maxCachedSessions: B,
    maxRedirections: m,
    connect: f,
    maxRequestsPerClient: y,
    localAddress: b,
    maxResponseSize: w,
    autoSelectFamily: S,
    autoSelectFamilyAttemptTimeout: v,
    // h2
    allowH2: N,
    maxConcurrentStreams: F
  } = {}) {
    if (super(), c !== void 0)
      throw new Pe("unsupported keepAlive, use pipelining=0 instead");
    if (o !== void 0)
      throw new Pe("unsupported socketTimeout, use headersTimeout & bodyTimeout instead");
    if (n !== void 0)
      throw new Pe("unsupported requestTimeout, use headersTimeout & bodyTimeout instead");
    if (g !== void 0)
      throw new Pe("unsupported idleTimeout, use keepAliveTimeout instead");
    if (l !== void 0)
      throw new Pe("unsupported maxKeepAliveTimeout, use keepAliveMaxTimeout instead");
    if (r != null && !Number.isFinite(r))
      throw new Pe("invalid maxHeaderSize");
    if (d != null && typeof d != "string")
      throw new Pe("invalid socketPath");
    if (i != null && (!Number.isFinite(i) || i < 0))
      throw new Pe("invalid connectTimeout");
    if (E != null && (!Number.isFinite(E) || E <= 0))
      throw new Pe("invalid keepAliveTimeout");
    if (Q != null && (!Number.isFinite(Q) || Q <= 0))
      throw new Pe("invalid keepAliveMaxTimeout");
    if (I != null && !Number.isFinite(I))
      throw new Pe("invalid keepAliveTimeoutThreshold");
    if (s != null && (!Number.isInteger(s) || s < 0))
      throw new Pe("headersTimeout must be a positive integer or zero");
    if (a != null && (!Number.isInteger(a) || a < 0))
      throw new Pe("bodyTimeout must be a positive integer or zero");
    if (f != null && typeof f != "function" && typeof f != "object")
      throw new Pe("connect must be a function or an object");
    if (m != null && (!Number.isInteger(m) || m < 0))
      throw new Pe("maxRedirections must be a positive number");
    if (y != null && (!Number.isInteger(y) || y < 0))
      throw new Pe("maxRequestsPerClient must be a positive number");
    if (b != null && (typeof b != "string" || Pl.isIP(b) === 0))
      throw new Pe("localAddress must be valid string IP address");
    if (w != null && (!Number.isInteger(w) || w < -1))
      throw new Pe("maxResponseSize must be a positive number");
    if (v != null && (!Number.isInteger(v) || v < -1))
      throw new Pe("autoSelectFamilyAttemptTimeout must be a positive number");
    if (N != null && typeof N != "boolean")
      throw new Pe("allowH2 must be a valid boolean value");
    if (F != null && (typeof F != "number" || F < 1))
      throw new Pe("maxConcurrentStreams must be a possitive integer, greater than 0");
    typeof f != "function" && (f = AQ({
      ...C,
      maxCachedSessions: B,
      allowH2: N,
      socketPath: d,
      timeout: i,
      ...ce.nodeHasAutoSelectFamily && S ? { autoSelectFamily: S, autoSelectFamilyAttemptTimeout: v } : void 0,
      ...f
    })), this[aQ] = t && t.Client && Array.isArray(t.Client) ? t.Client : [yQ({ maxRedirections: m })], this[Ze] = ce.parseOrigin(A), this[Sr] = f, this[Le] = null, this[it] = h ?? 1, this[ks] = r || Vd.maxHeaderSize, this[zn] = E ?? 4e3, this[xl] = Q ?? 6e5, this[Jl] = I ?? 1e3, this[Pr] = this[zn], this[rt] = null, this[Ur] = b ?? null, this[yt] = 0, this[nt] = 0, this[Yl] = `host: ${this[Ze].hostname}${this[Ze].port ? `:${this[Ze].port}` : ""}\r
`, this[Vl] = a ?? 3e5, this[Hl] = s ?? 3e5, this[Yr] = u ?? !0, this[sQ] = m, this[xr] = y, this[st] = null, this[Wl] = w > -1 ? w : -1, this[vA] = "h1", this[BA] = null, this[Ls] = N ? {
      // streams: null, // Fixed queue of streams - For future support of `push`
      openStreams: 0,
      // Keep track of them to decide wether or not unref the session
      maxConcurrentStreams: F ?? 100
      // Max peerConcurrentStreams for a Node h2 server
    } : null, this[jl] = `${this[Ze].hostname}${this[Ze].port ? `:${this[Ze].port}` : ""}`, this[ke] = [], this[Fe] = 0, this[CA] = 0;
  }
  get pipelining() {
    return this[it];
  }
  set pipelining(A) {
    this[it] = A, IA(this, !0);
  }
  get [Ft]() {
    return this[ke].length - this[CA];
  }
  get [_e]() {
    return this[CA] - this[Fe];
  }
  get [Rt]() {
    return this[ke].length - this[Fe];
  }
  get [rQ]() {
    return !!this[Le] && !this[Vt] && !this[Le].destroyed;
  }
  get [Kn]() {
    const A = this[Le];
    return A && (A[cA] || A[VA] || A[Ar]) || this[Rt] >= (this[it] || 1) || this[Ft] > 0;
  }
  /* istanbul ignore: only used for test */
  [tQ](A) {
    Zl(this), this.once("connect", A);
  }
  [iQ](A, t) {
    const r = A.origin || this[Ze].origin, s = this[vA] === "h2" ? $n[cQ](r, A, t) : $n[lQ](r, A, t);
    return this[ke].push(s), this[yt] || (ce.bodyLength(s.body) == null && ce.isIterable(s.body) ? (this[yt] = 1, process.nextTick(IA, this)) : IA(this, !0)), this[yt] && this[nt] !== 2 && this[Kn] && (this[nt] = 2), this[nt] < 2;
  }
  async [oQ]() {
    return new Promise((A) => {
      this[Rt] ? this[st] = A : A(null);
    });
  }
  async [nQ](A) {
    return new Promise((t) => {
      const r = this[ke].splice(this[CA]);
      for (let o = 0; o < r.length; o++) {
        const n = r[o];
        gA(this, n, A);
      }
      const s = () => {
        this[st] && (this[st](), this[st] = null), t();
      };
      this[BA] != null && (ce.destroy(this[BA], A), this[BA] = null, this[Ls] = null), this[Le] ? ce.destroy(this[Le].on("close", s), A) : queueMicrotask(s), IA(this);
    });
  }
};
function pQ(e) {
  oe(e.code !== "ERR_TLS_CERT_ALTNAME_INVALID"), this[Le][Xe] = e, Ws(this[NA], e);
}
function fQ(e, A, t) {
  const r = new _A(`HTTP/2: "frameError" received - type ${e}, code ${A}`);
  t === 0 && (this[Le][Xe] = r, Ws(this[NA], r));
}
function mQ() {
  ce.destroy(this, new er("other side closed")), ce.destroy(this[Le], new er("other side closed"));
}
function wQ(e) {
  const A = this[NA], t = new _A(`HTTP/2: "GOAWAY" frame received with code ${e}`);
  if (A[Le] = null, A[BA] = null, A.destroyed) {
    oe(this[Ft] === 0);
    const r = A[ke].splice(A[Fe]);
    for (let s = 0; s < r.length; s++) {
      const o = r[s];
      gA(this, o, t);
    }
  } else if (A[_e] > 0) {
    const r = A[ke][A[Fe]];
    A[ke][A[Fe]++] = null, gA(A, r, t);
  }
  A[CA] = A[Fe], oe(A[_e] === 0), A.emit(
    "disconnect",
    A[Ze],
    [A],
    t
  ), IA(A);
}
const FA = Nd(), yQ = yi, bQ = Buffer.alloc(0);
async function RQ() {
  const e = process.env.JEST_WORKER_ID ? wa() : void 0;
  let A;
  try {
    A = await WebAssembly.compile(Buffer.from(Hd(), "base64"));
  } catch {
    A = await WebAssembly.compile(Buffer.from(e || wa(), "base64"));
  }
  return await WebAssembly.instantiate(A, {
    env: {
      /* eslint-disable camelcase */
      wasm_on_url: (t, r, s) => 0,
      wasm_on_status: (t, r, s) => {
        oe.strictEqual(qe.ptr, t);
        const o = r - GA + UA.byteOffset;
        return qe.onStatus(new is(UA.buffer, o, s)) || 0;
      },
      wasm_on_message_begin: (t) => (oe.strictEqual(qe.ptr, t), qe.onMessageBegin() || 0),
      wasm_on_header_field: (t, r, s) => {
        oe.strictEqual(qe.ptr, t);
        const o = r - GA + UA.byteOffset;
        return qe.onHeaderField(new is(UA.buffer, o, s)) || 0;
      },
      wasm_on_header_value: (t, r, s) => {
        oe.strictEqual(qe.ptr, t);
        const o = r - GA + UA.byteOffset;
        return qe.onHeaderValue(new is(UA.buffer, o, s)) || 0;
      },
      wasm_on_headers_complete: (t, r, s, o) => (oe.strictEqual(qe.ptr, t), qe.onHeadersComplete(r, !!s, !!o) || 0),
      wasm_on_body: (t, r, s) => {
        oe.strictEqual(qe.ptr, t);
        const o = r - GA + UA.byteOffset;
        return qe.onBody(new is(UA.buffer, o, s)) || 0;
      },
      wasm_on_message_complete: (t) => (oe.strictEqual(qe.ptr, t), qe.onMessageComplete() || 0)
      /* eslint-enable camelcase */
    }
  });
}
let Oo = null, Zn = RQ();
Zn.catch();
let qe = null, UA = null, as = 0, GA = null;
const tr = 1, Fs = 2, Xn = 3;
class DQ {
  constructor(A, t, { exports: r }) {
    oe(Number.isFinite(A[ks]) && A[ks] > 0), this.llhttp = r, this.ptr = this.llhttp.llhttp_alloc(FA.TYPE.RESPONSE), this.client = A, this.socket = t, this.timeout = null, this.timeoutValue = null, this.timeoutType = null, this.statusCode = null, this.statusText = "", this.upgrade = !1, this.headers = [], this.headersSize = 0, this.headersMaxSize = A[ks], this.shouldKeepAlive = !1, this.paused = !1, this.resume = this.resume.bind(this), this.bytesRead = 0, this.keepAlive = "", this.contentLength = "", this.connection = "", this.maxResponseSize = A[Wl];
  }
  setTimeout(A, t) {
    this.timeoutType = t, A !== this.timeoutValue ? (Mo.clearTimeout(this.timeout), A ? (this.timeout = Mo.setTimeout(TQ, A, this), this.timeout.unref && this.timeout.unref()) : this.timeout = null, this.timeoutValue = A) : this.timeout && this.timeout.refresh && this.timeout.refresh();
  }
  resume() {
    this.socket.destroyed || !this.paused || (oe(this.ptr != null), oe(qe == null), this.llhttp.llhttp_resume(this.ptr), oe(this.timeoutType === Fs), this.timeout && this.timeout.refresh && this.timeout.refresh(), this.paused = !1, this.execute(this.socket.read() || bQ), this.readMore());
  }
  readMore() {
    for (; !this.paused && this.ptr; ) {
      const A = this.socket.read();
      if (A === null)
        break;
      this.execute(A);
    }
  }
  execute(A) {
    oe(this.ptr != null), oe(qe == null), oe(!this.paused);
    const { socket: t, llhttp: r } = this;
    A.length > as && (GA && r.free(GA), as = Math.ceil(A.length / 4096) * 4096, GA = r.malloc(as)), new Uint8Array(r.memory.buffer, GA, as).set(A);
    try {
      let s;
      try {
        UA = A, qe = this, s = r.llhttp_execute(this.ptr, GA, A.length);
      } catch (n) {
        throw n;
      } finally {
        qe = null, UA = null;
      }
      const o = r.llhttp_get_error_pos(this.ptr) - GA;
      if (s === FA.ERROR.PAUSED_UPGRADE)
        this.onUpgrade(A.slice(o));
      else if (s === FA.ERROR.PAUSED)
        this.paused = !0, t.unshift(A.slice(o));
      else if (s !== FA.ERROR.OK) {
        const n = r.llhttp_get_error_reason(this.ptr);
        let i = "";
        if (n) {
          const a = new Uint8Array(r.memory.buffer, n).indexOf(0);
          i = "Response does not match the HTTP/1.1 protocol (" + Buffer.from(r.memory.buffer, n, a).toString() + ")";
        }
        throw new Zd(i, FA.ERROR[s], A.slice(o));
      }
    } catch (s) {
      ce.destroy(t, s);
    }
  }
  destroy() {
    oe(this.ptr != null), oe(qe == null), this.llhttp.llhttp_free(this.ptr), this.ptr = null, Mo.clearTimeout(this.timeout), this.timeout = null, this.timeoutValue = null, this.timeoutType = null, this.paused = !1;
  }
  onStatus(A) {
    this.statusText = A.toString();
  }
  onMessageBegin() {
    const { socket: A, client: t } = this;
    if (A.destroyed || !t[ke][t[Fe]])
      return -1;
  }
  onHeaderField(A) {
    const t = this.headers.length;
    t & 1 ? this.headers[t - 1] = Buffer.concat([this.headers[t - 1], A]) : this.headers.push(A), this.trackHeader(A.length);
  }
  onHeaderValue(A) {
    let t = this.headers.length;
    (t & 1) === 1 ? (this.headers.push(A), t += 1) : this.headers[t - 1] = Buffer.concat([this.headers[t - 1], A]);
    const r = this.headers[t - 2];
    r.length === 10 && r.toString().toLowerCase() === "keep-alive" ? this.keepAlive += A.toString() : r.length === 10 && r.toString().toLowerCase() === "connection" ? this.connection += A.toString() : r.length === 14 && r.toString().toLowerCase() === "content-length" && (this.contentLength += A.toString()), this.trackHeader(A.length);
  }
  trackHeader(A) {
    this.headersSize += A, this.headersSize >= this.headersMaxSize && ce.destroy(this.socket, new Kd());
  }
  onUpgrade(A) {
    const { upgrade: t, client: r, socket: s, headers: o, statusCode: n } = this;
    oe(t);
    const i = r[ke][r[Fe]];
    oe(i), oe(!s.destroyed), oe(s === r[Le]), oe(!this.paused), oe(i.upgrade || i.method === "CONNECT"), this.statusCode = null, this.statusText = "", this.shouldKeepAlive = null, oe(this.headers.length % 2 === 0), this.headers = [], this.headersSize = 0, s.unshift(A), s[ve].destroy(), s[ve] = null, s[NA] = null, s[Xe] = null, s.removeListener("error", Kl).removeListener("readable", $l).removeListener("end", zl).removeListener("close", ei), r[Le] = null, r[ke][r[Fe]++] = null, r.emit("disconnect", r[Ze], [r], new _A("upgrade"));
    try {
      i.onUpgrade(n, o, s);
    } catch (a) {
      ce.destroy(s, a);
    }
    IA(r);
  }
  onHeadersComplete(A, t, r) {
    const { client: s, socket: o, headers: n, statusText: i } = this;
    if (o.destroyed)
      return -1;
    const a = s[ke][s[Fe]];
    if (!a)
      return -1;
    if (oe(!this.upgrade), oe(this.statusCode < 200), A === 100)
      return ce.destroy(o, new er("bad response", ce.getSocketInfo(o))), -1;
    if (t && !a.upgrade)
      return ce.destroy(o, new er("bad upgrade", ce.getSocketInfo(o))), -1;
    if (oe.strictEqual(this.timeoutType, tr), this.statusCode = A, this.shouldKeepAlive = r || // Override llhttp value which does not allow keepAlive for HEAD.
    a.method === "HEAD" && !o[cA] && this.connection.toLowerCase() === "keep-alive", this.statusCode >= 200) {
      const c = a.bodyTimeout != null ? a.bodyTimeout : s[Vl];
      this.setTimeout(c, Fs);
    } else this.timeout && this.timeout.refresh && this.timeout.refresh();
    if (a.method === "CONNECT")
      return oe(s[_e] === 1), this.upgrade = !0, 2;
    if (t)
      return oe(s[_e] === 1), this.upgrade = !0, 2;
    if (oe(this.headers.length % 2 === 0), this.headers = [], this.headersSize = 0, this.shouldKeepAlive && s[it]) {
      const c = this.keepAlive ? ce.parseKeepAliveTimeout(this.keepAlive) : null;
      if (c != null) {
        const E = Math.min(
          c - s[Jl],
          s[xl]
        );
        E <= 0 ? o[cA] = !0 : s[Pr] = E;
      } else
        s[Pr] = s[zn];
    } else
      o[cA] = !0;
    const g = a.onHeaders(A, n, this.resume, i) === !1;
    return a.aborted ? -1 : a.method === "HEAD" || A < 200 ? 1 : (o[Ar] && (o[Ar] = !1, IA(s)), g ? FA.ERROR.PAUSED : 0);
  }
  onBody(A) {
    const { client: t, socket: r, statusCode: s, maxResponseSize: o } = this;
    if (r.destroyed)
      return -1;
    const n = t[ke][t[Fe]];
    if (oe(n), oe.strictEqual(this.timeoutType, Fs), this.timeout && this.timeout.refresh && this.timeout.refresh(), oe(s >= 200), o > -1 && this.bytesRead + A.length > o)
      return ce.destroy(r, new Xd()), -1;
    if (this.bytesRead += A.length, n.onData(A) === !1)
      return FA.ERROR.PAUSED;
  }
  onMessageComplete() {
    const { client: A, socket: t, statusCode: r, upgrade: s, headers: o, contentLength: n, bytesRead: i, shouldKeepAlive: a } = this;
    if (t.destroyed && (!r || a))
      return -1;
    if (s)
      return;
    const g = A[ke][A[Fe]];
    if (oe(g), oe(r >= 100), this.statusCode = null, this.statusText = "", this.bytesRead = 0, this.contentLength = "", this.keepAlive = "", this.connection = "", oe(this.headers.length % 2 === 0), this.headers = [], this.headersSize = 0, !(r < 200)) {
      if (g.method !== "HEAD" && n && i !== parseInt(n, 10))
        return ce.destroy(t, new jd()), -1;
      if (g.onComplete(o), A[ke][A[Fe]++] = null, t[VA])
        return oe.strictEqual(A[_e], 0), ce.destroy(t, new _A("reset")), FA.ERROR.PAUSED;
      if (a) {
        if (t[cA] && A[_e] === 0)
          return ce.destroy(t, new _A("reset")), FA.ERROR.PAUSED;
        A[it] === 1 ? setImmediate(IA, A) : IA(A);
      } else return ce.destroy(t, new _A("reset")), FA.ERROR.PAUSED;
    }
  }
}
function TQ(e) {
  const { socket: A, timeoutType: t, client: r } = e;
  t === tr ? (!A[VA] || A.writableNeedDrain || r[_e] > 1) && (oe(!e.paused, "cannot be paused while waiting for headers"), ce.destroy(A, new $d())) : t === Fs ? e.paused || ce.destroy(A, new zd()) : t === Xn && (oe(r[_e] === 0 && r[Pr]), ce.destroy(A, new _A("socket idle timeout")));
}
function $l() {
  const { [ve]: e } = this;
  e && e.readMore();
}
function Kl(e) {
  const { [NA]: A, [ve]: t } = this;
  if (oe(e.code !== "ERR_TLS_CERT_ALTNAME_INVALID"), A[vA] !== "h2" && e.code === "ECONNRESET" && t.statusCode && !t.shouldKeepAlive) {
    t.onMessageComplete();
    return;
  }
  this[Xe] = e, Ws(this[NA], e);
}
function Ws(e, A) {
  if (e[_e] === 0 && A.code !== "UND_ERR_INFO" && A.code !== "UND_ERR_SOCKET") {
    oe(e[CA] === e[Fe]);
    const t = e[ke].splice(e[Fe]);
    for (let r = 0; r < t.length; r++) {
      const s = t[r];
      gA(e, s, A);
    }
    oe(e[Rt] === 0);
  }
}
function zl() {
  const { [ve]: e, [NA]: A } = this;
  if (A[vA] !== "h2" && e.statusCode && !e.shouldKeepAlive) {
    e.onMessageComplete();
    return;
  }
  ce.destroy(this, new er("other side closed", ce.getSocketInfo(this)));
}
function ei() {
  const { [NA]: e, [ve]: A } = this;
  e[vA] === "h1" && A && (!this[Xe] && A.statusCode && !A.shouldKeepAlive && A.onMessageComplete(), this[ve].destroy(), this[ve] = null);
  const t = this[Xe] || new er("closed", ce.getSocketInfo(this));
  if (e[Le] = null, e.destroyed) {
    oe(e[Ft] === 0);
    const r = e[ke].splice(e[Fe]);
    for (let s = 0; s < r.length; s++) {
      const o = r[s];
      gA(e, o, t);
    }
  } else if (e[_e] > 0 && t.code !== "UND_ERR_INFO") {
    const r = e[ke][e[Fe]];
    e[ke][e[Fe]++] = null, gA(e, r, t);
  }
  e[CA] = e[Fe], oe(e[_e] === 0), e.emit("disconnect", e[Ze], [e], t), IA(e);
}
async function Zl(e) {
  oe(!e[Vt]), oe(!e[Le]);
  let { host: A, hostname: t, protocol: r, port: s } = e[Ze];
  if (t[0] === "[") {
    const o = t.indexOf("]");
    oe(o !== -1);
    const n = t.substring(1, o);
    oe(Pl.isIP(n)), t = n;
  }
  e[Vt] = !0, sA.beforeConnect.hasSubscribers && sA.beforeConnect.publish({
    connectParams: {
      host: A,
      hostname: t,
      protocol: r,
      port: s,
      servername: e[rt],
      localAddress: e[Ur]
    },
    connector: e[Sr]
  });
  try {
    const o = await new Promise((i, a) => {
      e[Sr]({
        host: A,
        hostname: t,
        protocol: r,
        port: s,
        servername: e[rt],
        localAddress: e[Ur]
      }, (g, c) => {
        g ? a(g) : i(c);
      });
    });
    if (e.destroyed) {
      ce.destroy(o.on("error", () => {
      }), new eQ());
      return;
    }
    if (e[Vt] = !1, oe(o), o.alpnProtocol === "h2") {
      ba || (ba = !0, process.emitWarning("H2 support is experimental, expect them to change at any time.", {
        code: "UNDICI-H2"
      }));
      const i = Ms.connect(e[Ze], {
        createConnection: () => o,
        peerMaxConcurrentStreams: e[Ls].maxConcurrentStreams
      });
      e[vA] = "h2", i[NA] = e, i[Le] = o, i.on("error", pQ), i.on("frameError", fQ), i.on("end", mQ), i.on("goaway", wQ), i.on("close", ei), i.unref(), e[BA] = i, o[BA] = i;
    } else
      Oo || (Oo = await Zn, Zn = null), o[Fr] = !1, o[VA] = !1, o[cA] = !1, o[Ar] = !1, o[ve] = new DQ(e, o, Oo);
    o[ql] = 0, o[xr] = e[xr], o[NA] = e, o[Xe] = null, o.on("error", Kl).on("readable", $l).on("end", zl).on("close", ei), e[Le] = o, sA.connected.hasSubscribers && sA.connected.publish({
      connectParams: {
        host: A,
        hostname: t,
        protocol: r,
        port: s,
        servername: e[rt],
        localAddress: e[Ur]
      },
      connector: e[Sr],
      socket: o
    }), e.emit("connect", e[Ze], [e]);
  } catch (o) {
    if (e.destroyed)
      return;
    if (e[Vt] = !1, sA.connectError.hasSubscribers && sA.connectError.publish({
      connectParams: {
        host: A,
        hostname: t,
        protocol: r,
        port: s,
        servername: e[rt],
        localAddress: e[Ur]
      },
      connector: e[Sr],
      error: o
    }), o.code === "ERR_TLS_CERT_ALTNAME_INVALID")
      for (oe(e[_e] === 0); e[Ft] > 0 && e[ke][e[CA]].servername === e[rt]; ) {
        const n = e[ke][e[CA]++];
        gA(e, n, o);
      }
    else
      Ws(e, o);
    e.emit("connectionError", e[Ze], [e], o);
  }
  IA(e);
}
function Ra(e) {
  e[nt] = 0, e.emit("drain", e[Ze], [e]);
}
function IA(e, A) {
  e[yt] !== 2 && (e[yt] = 2, kQ(e, A), e[yt] = 0, e[Fe] > 256 && (e[ke].splice(0, e[Fe]), e[CA] -= e[Fe], e[Fe] = 0));
}
function kQ(e, A) {
  for (; ; ) {
    if (e.destroyed) {
      oe(e[Ft] === 0);
      return;
    }
    if (e[st] && !e[Rt]) {
      e[st](), e[st] = null;
      return;
    }
    const t = e[Le];
    if (t && !t.destroyed && t.alpnProtocol !== "h2") {
      if (e[Rt] === 0 ? !t[Fr] && t.unref && (t.unref(), t[Fr] = !0) : t[Fr] && t.ref && (t.ref(), t[Fr] = !1), e[Rt] === 0)
        t[ve].timeoutType !== Xn && t[ve].setTimeout(e[Pr], Xn);
      else if (e[_e] > 0 && t[ve].statusCode < 200 && t[ve].timeoutType !== tr) {
        const s = e[ke][e[Fe]], o = s.headersTimeout != null ? s.headersTimeout : e[Hl];
        t[ve].setTimeout(o, tr);
      }
    }
    if (e[Kn])
      e[nt] = 2;
    else if (e[nt] === 2) {
      A ? (e[nt] = 1, process.nextTick(Ra, e)) : Ra(e);
      continue;
    }
    if (e[Ft] === 0 || e[_e] >= (e[it] || 1))
      return;
    const r = e[ke][e[CA]];
    if (e[Ze].protocol === "https:" && e[rt] !== r.servername) {
      if (e[_e] > 0)
        return;
      if (e[rt] = r.servername, t && t.servername !== r.servername) {
        ce.destroy(t, new _A("servername changed"));
        return;
      }
    }
    if (e[Vt])
      return;
    if (!t && !e[BA]) {
      Zl(e);
      return;
    }
    if (t.destroyed || t[VA] || t[cA] || t[Ar] || e[_e] > 0 && !r.idempotent || e[_e] > 0 && (r.upgrade || r.method === "CONNECT") || e[_e] > 0 && ce.bodyLength(r.body) !== 0 && (ce.isStream(r.body) || ce.isAsyncIterable(r.body)))
      return;
    !r.aborted && FQ(e, r) ? e[CA]++ : e[ke].splice(e[CA], 1);
  }
}
function Xl(e) {
  return e !== "GET" && e !== "HEAD" && e !== "OPTIONS" && e !== "TRACE" && e !== "CONNECT";
}
function FQ(e, A) {
  if (e[vA] === "h2") {
    SQ(e, e[BA], A);
    return;
  }
  const { body: t, method: r, path: s, host: o, upgrade: n, headers: i, blocking: a, reset: g } = A, c = r === "PUT" || r === "POST" || r === "PATCH";
  t && typeof t.read == "function" && t.read(0);
  const E = ce.bodyLength(t);
  let l = E;
  if (l === null && (l = A.contentLength), l === 0 && !c && (l = null), Xl(r) && l > 0 && A.contentLength !== null && A.contentLength !== l) {
    if (e[Yr])
      return gA(e, A, new HA()), !1;
    process.emitWarning(new HA());
  }
  const Q = e[Le];
  try {
    A.onConnect((d) => {
      A.aborted || A.completed || (gA(e, A, d || new bi()), ce.destroy(Q, new _A("aborted")));
    });
  } catch (d) {
    gA(e, A, d);
  }
  if (A.aborted)
    return !1;
  r === "HEAD" && (Q[cA] = !0), (n || r === "CONNECT") && (Q[cA] = !0), g != null && (Q[cA] = g), e[xr] && Q[ql]++ >= e[xr] && (Q[cA] = !0), a && (Q[Ar] = !0);
  let I = `${r} ${s} HTTP/1.1\r
`;
  return typeof o == "string" ? I += `host: ${o}\r
` : I += e[Yl], n ? I += `connection: upgrade\r
upgrade: ${n}\r
` : e[it] && !Q[cA] ? I += `connection: keep-alive\r
` : I += `connection: close\r
`, i && (I += i), sA.sendHeaders.hasSubscribers && sA.sendHeaders.publish({ request: A, headers: I, socket: Q }), !t || E === 0 ? (l === 0 ? Q.write(`${I}content-length: 0\r
\r
`, "latin1") : (oe(l === null, "no body must not have content length"), Q.write(`${I}\r
`, "latin1")), A.onRequestSent()) : ce.isBuffer(t) ? (oe(l === t.byteLength, "buffer body must have content length"), Q.cork(), Q.write(`${I}content-length: ${l}\r
\r
`, "latin1"), Q.write(t), Q.uncork(), A.onBodySent(t), A.onRequestSent(), c || (Q[cA] = !0)) : ce.isBlobLike(t) ? typeof t.stream == "function" ? Os({ body: t.stream(), client: e, request: A, socket: Q, contentLength: l, header: I, expectsPayload: c }) : AE({ body: t, client: e, request: A, socket: Q, contentLength: l, header: I, expectsPayload: c }) : ce.isStream(t) ? eE({ body: t, client: e, request: A, socket: Q, contentLength: l, header: I, expectsPayload: c }) : ce.isIterable(t) ? Os({ body: t, client: e, request: A, socket: Q, contentLength: l, header: I, expectsPayload: c }) : oe(!1), !0;
}
function SQ(e, A, t) {
  const { body: r, method: s, path: o, host: n, upgrade: i, expectContinue: a, signal: g, headers: c } = t;
  let E;
  if (typeof c == "string" ? E = $n[gQ](c.trim()) : E = c, i)
    return gA(e, t, new Error("Upgrade not supported for H2")), !1;
  try {
    t.onConnect((u) => {
      t.aborted || t.completed || gA(e, t, u || new bi());
    });
  } catch (u) {
    gA(e, t, u);
  }
  if (t.aborted)
    return !1;
  let l;
  const Q = e[Ls];
  if (E[EQ] = n || e[jl], E[uQ] = s, s === "CONNECT")
    return A.ref(), l = A.request(E, { endStream: !1, signal: g }), l.id && !l.pending ? (t.onUpgrade(null, null, l), ++Q.openStreams) : l.once("ready", () => {
      t.onUpgrade(null, null, l), ++Q.openStreams;
    }), l.once("close", () => {
      Q.openStreams -= 1, Q.openStreams === 0 && A.unref();
    }), !0;
  E[hQ] = o, E[dQ] = "https";
  const I = s === "PUT" || s === "POST" || s === "PATCH";
  r && typeof r.read == "function" && r.read(0);
  let d = ce.bodyLength(r);
  if (d == null && (d = t.contentLength), (d === 0 || !I) && (d = null), Xl(s) && d > 0 && t.contentLength != null && t.contentLength !== d) {
    if (e[Yr])
      return gA(e, t, new HA()), !1;
    process.emitWarning(new HA());
  }
  d != null && (oe(r, "no body must not have content length"), E[QQ] = `${d}`), A.ref();
  const h = s === "GET" || s === "HEAD";
  return a ? (E[CQ] = "100-continue", l = A.request(E, { endStream: h, signal: g }), l.once("continue", C)) : (l = A.request(E, {
    endStream: h,
    signal: g
  }), C()), ++Q.openStreams, l.once("response", (u) => {
    const { [BQ]: B, ...m } = u;
    t.onHeaders(Number(B), m, l.resume.bind(l), "") === !1 && l.pause();
  }), l.once("end", () => {
    t.onComplete([]);
  }), l.on("data", (u) => {
    t.onData(u) === !1 && l.pause();
  }), l.once("close", () => {
    Q.openStreams -= 1, Q.openStreams === 0 && A.unref();
  }), l.once("error", function(u) {
    e[BA] && !e[BA].destroyed && !this.closed && !this.destroyed && (Q.streams -= 1, ce.destroy(l, u));
  }), l.once("frameError", (u, B) => {
    const m = new _A(`HTTP/2: "frameError" received - type ${u}, code ${B}`);
    gA(e, t, m), e[BA] && !e[BA].destroyed && !this.closed && !this.destroyed && (Q.streams -= 1, ce.destroy(l, m));
  }), !0;
  function C() {
    r ? ce.isBuffer(r) ? (oe(d === r.byteLength, "buffer body must have content length"), l.cork(), l.write(r), l.uncork(), l.end(), t.onBodySent(r), t.onRequestSent()) : ce.isBlobLike(r) ? typeof r.stream == "function" ? Os({
      client: e,
      request: t,
      contentLength: d,
      h2stream: l,
      expectsPayload: I,
      body: r.stream(),
      socket: e[Le],
      header: ""
    }) : AE({
      body: r,
      client: e,
      request: t,
      contentLength: d,
      expectsPayload: I,
      h2stream: l,
      header: "",
      socket: e[Le]
    }) : ce.isStream(r) ? eE({
      body: r,
      client: e,
      request: t,
      contentLength: d,
      expectsPayload: I,
      socket: e[Le],
      h2stream: l,
      header: ""
    }) : ce.isIterable(r) ? Os({
      body: r,
      client: e,
      request: t,
      contentLength: d,
      expectsPayload: I,
      header: "",
      h2stream: l,
      socket: e[Le]
    }) : oe(!1) : t.onRequestSent();
  }
}
function eE({ h2stream: e, body: A, client: t, request: r, socket: s, contentLength: o, header: n, expectsPayload: i }) {
  if (oe(o !== 0 || t[_e] === 0, "stream body cannot be pipelined"), t[vA] === "h2") {
    let d = function(h) {
      r.onBodySent(h);
    };
    const I = qd(
      A,
      e,
      (h) => {
        h ? (ce.destroy(A, h), ce.destroy(e, h)) : r.onRequestSent();
      }
    );
    I.on("data", d), I.once("end", () => {
      I.removeListener("data", d), ce.destroy(I);
    });
    return;
  }
  let a = !1;
  const g = new tE({ socket: s, request: r, contentLength: o, client: t, expectsPayload: i, header: n }), c = function(I) {
    if (!a)
      try {
        !g.write(I) && this.pause && this.pause();
      } catch (d) {
        ce.destroy(this, d);
      }
  }, E = function() {
    a || A.resume && A.resume();
  }, l = function() {
    if (a)
      return;
    const I = new bi();
    queueMicrotask(() => Q(I));
  }, Q = function(I) {
    if (!a) {
      if (a = !0, oe(s.destroyed || s[VA] && t[_e] <= 1), s.off("drain", E).off("error", Q), A.removeListener("data", c).removeListener("end", Q).removeListener("error", Q).removeListener("close", l), !I)
        try {
          g.end();
        } catch (d) {
          I = d;
        }
      g.destroy(I), I && (I.code !== "UND_ERR_INFO" || I.message !== "reset") ? ce.destroy(A, I) : ce.destroy(A);
    }
  };
  A.on("data", c).on("end", Q).on("error", Q).on("close", l), A.resume && A.resume(), s.on("drain", E).on("error", Q);
}
async function AE({ h2stream: e, body: A, client: t, request: r, socket: s, contentLength: o, header: n, expectsPayload: i }) {
  oe(o === A.size, "blob body must have content length");
  const a = t[vA] === "h2";
  try {
    if (o != null && o !== A.size)
      throw new HA();
    const g = Buffer.from(await A.arrayBuffer());
    a ? (e.cork(), e.write(g), e.uncork()) : (s.cork(), s.write(`${n}content-length: ${o}\r
\r
`, "latin1"), s.write(g), s.uncork()), r.onBodySent(g), r.onRequestSent(), i || (s[cA] = !0), IA(t);
  } catch (g) {
    ce.destroy(a ? e : s, g);
  }
}
async function Os({ h2stream: e, body: A, client: t, request: r, socket: s, contentLength: o, header: n, expectsPayload: i }) {
  oe(o !== 0 || t[_e] === 0, "iterator body cannot be pipelined");
  let a = null;
  function g() {
    if (a) {
      const l = a;
      a = null, l();
    }
  }
  const c = () => new Promise((l, Q) => {
    oe(a === null), s[Xe] ? Q(s[Xe]) : a = l;
  });
  if (t[vA] === "h2") {
    e.on("close", g).on("drain", g);
    try {
      for await (const l of A) {
        if (s[Xe])
          throw s[Xe];
        const Q = e.write(l);
        r.onBodySent(l), Q || await c();
      }
    } catch (l) {
      e.destroy(l);
    } finally {
      r.onRequestSent(), e.end(), e.off("close", g).off("drain", g);
    }
    return;
  }
  s.on("close", g).on("drain", g);
  const E = new tE({ socket: s, request: r, contentLength: o, client: t, expectsPayload: i, header: n });
  try {
    for await (const l of A) {
      if (s[Xe])
        throw s[Xe];
      E.write(l) || await c();
    }
    E.end();
  } catch (l) {
    E.destroy(l);
  } finally {
    s.off("close", g).off("drain", g);
  }
}
class tE {
  constructor({ socket: A, request: t, contentLength: r, client: s, expectsPayload: o, header: n }) {
    this.socket = A, this.request = t, this.contentLength = r, this.client = s, this.bytesWritten = 0, this.expectsPayload = o, this.header = n, A[VA] = !0;
  }
  write(A) {
    const { socket: t, request: r, contentLength: s, client: o, bytesWritten: n, expectsPayload: i, header: a } = this;
    if (t[Xe])
      throw t[Xe];
    if (t.destroyed)
      return !1;
    const g = Buffer.byteLength(A);
    if (!g)
      return !0;
    if (s !== null && n + g > s) {
      if (o[Yr])
        throw new HA();
      process.emitWarning(new HA());
    }
    t.cork(), n === 0 && (i || (t[cA] = !0), s === null ? t.write(`${a}transfer-encoding: chunked\r
`, "latin1") : t.write(`${a}content-length: ${s}\r
\r
`, "latin1")), s === null && t.write(`\r
${g.toString(16)}\r
`, "latin1"), this.bytesWritten += g;
    const c = t.write(A);
    return t.uncork(), r.onBodySent(A), c || t[ve].timeout && t[ve].timeoutType === tr && t[ve].timeout.refresh && t[ve].timeout.refresh(), c;
  }
  end() {
    const { socket: A, contentLength: t, client: r, bytesWritten: s, expectsPayload: o, header: n, request: i } = this;
    if (i.onRequestSent(), A[VA] = !1, A[Xe])
      throw A[Xe];
    if (!A.destroyed) {
      if (s === 0 ? o ? A.write(`${n}content-length: 0\r
\r
`, "latin1") : A.write(`${n}\r
`, "latin1") : t === null && A.write(`\r
0\r
\r
`, "latin1"), t !== null && s !== t) {
        if (r[Yr])
          throw new HA();
        process.emitWarning(new HA());
      }
      A[ve].timeout && A[ve].timeoutType === tr && A[ve].timeout.refresh && A[ve].timeout.refresh(), IA(r);
    }
  }
  destroy(A) {
    const { socket: t, client: r } = this;
    t[VA] = !1, A && (oe(r[_e] <= 1, "pipeline should only contain this request"), ce.destroy(t, A));
  }
}
function gA(e, A, t) {
  try {
    A.onError(t), oe(A.aborted);
  } catch (r) {
    e.emit("error", r);
  }
}
var js = IQ;
const rE = 2048, Po = rE - 1;
class Da {
  constructor() {
    this.bottom = 0, this.top = 0, this.list = new Array(rE), this.next = null;
  }
  isEmpty() {
    return this.top === this.bottom;
  }
  isFull() {
    return (this.top + 1 & Po) === this.bottom;
  }
  push(A) {
    this.list[this.top] = A, this.top = this.top + 1 & Po;
  }
  shift() {
    const A = this.list[this.bottom];
    return A === void 0 ? null : (this.list[this.bottom] = void 0, this.bottom = this.bottom + 1 & Po, A);
  }
}
var UQ = class {
  constructor() {
    this.head = this.tail = new Da();
  }
  isEmpty() {
    return this.head.isEmpty();
  }
  push(A) {
    this.head.isFull() && (this.head = this.head.next = new Da()), this.head.push(A);
  }
  shift() {
    const A = this.tail, t = A.shift();
    return A.isEmpty() && A.next !== null && (this.tail = A.next), t;
  }
};
const { kFree: GQ, kConnected: _Q, kPending: NQ, kQueued: vQ, kRunning: LQ, kSize: MQ } = Se, Qt = Symbol("pool");
let OQ = class {
  constructor(A) {
    this[Qt] = A;
  }
  get connected() {
    return this[Qt][_Q];
  }
  get free() {
    return this[Qt][GQ];
  }
  get pending() {
    return this[Qt][NQ];
  }
  get queued() {
    return this[Qt][vQ];
  }
  get running() {
    return this[Qt][LQ];
  }
  get size() {
    return this[Qt][MQ];
  }
};
var PQ = OQ;
const YQ = Vs, xQ = UQ, { kConnected: Yo, kSize: Ta, kRunning: ka, kPending: Fa, kQueued: pr, kBusy: JQ, kFree: HQ, kUrl: VQ, kClose: qQ, kDestroy: WQ, kDispatch: jQ } = Se, $Q = PQ, uA = Symbol("clients"), aA = Symbol("needDrain"), fr = Symbol("queue"), xo = Symbol("closed resolve"), Jo = Symbol("onDrain"), Sa = Symbol("onConnect"), Ua = Symbol("onDisconnect"), Ga = Symbol("onConnectionError"), Ai = Symbol("get dispatcher"), sE = Symbol("add client"), oE = Symbol("remove client"), _a = Symbol("stats");
let KQ = class extends YQ {
  constructor() {
    super(), this[fr] = new xQ(), this[uA] = [], this[pr] = 0;
    const A = this;
    this[Jo] = function(r, s) {
      const o = A[fr];
      let n = !1;
      for (; !n; ) {
        const i = o.shift();
        if (!i)
          break;
        A[pr]--, n = !this.dispatch(i.opts, i.handler);
      }
      this[aA] = n, !this[aA] && A[aA] && (A[aA] = !1, A.emit("drain", r, [A, ...s])), A[xo] && o.isEmpty() && Promise.all(A[uA].map((i) => i.close())).then(A[xo]);
    }, this[Sa] = (t, r) => {
      A.emit("connect", t, [A, ...r]);
    }, this[Ua] = (t, r, s) => {
      A.emit("disconnect", t, [A, ...r], s);
    }, this[Ga] = (t, r, s) => {
      A.emit("connectionError", t, [A, ...r], s);
    }, this[_a] = new $Q(this);
  }
  get [JQ]() {
    return this[aA];
  }
  get [Yo]() {
    return this[uA].filter((A) => A[Yo]).length;
  }
  get [HQ]() {
    return this[uA].filter((A) => A[Yo] && !A[aA]).length;
  }
  get [Fa]() {
    let A = this[pr];
    for (const { [Fa]: t } of this[uA])
      A += t;
    return A;
  }
  get [ka]() {
    let A = 0;
    for (const { [ka]: t } of this[uA])
      A += t;
    return A;
  }
  get [Ta]() {
    let A = this[pr];
    for (const { [Ta]: t } of this[uA])
      A += t;
    return A;
  }
  get stats() {
    return this[_a];
  }
  async [qQ]() {
    return this[fr].isEmpty() ? Promise.all(this[uA].map((A) => A.close())) : new Promise((A) => {
      this[xo] = A;
    });
  }
  async [WQ](A) {
    for (; ; ) {
      const t = this[fr].shift();
      if (!t)
        break;
      t.handler.onError(A);
    }
    return Promise.all(this[uA].map((t) => t.destroy(A)));
  }
  [jQ](A, t) {
    const r = this[Ai]();
    return r ? r.dispatch(A, t) || (r[aA] = !0, this[aA] = !this[Ai]()) : (this[aA] = !0, this[fr].push({ opts: A, handler: t }), this[pr]++), !this[aA];
  }
  [sE](A) {
    return A.on("drain", this[Jo]).on("connect", this[Sa]).on("disconnect", this[Ua]).on("connectionError", this[Ga]), this[uA].push(A), this[aA] && process.nextTick(() => {
      this[aA] && this[Jo](A[VQ], [this, A]);
    }), this;
  }
  [oE](A) {
    A.close(() => {
      const t = this[uA].indexOf(A);
      t !== -1 && this[uA].splice(t, 1);
    }), this[aA] = this[uA].some((t) => !t[aA] && t.closed !== !0 && t.destroyed !== !0);
  }
};
var nE = {
  PoolBase: KQ,
  kClients: uA,
  kNeedDrain: aA,
  kAddClient: sE,
  kRemoveClient: oE,
  kGetDispatcher: Ai
};
const {
  PoolBase: zQ,
  kClients: Na,
  kNeedDrain: ZQ,
  kAddClient: XQ,
  kGetDispatcher: eC
} = nE, AC = js, {
  InvalidArgumentError: Ho
} = Re, Vo = we, { kUrl: va, kInterceptors: tC } = Se, rC = qs, qo = Symbol("options"), Wo = Symbol("connections"), La = Symbol("factory");
function sC(e, A) {
  return new AC(e, A);
}
let oC = class extends zQ {
  constructor(A, {
    connections: t,
    factory: r = sC,
    connect: s,
    connectTimeout: o,
    tls: n,
    maxCachedSessions: i,
    socketPath: a,
    autoSelectFamily: g,
    autoSelectFamilyAttemptTimeout: c,
    allowH2: E,
    ...l
  } = {}) {
    if (super(), t != null && (!Number.isFinite(t) || t < 0))
      throw new Ho("invalid connections");
    if (typeof r != "function")
      throw new Ho("factory must be a function.");
    if (s != null && typeof s != "function" && typeof s != "object")
      throw new Ho("connect must be a function or an object");
    typeof s != "function" && (s = rC({
      ...n,
      maxCachedSessions: i,
      allowH2: E,
      socketPath: a,
      timeout: o,
      ...Vo.nodeHasAutoSelectFamily && g ? { autoSelectFamily: g, autoSelectFamilyAttemptTimeout: c } : void 0,
      ...s
    })), this[tC] = l.interceptors && l.interceptors.Pool && Array.isArray(l.interceptors.Pool) ? l.interceptors.Pool : [], this[Wo] = t || null, this[va] = Vo.parseOrigin(A), this[qo] = { ...Vo.deepClone(l), connect: s, allowH2: E }, this[qo].interceptors = l.interceptors ? { ...l.interceptors } : void 0, this[La] = r;
  }
  [eC]() {
    let A = this[Na].find((t) => !t[ZQ]);
    return A || ((!this[Wo] || this[Na].length < this[Wo]) && (A = this[La](this[va], this[qo]), this[XQ](A)), A);
  }
};
var $r = oC;
const {
  BalancedPoolMissingUpstreamError: nC,
  InvalidArgumentError: iC
} = Re, {
  PoolBase: aC,
  kClients: nA,
  kNeedDrain: mr,
  kAddClient: cC,
  kRemoveClient: gC,
  kGetDispatcher: lC
} = nE, EC = $r, { kUrl: jo, kInterceptors: uC } = Se, { parseOrigin: Ma } = we, Oa = Symbol("factory"), cs = Symbol("options"), Pa = Symbol("kGreatestCommonDivisor"), Ct = Symbol("kCurrentWeight"), Bt = Symbol("kIndex"), pA = Symbol("kWeight"), gs = Symbol("kMaxWeightPerServer"), ls = Symbol("kErrorPenalty");
function iE(e, A) {
  return A === 0 ? e : iE(A, e % A);
}
function hC(e, A) {
  return new EC(e, A);
}
let dC = class extends aC {
  constructor(A = [], { factory: t = hC, ...r } = {}) {
    if (super(), this[cs] = r, this[Bt] = -1, this[Ct] = 0, this[gs] = this[cs].maxWeightPerServer || 100, this[ls] = this[cs].errorPenalty || 15, Array.isArray(A) || (A = [A]), typeof t != "function")
      throw new iC("factory must be a function.");
    this[uC] = r.interceptors && r.interceptors.BalancedPool && Array.isArray(r.interceptors.BalancedPool) ? r.interceptors.BalancedPool : [], this[Oa] = t;
    for (const s of A)
      this.addUpstream(s);
    this._updateBalancedPoolStats();
  }
  addUpstream(A) {
    const t = Ma(A).origin;
    if (this[nA].find((s) => s[jo].origin === t && s.closed !== !0 && s.destroyed !== !0))
      return this;
    const r = this[Oa](t, Object.assign({}, this[cs]));
    this[cC](r), r.on("connect", () => {
      r[pA] = Math.min(this[gs], r[pA] + this[ls]);
    }), r.on("connectionError", () => {
      r[pA] = Math.max(1, r[pA] - this[ls]), this._updateBalancedPoolStats();
    }), r.on("disconnect", (...s) => {
      const o = s[2];
      o && o.code === "UND_ERR_SOCKET" && (r[pA] = Math.max(1, r[pA] - this[ls]), this._updateBalancedPoolStats());
    });
    for (const s of this[nA])
      s[pA] = this[gs];
    return this._updateBalancedPoolStats(), this;
  }
  _updateBalancedPoolStats() {
    this[Pa] = this[nA].map((A) => A[pA]).reduce(iE, 0);
  }
  removeUpstream(A) {
    const t = Ma(A).origin, r = this[nA].find((s) => s[jo].origin === t && s.closed !== !0 && s.destroyed !== !0);
    return r && this[gC](r), this;
  }
  get upstreams() {
    return this[nA].filter((A) => A.closed !== !0 && A.destroyed !== !0).map((A) => A[jo].origin);
  }
  [lC]() {
    if (this[nA].length === 0)
      throw new nC();
    if (!this[nA].find((o) => !o[mr] && o.closed !== !0 && o.destroyed !== !0) || this[nA].map((o) => o[mr]).reduce((o, n) => o && n, !0))
      return;
    let r = 0, s = this[nA].findIndex((o) => !o[mr]);
    for (; r++ < this[nA].length; ) {
      this[Bt] = (this[Bt] + 1) % this[nA].length;
      const o = this[nA][this[Bt]];
      if (o[pA] > this[nA][s][pA] && !o[mr] && (s = this[Bt]), this[Bt] === 0 && (this[Ct] = this[Ct] - this[Pa], this[Ct] <= 0 && (this[Ct] = this[gs])), o[pA] >= this[Ct] && !o[mr])
        return o;
    }
    return this[Ct] = this[nA][s][pA], this[Bt] = s, this[nA][s];
  }
};
var QC = dC;
const { kConnected: aE, kSize: cE } = Se;
class Ya {
  constructor(A) {
    this.value = A;
  }
  deref() {
    return this.value[aE] === 0 && this.value[cE] === 0 ? void 0 : this.value;
  }
}
class xa {
  constructor(A) {
    this.finalizer = A;
  }
  register(A, t) {
    A.on && A.on("disconnect", () => {
      A[aE] === 0 && A[cE] === 0 && this.finalizer(t);
    });
  }
}
var gE = function() {
  return process.env.NODE_V8_COVERAGE ? {
    WeakRef: Ya,
    FinalizationRegistry: xa
  } : {
    WeakRef: O.WeakRef || Ya,
    FinalizationRegistry: O.FinalizationRegistry || xa
  };
};
const { InvalidArgumentError: Es } = Re, { kClients: ZA, kRunning: Ja, kClose: CC, kDestroy: BC, kDispatch: IC, kInterceptors: pC } = Se, fC = Vs, mC = $r, wC = js, yC = we, bC = yi, { WeakRef: RC, FinalizationRegistry: DC } = gE(), Ha = Symbol("onConnect"), Va = Symbol("onDisconnect"), qa = Symbol("onConnectionError"), TC = Symbol("maxRedirections"), Wa = Symbol("onDrain"), ja = Symbol("factory"), $a = Symbol("finalizer"), $o = Symbol("options");
function kC(e, A) {
  return A && A.connections === 1 ? new wC(e, A) : new mC(e, A);
}
let FC = class extends fC {
  constructor({ factory: A = kC, maxRedirections: t = 0, connect: r, ...s } = {}) {
    if (super(), typeof A != "function")
      throw new Es("factory must be a function.");
    if (r != null && typeof r != "function" && typeof r != "object")
      throw new Es("connect must be a function or an object");
    if (!Number.isInteger(t) || t < 0)
      throw new Es("maxRedirections must be a positive number");
    r && typeof r != "function" && (r = { ...r }), this[pC] = s.interceptors && s.interceptors.Agent && Array.isArray(s.interceptors.Agent) ? s.interceptors.Agent : [bC({ maxRedirections: t })], this[$o] = { ...yC.deepClone(s), connect: r }, this[$o].interceptors = s.interceptors ? { ...s.interceptors } : void 0, this[TC] = t, this[ja] = A, this[ZA] = /* @__PURE__ */ new Map(), this[$a] = new DC(
      /* istanbul ignore next: gc is undeterministic */
      (n) => {
        const i = this[ZA].get(n);
        i !== void 0 && i.deref() === void 0 && this[ZA].delete(n);
      }
    );
    const o = this;
    this[Wa] = (n, i) => {
      o.emit("drain", n, [o, ...i]);
    }, this[Ha] = (n, i) => {
      o.emit("connect", n, [o, ...i]);
    }, this[Va] = (n, i, a) => {
      o.emit("disconnect", n, [o, ...i], a);
    }, this[qa] = (n, i, a) => {
      o.emit("connectionError", n, [o, ...i], a);
    };
  }
  get [Ja]() {
    let A = 0;
    for (const t of this[ZA].values()) {
      const r = t.deref();
      r && (A += r[Ja]);
    }
    return A;
  }
  [IC](A, t) {
    let r;
    if (A.origin && (typeof A.origin == "string" || A.origin instanceof URL))
      r = String(A.origin);
    else
      throw new Es("opts.origin must be a non-empty string or URL.");
    const s = this[ZA].get(r);
    let o = s ? s.deref() : null;
    return o || (o = this[ja](A.origin, this[$o]).on("drain", this[Wa]).on("connect", this[Ha]).on("disconnect", this[Va]).on("connectionError", this[qa]), this[ZA].set(r, new RC(o)), this[$a].register(o, r)), o.dispatch(A, t);
  }
  async [CC]() {
    const A = [];
    for (const t of this[ZA].values()) {
      const r = t.deref();
      r && A.push(r.close());
    }
    await Promise.all(A);
  }
  async [BC](A) {
    const t = [];
    for (const r of this[ZA].values()) {
      const s = r.deref();
      s && t.push(s.destroy(A));
    }
    await Promise.all(t);
  }
};
var $s = FC, cr = {}, Ri = { exports: {} };
const lE = Me, { Readable: SC } = lt, { RequestAbortedError: EE, NotSupportedError: UC, InvalidArgumentError: GC } = Re, Ss = we, { ReadableStreamFrom: _C, toUSVString: NC } = we;
let Ko;
const QA = Symbol("kConsume"), us = Symbol("kReading"), At = Symbol("kBody"), Ka = Symbol("abort"), uE = Symbol("kContentType"), za = () => {
};
var vC = class extends SC {
  constructor({
    resume: A,
    abort: t,
    contentType: r = "",
    highWaterMark: s = 64 * 1024
    // Same as nodejs fs streams.
  }) {
    super({
      autoDestroy: !0,
      read: A,
      highWaterMark: s
    }), this._readableState.dataEmitted = !1, this[Ka] = t, this[QA] = null, this[At] = null, this[uE] = r, this[us] = !1;
  }
  destroy(A) {
    return this.destroyed ? this : (!A && !this._readableState.endEmitted && (A = new EE()), A && this[Ka](), super.destroy(A));
  }
  emit(A, ...t) {
    return A === "data" ? this._readableState.dataEmitted = !0 : A === "error" && (this._readableState.errorEmitted = !0), super.emit(A, ...t);
  }
  on(A, ...t) {
    return (A === "data" || A === "readable") && (this[us] = !0), super.on(A, ...t);
  }
  addListener(A, ...t) {
    return this.on(A, ...t);
  }
  off(A, ...t) {
    const r = super.off(A, ...t);
    return (A === "data" || A === "readable") && (this[us] = this.listenerCount("data") > 0 || this.listenerCount("readable") > 0), r;
  }
  removeListener(A, ...t) {
    return this.off(A, ...t);
  }
  push(A) {
    return this[QA] && A !== null && this.readableLength === 0 ? (hE(this[QA], A), this[us] ? super.push(A) : !0) : super.push(A);
  }
  // https://fetch.spec.whatwg.org/#dom-body-text
  async text() {
    return hs(this, "text");
  }
  // https://fetch.spec.whatwg.org/#dom-body-json
  async json() {
    return hs(this, "json");
  }
  // https://fetch.spec.whatwg.org/#dom-body-blob
  async blob() {
    return hs(this, "blob");
  }
  // https://fetch.spec.whatwg.org/#dom-body-arraybuffer
  async arrayBuffer() {
    return hs(this, "arrayBuffer");
  }
  // https://fetch.spec.whatwg.org/#dom-body-formdata
  async formData() {
    throw new UC();
  }
  // https://fetch.spec.whatwg.org/#dom-body-bodyused
  get bodyUsed() {
    return Ss.isDisturbed(this);
  }
  // https://fetch.spec.whatwg.org/#dom-body-body
  get body() {
    return this[At] || (this[At] = _C(this), this[QA] && (this[At].getReader(), lE(this[At].locked))), this[At];
  }
  dump(A) {
    let t = A && Number.isFinite(A.limit) ? A.limit : 262144;
    const r = A && A.signal;
    if (r)
      try {
        if (typeof r != "object" || !("aborted" in r))
          throw new GC("signal must be an AbortSignal");
        Ss.throwIfAborted(r);
      } catch (s) {
        return Promise.reject(s);
      }
    return this.closed ? Promise.resolve(null) : new Promise((s, o) => {
      const n = r ? Ss.addAbortListener(r, () => {
        this.destroy();
      }) : za;
      this.on("close", function() {
        n(), r && r.aborted ? o(r.reason || Object.assign(new Error("The operation was aborted"), { name: "AbortError" })) : s(null);
      }).on("error", za).on("data", function(i) {
        t -= i.length, t <= 0 && this.destroy();
      }).resume();
    });
  }
};
function LC(e) {
  return e[At] && e[At].locked === !0 || e[QA];
}
function MC(e) {
  return Ss.isDisturbed(e) || LC(e);
}
async function hs(e, A) {
  if (MC(e))
    throw new TypeError("unusable");
  return lE(!e[QA]), new Promise((t, r) => {
    e[QA] = {
      type: A,
      stream: e,
      resolve: t,
      reject: r,
      length: 0,
      body: []
    }, e.on("error", function(s) {
      ti(this[QA], s);
    }).on("close", function() {
      this[QA].body !== null && ti(this[QA], new EE());
    }), process.nextTick(OC, e[QA]);
  });
}
function OC(e) {
  if (e.body === null)
    return;
  const { _readableState: A } = e.stream;
  for (const t of A.buffer)
    hE(e, t);
  for (A.endEmitted ? Za(this[QA]) : e.stream.on("end", function() {
    Za(this[QA]);
  }), e.stream.resume(); e.stream.read() != null; )
    ;
}
function Za(e) {
  const { type: A, body: t, resolve: r, stream: s, length: o } = e;
  try {
    if (A === "text")
      r(NC(Buffer.concat(t)));
    else if (A === "json")
      r(JSON.parse(Buffer.concat(t)));
    else if (A === "arrayBuffer") {
      const n = new Uint8Array(o);
      let i = 0;
      for (const a of t)
        n.set(a, i), i += a.byteLength;
      r(n.buffer);
    } else A === "blob" && (Ko || (Ko = require("buffer").Blob), r(new Ko(t, { type: s[uE] })));
    ti(e);
  } catch (n) {
    s.destroy(n);
  }
}
function hE(e, A) {
  e.length += A.length, e.body.push(A);
}
function ti(e, A) {
  e.body !== null && (A ? e.reject(A) : e.resolve(), e.type = null, e.stream = null, e.resolve = null, e.reject = null, e.length = 0, e.body = null);
}
const PC = Me, {
  ResponseStatusCodeError: ds
} = Re, { toUSVString: Xa } = we;
async function YC({ callback: e, body: A, contentType: t, statusCode: r, statusMessage: s, headers: o }) {
  PC(A);
  let n = [], i = 0;
  for await (const a of A)
    if (n.push(a), i += a.length, i > 128 * 1024) {
      n = null;
      break;
    }
  if (r === 204 || !t || !n) {
    process.nextTick(e, new ds(`Response status code ${r}${s ? `: ${s}` : ""}`, r, o));
    return;
  }
  try {
    if (t.startsWith("application/json")) {
      const a = JSON.parse(Xa(Buffer.concat(n)));
      process.nextTick(e, new ds(`Response status code ${r}${s ? `: ${s}` : ""}`, r, o, a));
      return;
    }
    if (t.startsWith("text/")) {
      const a = Xa(Buffer.concat(n));
      process.nextTick(e, new ds(`Response status code ${r}${s ? `: ${s}` : ""}`, r, o, a));
      return;
    }
  } catch {
  }
  process.nextTick(e, new ds(`Response status code ${r}${s ? `: ${s}` : ""}`, r, o));
}
var dE = { getResolveErrorBodyCallback: YC };
const { addAbortListener: xC } = we, { RequestAbortedError: JC } = Re, Kt = Symbol("kListener"), ot = Symbol("kSignal");
function ec(e) {
  e.abort ? e.abort() : e.onError(new JC());
}
function HC(e, A) {
  if (e[ot] = null, e[Kt] = null, !!A) {
    if (A.aborted) {
      ec(e);
      return;
    }
    e[ot] = A, e[Kt] = () => {
      ec(e);
    }, xC(e[ot], e[Kt]);
  }
}
function VC(e) {
  e[ot] && ("removeEventListener" in e[ot] ? e[ot].removeEventListener("abort", e[Kt]) : e[ot].removeListener("abort", e[Kt]), e[ot] = null, e[Kt] = null);
}
var Kr = {
  addSignal: HC,
  removeSignal: VC
};
const qC = vC, {
  InvalidArgumentError: Yt,
  RequestAbortedError: WC
} = Re, SA = we, { getResolveErrorBodyCallback: jC } = dE, { AsyncResource: $C } = Vr, { addSignal: KC, removeSignal: Ac } = Kr;
class QE extends $C {
  constructor(A, t) {
    if (!A || typeof A != "object")
      throw new Yt("invalid opts");
    const { signal: r, method: s, opaque: o, body: n, onInfo: i, responseHeaders: a, throwOnError: g, highWaterMark: c } = A;
    try {
      if (typeof t != "function")
        throw new Yt("invalid callback");
      if (c && (typeof c != "number" || c < 0))
        throw new Yt("invalid highWaterMark");
      if (r && typeof r.on != "function" && typeof r.addEventListener != "function")
        throw new Yt("signal must be an EventEmitter or EventTarget");
      if (s === "CONNECT")
        throw new Yt("invalid method");
      if (i && typeof i != "function")
        throw new Yt("invalid onInfo callback");
      super("UNDICI_REQUEST");
    } catch (E) {
      throw SA.isStream(n) && SA.destroy(n.on("error", SA.nop), E), E;
    }
    this.responseHeaders = a || null, this.opaque = o || null, this.callback = t, this.res = null, this.abort = null, this.body = n, this.trailers = {}, this.context = null, this.onInfo = i || null, this.throwOnError = g, this.highWaterMark = c, SA.isStream(n) && n.on("error", (E) => {
      this.onError(E);
    }), KC(this, r);
  }
  onConnect(A, t) {
    if (!this.callback)
      throw new WC();
    this.abort = A, this.context = t;
  }
  onHeaders(A, t, r, s) {
    const { callback: o, opaque: n, abort: i, context: a, responseHeaders: g, highWaterMark: c } = this, E = g === "raw" ? SA.parseRawHeaders(t) : SA.parseHeaders(t);
    if (A < 200) {
      this.onInfo && this.onInfo({ statusCode: A, headers: E });
      return;
    }
    const Q = (g === "raw" ? SA.parseHeaders(t) : E)["content-type"], I = new qC({ resume: r, abort: i, contentType: Q, highWaterMark: c });
    this.callback = null, this.res = I, o !== null && (this.throwOnError && A >= 400 ? this.runInAsyncScope(
      jC,
      null,
      { callback: o, body: I, contentType: Q, statusCode: A, statusMessage: s, headers: E }
    ) : this.runInAsyncScope(o, null, null, {
      statusCode: A,
      headers: E,
      trailers: this.trailers,
      opaque: n,
      body: I,
      context: a
    }));
  }
  onData(A) {
    const { res: t } = this;
    return t.push(A);
  }
  onComplete(A) {
    const { res: t } = this;
    Ac(this), SA.parseHeaders(A, this.trailers), t.push(null);
  }
  onError(A) {
    const { res: t, callback: r, body: s, opaque: o } = this;
    Ac(this), r && (this.callback = null, queueMicrotask(() => {
      this.runInAsyncScope(r, null, A, { opaque: o });
    })), t && (this.res = null, queueMicrotask(() => {
      SA.destroy(t, A);
    })), s && (this.body = null, SA.destroy(s, A));
  }
}
function CE(e, A) {
  if (A === void 0)
    return new Promise((t, r) => {
      CE.call(this, e, (s, o) => s ? r(s) : t(o));
    });
  try {
    this.dispatch(e, new QE(e, A));
  } catch (t) {
    if (typeof A != "function")
      throw t;
    const r = e && e.opaque;
    queueMicrotask(() => A(t, { opaque: r }));
  }
}
Ri.exports = CE;
Ri.exports.RequestHandler = QE;
var zC = Ri.exports;
const { finished: ZC, PassThrough: XC } = lt, {
  InvalidArgumentError: xt,
  InvalidReturnValueError: eB,
  RequestAbortedError: AB
} = Re, RA = we, { getResolveErrorBodyCallback: tB } = dE, { AsyncResource: rB } = Vr, { addSignal: sB, removeSignal: tc } = Kr;
class oB extends rB {
  constructor(A, t, r) {
    if (!A || typeof A != "object")
      throw new xt("invalid opts");
    const { signal: s, method: o, opaque: n, body: i, onInfo: a, responseHeaders: g, throwOnError: c } = A;
    try {
      if (typeof r != "function")
        throw new xt("invalid callback");
      if (typeof t != "function")
        throw new xt("invalid factory");
      if (s && typeof s.on != "function" && typeof s.addEventListener != "function")
        throw new xt("signal must be an EventEmitter or EventTarget");
      if (o === "CONNECT")
        throw new xt("invalid method");
      if (a && typeof a != "function")
        throw new xt("invalid onInfo callback");
      super("UNDICI_STREAM");
    } catch (E) {
      throw RA.isStream(i) && RA.destroy(i.on("error", RA.nop), E), E;
    }
    this.responseHeaders = g || null, this.opaque = n || null, this.factory = t, this.callback = r, this.res = null, this.abort = null, this.context = null, this.trailers = null, this.body = i, this.onInfo = a || null, this.throwOnError = c || !1, RA.isStream(i) && i.on("error", (E) => {
      this.onError(E);
    }), sB(this, s);
  }
  onConnect(A, t) {
    if (!this.callback)
      throw new AB();
    this.abort = A, this.context = t;
  }
  onHeaders(A, t, r, s) {
    const { factory: o, opaque: n, context: i, callback: a, responseHeaders: g } = this, c = g === "raw" ? RA.parseRawHeaders(t) : RA.parseHeaders(t);
    if (A < 200) {
      this.onInfo && this.onInfo({ statusCode: A, headers: c });
      return;
    }
    this.factory = null;
    let E;
    if (this.throwOnError && A >= 400) {
      const I = (g === "raw" ? RA.parseHeaders(t) : c)["content-type"];
      E = new XC(), this.callback = null, this.runInAsyncScope(
        tB,
        null,
        { callback: a, body: E, contentType: I, statusCode: A, statusMessage: s, headers: c }
      );
    } else {
      if (o === null)
        return;
      if (E = this.runInAsyncScope(o, null, {
        statusCode: A,
        headers: c,
        opaque: n,
        context: i
      }), !E || typeof E.write != "function" || typeof E.end != "function" || typeof E.on != "function")
        throw new eB("expected Writable");
      ZC(E, { readable: !1 }, (Q) => {
        const { callback: I, res: d, opaque: h, trailers: C, abort: u } = this;
        this.res = null, (Q || !d.readable) && RA.destroy(d, Q), this.callback = null, this.runInAsyncScope(I, null, Q || null, { opaque: h, trailers: C }), Q && u();
      });
    }
    return E.on("drain", r), this.res = E, (E.writableNeedDrain !== void 0 ? E.writableNeedDrain : E._writableState && E._writableState.needDrain) !== !0;
  }
  onData(A) {
    const { res: t } = this;
    return t ? t.write(A) : !0;
  }
  onComplete(A) {
    const { res: t } = this;
    tc(this), t && (this.trailers = RA.parseHeaders(A), t.end());
  }
  onError(A) {
    const { res: t, callback: r, opaque: s, body: o } = this;
    tc(this), this.factory = null, t ? (this.res = null, RA.destroy(t, A)) : r && (this.callback = null, queueMicrotask(() => {
      this.runInAsyncScope(r, null, A, { opaque: s });
    })), o && (this.body = null, RA.destroy(o, A));
  }
}
function BE(e, A, t) {
  if (t === void 0)
    return new Promise((r, s) => {
      BE.call(this, e, A, (o, n) => o ? s(o) : r(n));
    });
  try {
    this.dispatch(e, new oB(e, A, t));
  } catch (r) {
    if (typeof t != "function")
      throw r;
    const s = e && e.opaque;
    queueMicrotask(() => t(r, { opaque: s }));
  }
}
var nB = BE;
const {
  Readable: IE,
  Duplex: iB,
  PassThrough: aB
} = lt, {
  InvalidArgumentError: wr,
  InvalidReturnValueError: cB,
  RequestAbortedError: Us
} = Re, fA = we, { AsyncResource: gB } = Vr, { addSignal: lB, removeSignal: EB } = Kr, uB = Me, zt = Symbol("resume");
class hB extends IE {
  constructor() {
    super({ autoDestroy: !0 }), this[zt] = null;
  }
  _read() {
    const { [zt]: A } = this;
    A && (this[zt] = null, A());
  }
  _destroy(A, t) {
    this._read(), t(A);
  }
}
class dB extends IE {
  constructor(A) {
    super({ autoDestroy: !0 }), this[zt] = A;
  }
  _read() {
    this[zt]();
  }
  _destroy(A, t) {
    !A && !this._readableState.endEmitted && (A = new Us()), t(A);
  }
}
class QB extends gB {
  constructor(A, t) {
    if (!A || typeof A != "object")
      throw new wr("invalid opts");
    if (typeof t != "function")
      throw new wr("invalid handler");
    const { signal: r, method: s, opaque: o, onInfo: n, responseHeaders: i } = A;
    if (r && typeof r.on != "function" && typeof r.addEventListener != "function")
      throw new wr("signal must be an EventEmitter or EventTarget");
    if (s === "CONNECT")
      throw new wr("invalid method");
    if (n && typeof n != "function")
      throw new wr("invalid onInfo callback");
    super("UNDICI_PIPELINE"), this.opaque = o || null, this.responseHeaders = i || null, this.handler = t, this.abort = null, this.context = null, this.onInfo = n || null, this.req = new hB().on("error", fA.nop), this.ret = new iB({
      readableObjectMode: A.objectMode,
      autoDestroy: !0,
      read: () => {
        const { body: a } = this;
        a && a.resume && a.resume();
      },
      write: (a, g, c) => {
        const { req: E } = this;
        E.push(a, g) || E._readableState.destroyed ? c() : E[zt] = c;
      },
      destroy: (a, g) => {
        const { body: c, req: E, res: l, ret: Q, abort: I } = this;
        !a && !Q._readableState.endEmitted && (a = new Us()), I && a && I(), fA.destroy(c, a), fA.destroy(E, a), fA.destroy(l, a), EB(this), g(a);
      }
    }).on("prefinish", () => {
      const { req: a } = this;
      a.push(null);
    }), this.res = null, lB(this, r);
  }
  onConnect(A, t) {
    const { ret: r, res: s } = this;
    if (uB(!s, "pipeline cannot be retried"), r.destroyed)
      throw new Us();
    this.abort = A, this.context = t;
  }
  onHeaders(A, t, r) {
    const { opaque: s, handler: o, context: n } = this;
    if (A < 200) {
      if (this.onInfo) {
        const a = this.responseHeaders === "raw" ? fA.parseRawHeaders(t) : fA.parseHeaders(t);
        this.onInfo({ statusCode: A, headers: a });
      }
      return;
    }
    this.res = new dB(r);
    let i;
    try {
      this.handler = null;
      const a = this.responseHeaders === "raw" ? fA.parseRawHeaders(t) : fA.parseHeaders(t);
      i = this.runInAsyncScope(o, null, {
        statusCode: A,
        headers: a,
        opaque: s,
        body: this.res,
        context: n
      });
    } catch (a) {
      throw this.res.on("error", fA.nop), a;
    }
    if (!i || typeof i.on != "function")
      throw new cB("expected Readable");
    i.on("data", (a) => {
      const { ret: g, body: c } = this;
      !g.push(a) && c.pause && c.pause();
    }).on("error", (a) => {
      const { ret: g } = this;
      fA.destroy(g, a);
    }).on("end", () => {
      const { ret: a } = this;
      a.push(null);
    }).on("close", () => {
      const { ret: a } = this;
      a._readableState.ended || fA.destroy(a, new Us());
    }), this.body = i;
  }
  onData(A) {
    const { res: t } = this;
    return t.push(A);
  }
  onComplete(A) {
    const { res: t } = this;
    t.push(null);
  }
  onError(A) {
    const { ret: t } = this;
    this.handler = null, fA.destroy(t, A);
  }
}
function CB(e, A) {
  try {
    const t = new QB(e, A);
    return this.dispatch({ ...e, body: t.req }, t), t.ret;
  } catch (t) {
    return new aB().destroy(t);
  }
}
var BB = CB;
const { InvalidArgumentError: zo, RequestAbortedError: IB, SocketError: pB } = Re, { AsyncResource: fB } = Vr, rc = we, { addSignal: mB, removeSignal: sc } = Kr, wB = Me;
class yB extends fB {
  constructor(A, t) {
    if (!A || typeof A != "object")
      throw new zo("invalid opts");
    if (typeof t != "function")
      throw new zo("invalid callback");
    const { signal: r, opaque: s, responseHeaders: o } = A;
    if (r && typeof r.on != "function" && typeof r.addEventListener != "function")
      throw new zo("signal must be an EventEmitter or EventTarget");
    super("UNDICI_UPGRADE"), this.responseHeaders = o || null, this.opaque = s || null, this.callback = t, this.abort = null, this.context = null, mB(this, r);
  }
  onConnect(A, t) {
    if (!this.callback)
      throw new IB();
    this.abort = A, this.context = null;
  }
  onHeaders() {
    throw new pB("bad upgrade", null);
  }
  onUpgrade(A, t, r) {
    const { callback: s, opaque: o, context: n } = this;
    wB.strictEqual(A, 101), sc(this), this.callback = null;
    const i = this.responseHeaders === "raw" ? rc.parseRawHeaders(t) : rc.parseHeaders(t);
    this.runInAsyncScope(s, null, null, {
      headers: i,
      socket: r,
      opaque: o,
      context: n
    });
  }
  onError(A) {
    const { callback: t, opaque: r } = this;
    sc(this), t && (this.callback = null, queueMicrotask(() => {
      this.runInAsyncScope(t, null, A, { opaque: r });
    }));
  }
}
function pE(e, A) {
  if (A === void 0)
    return new Promise((t, r) => {
      pE.call(this, e, (s, o) => s ? r(s) : t(o));
    });
  try {
    const t = new yB(e, A);
    this.dispatch({
      ...e,
      method: e.method || "GET",
      upgrade: e.protocol || "Websocket"
    }, t);
  } catch (t) {
    if (typeof A != "function")
      throw t;
    const r = e && e.opaque;
    queueMicrotask(() => A(t, { opaque: r }));
  }
}
var bB = pE;
const { AsyncResource: RB } = Vr, { InvalidArgumentError: Zo, RequestAbortedError: DB, SocketError: TB } = Re, oc = we, { addSignal: kB, removeSignal: nc } = Kr;
class FB extends RB {
  constructor(A, t) {
    if (!A || typeof A != "object")
      throw new Zo("invalid opts");
    if (typeof t != "function")
      throw new Zo("invalid callback");
    const { signal: r, opaque: s, responseHeaders: o } = A;
    if (r && typeof r.on != "function" && typeof r.addEventListener != "function")
      throw new Zo("signal must be an EventEmitter or EventTarget");
    super("UNDICI_CONNECT"), this.opaque = s || null, this.responseHeaders = o || null, this.callback = t, this.abort = null, kB(this, r);
  }
  onConnect(A, t) {
    if (!this.callback)
      throw new DB();
    this.abort = A, this.context = t;
  }
  onHeaders() {
    throw new TB("bad connect", null);
  }
  onUpgrade(A, t, r) {
    const { callback: s, opaque: o, context: n } = this;
    nc(this), this.callback = null;
    let i = t;
    i != null && (i = this.responseHeaders === "raw" ? oc.parseRawHeaders(t) : oc.parseHeaders(t)), this.runInAsyncScope(s, null, null, {
      statusCode: A,
      headers: i,
      socket: r,
      opaque: o,
      context: n
    });
  }
  onError(A) {
    const { callback: t, opaque: r } = this;
    nc(this), t && (this.callback = null, queueMicrotask(() => {
      this.runInAsyncScope(t, null, A, { opaque: r });
    }));
  }
}
function fE(e, A) {
  if (A === void 0)
    return new Promise((t, r) => {
      fE.call(this, e, (s, o) => s ? r(s) : t(o));
    });
  try {
    const t = new FB(e, A);
    this.dispatch({ ...e, method: "CONNECT" }, t);
  } catch (t) {
    if (typeof A != "function")
      throw t;
    const r = e && e.opaque;
    queueMicrotask(() => A(t, { opaque: r }));
  }
}
var SB = fE;
cr.request = zC;
cr.stream = nB;
cr.pipeline = BB;
cr.upgrade = bB;
cr.connect = SB;
const { UndiciError: UB } = Re;
let GB = class mE extends UB {
  constructor(A) {
    super(A), Error.captureStackTrace(this, mE), this.name = "MockNotMatchedError", this.message = A || "The request does not match any registered mock dispatches", this.code = "UND_MOCK_ERR_MOCK_NOT_MATCHED";
  }
};
var wE = {
  MockNotMatchedError: GB
}, zr = {
  kAgent: Symbol("agent"),
  kOptions: Symbol("options"),
  kFactory: Symbol("factory"),
  kDispatches: Symbol("dispatches"),
  kDispatchKey: Symbol("dispatch key"),
  kDefaultHeaders: Symbol("default headers"),
  kDefaultTrailers: Symbol("default trailers"),
  kContentLength: Symbol("content length"),
  kMockAgent: Symbol("mock agent"),
  kMockAgentSet: Symbol("mock agent set"),
  kMockAgentGet: Symbol("mock agent get"),
  kMockDispatch: Symbol("mock dispatch"),
  kClose: Symbol("close"),
  kOriginalClose: Symbol("original agent close"),
  kOrigin: Symbol("origin"),
  kIsMockActive: Symbol("is mock active"),
  kNetConnect: Symbol("net connect"),
  kGetNetConnect: Symbol("get net connect"),
  kConnected: Symbol("connected")
};
const { MockNotMatchedError: bt } = wE, {
  kDispatches: Qs,
  kMockAgent: _B,
  kOriginalDispatch: NB,
  kOrigin: vB,
  kGetNetConnect: LB
} = zr, { buildURL: MB, nop: OB } = we, { STATUS_CODES: PB } = or, {
  types: {
    isPromise: YB
  }
} = LA;
function qA(e, A) {
  return typeof e == "string" ? e === A : e instanceof RegExp ? e.test(A) : typeof e == "function" ? e(A) === !0 : !1;
}
function yE(e) {
  return Object.fromEntries(
    Object.entries(e).map(([A, t]) => [A.toLocaleLowerCase(), t])
  );
}
function xB(e, A) {
  if (Array.isArray(e)) {
    for (let t = 0; t < e.length; t += 2)
      if (e[t].toLocaleLowerCase() === A.toLocaleLowerCase())
        return e[t + 1];
    return;
  } else return typeof e.get == "function" ? e.get(A) : yE(e)[A.toLocaleLowerCase()];
}
function bE(e) {
  const A = e.slice(), t = [];
  for (let r = 0; r < A.length; r += 2)
    t.push([A[r], A[r + 1]]);
  return Object.fromEntries(t);
}
function RE(e, A) {
  if (typeof e.headers == "function")
    return Array.isArray(A) && (A = bE(A)), e.headers(A ? yE(A) : {});
  if (typeof e.headers > "u")
    return !0;
  if (typeof A != "object" || typeof e.headers != "object")
    return !1;
  for (const [t, r] of Object.entries(e.headers)) {
    const s = xB(A, t);
    if (!qA(r, s))
      return !1;
  }
  return !0;
}
function ic(e) {
  if (typeof e != "string")
    return e;
  const A = e.split("?");
  if (A.length !== 2)
    return e;
  const t = new URLSearchParams(A.pop());
  return t.sort(), [...A, t.toString()].join("?");
}
function JB(e, { path: A, method: t, body: r, headers: s }) {
  const o = qA(e.path, A), n = qA(e.method, t), i = typeof e.body < "u" ? qA(e.body, r) : !0, a = RE(e, s);
  return o && n && i && a;
}
function DE(e) {
  return Buffer.isBuffer(e) ? e : typeof e == "object" ? JSON.stringify(e) : e.toString();
}
function HB(e, A) {
  const t = A.query ? MB(A.path, A.query) : A.path, r = typeof t == "string" ? ic(t) : t;
  let s = e.filter(({ consumed: o }) => !o).filter(({ path: o }) => qA(ic(o), r));
  if (s.length === 0)
    throw new bt(`Mock dispatch not matched for path '${r}'`);
  if (s = s.filter(({ method: o }) => qA(o, A.method)), s.length === 0)
    throw new bt(`Mock dispatch not matched for method '${A.method}'`);
  if (s = s.filter(({ body: o }) => typeof o < "u" ? qA(o, A.body) : !0), s.length === 0)
    throw new bt(`Mock dispatch not matched for body '${A.body}'`);
  if (s = s.filter((o) => RE(o, A.headers)), s.length === 0)
    throw new bt(`Mock dispatch not matched for headers '${typeof A.headers == "object" ? JSON.stringify(A.headers) : A.headers}'`);
  return s[0];
}
function VB(e, A, t) {
  const r = { timesInvoked: 0, times: 1, persist: !1, consumed: !1 }, s = typeof t == "function" ? { callback: t } : { ...t }, o = { ...r, ...A, pending: !0, data: { error: null, ...s } };
  return e.push(o), o;
}
function ac(e, A) {
  const t = e.findIndex((r) => r.consumed ? JB(r, A) : !1);
  t !== -1 && e.splice(t, 1);
}
function TE(e) {
  const { path: A, method: t, body: r, headers: s, query: o } = e;
  return {
    path: A,
    method: t,
    body: r,
    headers: s,
    query: o
  };
}
function cc(e) {
  return Object.entries(e).reduce((A, [t, r]) => [
    ...A,
    Buffer.from(`${t}`),
    Array.isArray(r) ? r.map((s) => Buffer.from(`${s}`)) : Buffer.from(`${r}`)
  ], []);
}
function qB(e) {
  return PB[e] || "unknown";
}
function WB(e, A) {
  const t = TE(e), r = HB(this[Qs], t);
  r.timesInvoked++, r.data.callback && (r.data = { ...r.data, ...r.data.callback(e) });
  const { data: { statusCode: s, data: o, headers: n, trailers: i, error: a }, delay: g, persist: c } = r, { timesInvoked: E, times: l } = r;
  if (r.consumed = !c && E >= l, r.pending = E < l, a !== null)
    return ac(this[Qs], t), A.onError(a), !0;
  typeof g == "number" && g > 0 ? setTimeout(() => {
    Q(this[Qs]);
  }, g) : Q(this[Qs]);
  function Q(d, h = o) {
    const C = Array.isArray(e.headers) ? bE(e.headers) : e.headers, u = typeof h == "function" ? h({ ...e, headers: C }) : h;
    if (YB(u)) {
      u.then((y) => Q(d, y));
      return;
    }
    const B = DE(u), m = cc(n), f = cc(i);
    A.abort = OB, A.onHeaders(s, m, I, qB(s)), A.onData(Buffer.from(B)), A.onComplete(f), ac(d, t);
  }
  function I() {
  }
  return !0;
}
function jB() {
  const e = this[_B], A = this[vB], t = this[NB];
  return function(s, o) {
    if (e.isMockActive)
      try {
        WB.call(this, s, o);
      } catch (n) {
        if (n instanceof bt) {
          const i = e[LB]();
          if (i === !1)
            throw new bt(`${n.message}: subsequent request to origin ${A} was not allowed (net.connect disabled)`);
          if ($B(i, A))
            t.call(this, s, o);
          else
            throw new bt(`${n.message}: subsequent request to origin ${A} was not allowed (net.connect is not enabled for this origin)`);
        } else
          throw n;
      }
    else
      t.call(this, s, o);
  };
}
function $B(e, A) {
  const t = new URL(A);
  return e === !0 ? !0 : !!(Array.isArray(e) && e.some((r) => qA(r, t.host)));
}
function KB(e) {
  if (e) {
    const { agent: A, ...t } = e;
    return t;
  }
}
var Ks = {
  getResponseData: DE,
  addMockDispatch: VB,
  buildKey: TE,
  matchValue: qA,
  buildMockDispatch: jB,
  buildMockOptions: KB
}, zs = {};
const { getResponseData: zB, buildKey: ZB, addMockDispatch: Xo } = Ks, {
  kDispatches: Cs,
  kDispatchKey: Bs,
  kDefaultHeaders: en,
  kDefaultTrailers: An,
  kContentLength: tn,
  kMockDispatch: Is
} = zr, { InvalidArgumentError: DA } = Re, { buildURL: XB } = we;
class Gs {
  constructor(A) {
    this[Is] = A;
  }
  /**
   * Delay a reply by a set amount in ms.
   */
  delay(A) {
    if (typeof A != "number" || !Number.isInteger(A) || A <= 0)
      throw new DA("waitInMs must be a valid integer > 0");
    return this[Is].delay = A, this;
  }
  /**
   * For a defined reply, never mark as consumed.
   */
  persist() {
    return this[Is].persist = !0, this;
  }
  /**
   * Allow one to define a reply for a set amount of matching requests.
   */
  times(A) {
    if (typeof A != "number" || !Number.isInteger(A) || A <= 0)
      throw new DA("repeatTimes must be a valid integer > 0");
    return this[Is].times = A, this;
  }
}
let eI = class {
  constructor(A, t) {
    if (typeof A != "object")
      throw new DA("opts must be an object");
    if (typeof A.path > "u")
      throw new DA("opts.path must be defined");
    if (typeof A.method > "u" && (A.method = "GET"), typeof A.path == "string")
      if (A.query)
        A.path = XB(A.path, A.query);
      else {
        const r = new URL(A.path, "data://");
        A.path = r.pathname + r.search;
      }
    typeof A.method == "string" && (A.method = A.method.toUpperCase()), this[Bs] = ZB(A), this[Cs] = t, this[en] = {}, this[An] = {}, this[tn] = !1;
  }
  createMockScopeDispatchData(A, t, r = {}) {
    const s = zB(t), o = this[tn] ? { "content-length": s.length } : {}, n = { ...this[en], ...o, ...r.headers }, i = { ...this[An], ...r.trailers };
    return { statusCode: A, data: t, headers: n, trailers: i };
  }
  validateReplyParameters(A, t, r) {
    if (typeof A > "u")
      throw new DA("statusCode must be defined");
    if (typeof t > "u")
      throw new DA("data must be defined");
    if (typeof r != "object")
      throw new DA("responseOptions must be an object");
  }
  /**
   * Mock an undici request with a defined reply.
   */
  reply(A) {
    if (typeof A == "function") {
      const i = (g) => {
        const c = A(g);
        if (typeof c != "object")
          throw new DA("reply options callback must return an object");
        const { statusCode: E, data: l = "", responseOptions: Q = {} } = c;
        return this.validateReplyParameters(E, l, Q), {
          ...this.createMockScopeDispatchData(E, l, Q)
        };
      }, a = Xo(this[Cs], this[Bs], i);
      return new Gs(a);
    }
    const [t, r = "", s = {}] = [...arguments];
    this.validateReplyParameters(t, r, s);
    const o = this.createMockScopeDispatchData(t, r, s), n = Xo(this[Cs], this[Bs], o);
    return new Gs(n);
  }
  /**
   * Mock an undici request with a defined error.
   */
  replyWithError(A) {
    if (typeof A > "u")
      throw new DA("error must be defined");
    const t = Xo(this[Cs], this[Bs], { error: A });
    return new Gs(t);
  }
  /**
   * Set default reply headers on the interceptor for subsequent replies
   */
  defaultReplyHeaders(A) {
    if (typeof A > "u")
      throw new DA("headers must be defined");
    return this[en] = A, this;
  }
  /**
   * Set default reply trailers on the interceptor for subsequent replies
   */
  defaultReplyTrailers(A) {
    if (typeof A > "u")
      throw new DA("trailers must be defined");
    return this[An] = A, this;
  }
  /**
   * Set reply content length header for replies on the interceptor
   */
  replyContentLength() {
    return this[tn] = !0, this;
  }
};
zs.MockInterceptor = eI;
zs.MockScope = Gs;
const { promisify: AI } = LA, tI = js, { buildMockDispatch: rI } = Ks, {
  kDispatches: gc,
  kMockAgent: lc,
  kClose: Ec,
  kOriginalClose: uc,
  kOrigin: hc,
  kOriginalDispatch: sI,
  kConnected: rn
} = zr, { MockInterceptor: oI } = zs, dc = Se, { InvalidArgumentError: nI } = Re;
let iI = class extends tI {
  constructor(A, t) {
    if (super(A, t), !t || !t.agent || typeof t.agent.dispatch != "function")
      throw new nI("Argument opts.agent must implement Agent");
    this[lc] = t.agent, this[hc] = A, this[gc] = [], this[rn] = 1, this[sI] = this.dispatch, this[uc] = this.close.bind(this), this.dispatch = rI.call(this), this.close = this[Ec];
  }
  get [dc.kConnected]() {
    return this[rn];
  }
  /**
   * Sets up the base interceptor for mocking replies from undici.
   */
  intercept(A) {
    return new oI(A, this[gc]);
  }
  async [Ec]() {
    await AI(this[uc])(), this[rn] = 0, this[lc][dc.kClients].delete(this[hc]);
  }
};
var kE = iI;
const { promisify: aI } = LA, cI = $r, { buildMockDispatch: gI } = Ks, {
  kDispatches: Qc,
  kMockAgent: Cc,
  kClose: Bc,
  kOriginalClose: Ic,
  kOrigin: pc,
  kOriginalDispatch: lI,
  kConnected: sn
} = zr, { MockInterceptor: EI } = zs, fc = Se, { InvalidArgumentError: uI } = Re;
let hI = class extends cI {
  constructor(A, t) {
    if (super(A, t), !t || !t.agent || typeof t.agent.dispatch != "function")
      throw new uI("Argument opts.agent must implement Agent");
    this[Cc] = t.agent, this[pc] = A, this[Qc] = [], this[sn] = 1, this[lI] = this.dispatch, this[Ic] = this.close.bind(this), this.dispatch = gI.call(this), this.close = this[Bc];
  }
  get [fc.kConnected]() {
    return this[sn];
  }
  /**
   * Sets up the base interceptor for mocking replies from undici.
   */
  intercept(A) {
    return new EI(A, this[Qc]);
  }
  async [Bc]() {
    await aI(this[Ic])(), this[sn] = 0, this[Cc][fc.kClients].delete(this[pc]);
  }
};
var FE = hI;
const dI = {
  pronoun: "it",
  is: "is",
  was: "was",
  this: "this"
}, QI = {
  pronoun: "they",
  is: "are",
  was: "were",
  this: "these"
};
var CI = class {
  constructor(A, t) {
    this.singular = A, this.plural = t;
  }
  pluralize(A) {
    const t = A === 1, r = t ? dI : QI, s = t ? this.singular : this.plural;
    return { ...r, count: A, noun: s };
  }
};
const { Transform: BI } = lt, { Console: II } = Hu;
var pI = class {
  constructor({ disableColors: A } = {}) {
    this.transform = new BI({
      transform(t, r, s) {
        s(null, t);
      }
    }), this.logger = new II({
      stdout: this.transform,
      inspectOptions: {
        colors: !A && !process.env.CI
      }
    });
  }
  format(A) {
    const t = A.map(
      ({ method: r, path: s, data: { statusCode: o }, persist: n, times: i, timesInvoked: a, origin: g }) => ({
        Method: r,
        Origin: g,
        Path: s,
        "Status code": o,
        Persistent: n ? "✅" : "❌",
        Invocations: a,
        Remaining: n ? 1 / 0 : i - a
      })
    );
    return this.logger.table(t), this.transform.read().toString();
  }
};
const { kClients: It } = Se, fI = $s, {
  kAgent: on,
  kMockAgentSet: ps,
  kMockAgentGet: mc,
  kDispatches: nn,
  kIsMockActive: fs,
  kNetConnect: pt,
  kGetNetConnect: mI,
  kOptions: ms,
  kFactory: ws
} = zr, wI = kE, yI = FE, { matchValue: bI, buildMockOptions: RI } = Ks, { InvalidArgumentError: wc, UndiciError: DI } = Re, TI = mi, kI = CI, FI = pI;
class SI {
  constructor(A) {
    this.value = A;
  }
  deref() {
    return this.value;
  }
}
let UI = class extends TI {
  constructor(A) {
    if (super(A), this[pt] = !0, this[fs] = !0, A && A.agent && typeof A.agent.dispatch != "function")
      throw new wc("Argument opts.agent must implement Agent");
    const t = A && A.agent ? A.agent : new fI(A);
    this[on] = t, this[It] = t[It], this[ms] = RI(A);
  }
  get(A) {
    let t = this[mc](A);
    return t || (t = this[ws](A), this[ps](A, t)), t;
  }
  dispatch(A, t) {
    return this.get(A.origin), this[on].dispatch(A, t);
  }
  async close() {
    await this[on].close(), this[It].clear();
  }
  deactivate() {
    this[fs] = !1;
  }
  activate() {
    this[fs] = !0;
  }
  enableNetConnect(A) {
    if (typeof A == "string" || typeof A == "function" || A instanceof RegExp)
      Array.isArray(this[pt]) ? this[pt].push(A) : this[pt] = [A];
    else if (typeof A > "u")
      this[pt] = !0;
    else
      throw new wc("Unsupported matcher. Must be one of String|Function|RegExp.");
  }
  disableNetConnect() {
    this[pt] = !1;
  }
  // This is required to bypass issues caused by using global symbols - see:
  // https://github.com/nodejs/undici/issues/1447
  get isMockActive() {
    return this[fs];
  }
  [ps](A, t) {
    this[It].set(A, new SI(t));
  }
  [ws](A) {
    const t = Object.assign({ agent: this }, this[ms]);
    return this[ms] && this[ms].connections === 1 ? new wI(A, t) : new yI(A, t);
  }
  [mc](A) {
    const t = this[It].get(A);
    if (t)
      return t.deref();
    if (typeof A != "string") {
      const r = this[ws]("http://localhost:9999");
      return this[ps](A, r), r;
    }
    for (const [r, s] of Array.from(this[It])) {
      const o = s.deref();
      if (o && typeof r != "string" && bI(r, A)) {
        const n = this[ws](A);
        return this[ps](A, n), n[nn] = o[nn], n;
      }
    }
  }
  [mI]() {
    return this[pt];
  }
  pendingInterceptors() {
    const A = this[It];
    return Array.from(A.entries()).flatMap(([t, r]) => r.deref()[nn].map((s) => ({ ...s, origin: t }))).filter(({ pending: t }) => t);
  }
  assertNoPendingInterceptors({ pendingInterceptorsFormatter: A = new FI() } = {}) {
    const t = this.pendingInterceptors();
    if (t.length === 0)
      return;
    const r = new kI("interceptor", "interceptors").pluralize(t.length);
    throw new DI(`
${r.count} ${r.noun} ${r.is} pending:

${A.format(t)}
`.trim());
  }
};
var GI = UI;
const { kProxy: _I, kClose: NI, kDestroy: vI, kInterceptors: LI } = Se, { URL: yc } = Vu, bc = $s, MI = $r, OI = Vs, { InvalidArgumentError: vr, RequestAbortedError: PI } = Re, Rc = qs, yr = Symbol("proxy agent"), ys = Symbol("proxy client"), br = Symbol("proxy headers"), an = Symbol("request tls settings"), YI = Symbol("proxy tls settings"), Dc = Symbol("connect endpoint function");
function xI(e) {
  return e === "https:" ? 443 : 80;
}
function JI(e) {
  if (typeof e == "string" && (e = { uri: e }), !e || !e.uri)
    throw new vr("Proxy opts.uri is mandatory");
  return {
    uri: e.uri,
    protocol: e.protocol || "https"
  };
}
function HI(e, A) {
  return new MI(e, A);
}
let VI = class extends OI {
  constructor(A) {
    if (super(A), this[_I] = JI(A), this[yr] = new bc(A), this[LI] = A.interceptors && A.interceptors.ProxyAgent && Array.isArray(A.interceptors.ProxyAgent) ? A.interceptors.ProxyAgent : [], typeof A == "string" && (A = { uri: A }), !A || !A.uri)
      throw new vr("Proxy opts.uri is mandatory");
    const { clientFactory: t = HI } = A;
    if (typeof t != "function")
      throw new vr("Proxy opts.clientFactory must be a function.");
    this[an] = A.requestTls, this[YI] = A.proxyTls, this[br] = A.headers || {};
    const r = new yc(A.uri), { origin: s, port: o, host: n, username: i, password: a } = r;
    if (A.auth && A.token)
      throw new vr("opts.auth cannot be used in combination with opts.token");
    A.auth ? this[br]["proxy-authorization"] = `Basic ${A.auth}` : A.token ? this[br]["proxy-authorization"] = A.token : i && a && (this[br]["proxy-authorization"] = `Basic ${Buffer.from(`${decodeURIComponent(i)}:${decodeURIComponent(a)}`).toString("base64")}`);
    const g = Rc({ ...A.proxyTls });
    this[Dc] = Rc({ ...A.requestTls }), this[ys] = t(r, { connect: g }), this[yr] = new bc({
      ...A,
      connect: async (c, E) => {
        let l = c.host;
        c.port || (l += `:${xI(c.protocol)}`);
        try {
          const { socket: Q, statusCode: I } = await this[ys].connect({
            origin: s,
            port: o,
            path: l,
            signal: c.signal,
            headers: {
              ...this[br],
              host: n
            }
          });
          if (I !== 200 && (Q.on("error", () => {
          }).destroy(), E(new PI(`Proxy response (${I}) !== 200 when HTTP Tunneling`))), c.protocol !== "https:") {
            E(null, Q);
            return;
          }
          let d;
          this[an] ? d = this[an].servername : d = c.servername, this[Dc]({ ...c, servername: d, httpSocket: Q }, E);
        } catch (Q) {
          E(Q);
        }
      }
    });
  }
  dispatch(A, t) {
    const { host: r } = new yc(A.origin), s = qI(A.headers);
    return WI(s), this[yr].dispatch(
      {
        ...A,
        headers: {
          ...s,
          host: r
        }
      },
      t
    );
  }
  async [NI]() {
    await this[yr].close(), await this[ys].close();
  }
  async [vI]() {
    await this[yr].destroy(), await this[ys].destroy();
  }
};
function qI(e) {
  if (Array.isArray(e)) {
    const A = {};
    for (let t = 0; t < e.length; t += 2)
      A[e[t]] = e[t + 1];
    return A;
  }
  return e;
}
function WI(e) {
  if (e && Object.keys(e).find((t) => t.toLowerCase() === "proxy-authorization"))
    throw new vr("Proxy-Authorization should be sent in ProxyAgent constructor");
}
var jI = VI;
const ft = Me, { kRetryHandlerDefaultRetry: Tc } = Se, { RequestRetryError: bs } = Re, { isDisturbed: kc, parseHeaders: $I, parseRangeHeader: Fc } = we;
function KI(e) {
  const A = Date.now();
  return new Date(e).getTime() - A;
}
let zI = class SE {
  constructor(A, t) {
    const { retryOptions: r, ...s } = A, {
      // Retry scoped
      retry: o,
      maxRetries: n,
      maxTimeout: i,
      minTimeout: a,
      timeoutFactor: g,
      // Response scoped
      methods: c,
      errorCodes: E,
      retryAfter: l,
      statusCodes: Q
    } = r ?? {};
    this.dispatch = t.dispatch, this.handler = t.handler, this.opts = s, this.abort = null, this.aborted = !1, this.retryOpts = {
      retry: o ?? SE[Tc],
      retryAfter: l ?? !0,
      maxTimeout: i ?? 30 * 1e3,
      // 30s,
      timeout: a ?? 500,
      // .5s
      timeoutFactor: g ?? 2,
      maxRetries: n ?? 5,
      // What errors we should retry
      methods: c ?? ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"],
      // Indicates which errors to retry
      statusCodes: Q ?? [500, 502, 503, 504, 429],
      // List of errors to retry
      errorCodes: E ?? [
        "ECONNRESET",
        "ECONNREFUSED",
        "ENOTFOUND",
        "ENETDOWN",
        "ENETUNREACH",
        "EHOSTDOWN",
        "EHOSTUNREACH",
        "EPIPE"
      ]
    }, this.retryCount = 0, this.start = 0, this.end = null, this.etag = null, this.resume = null, this.handler.onConnect((I) => {
      this.aborted = !0, this.abort ? this.abort(I) : this.reason = I;
    });
  }
  onRequestSent() {
    this.handler.onRequestSent && this.handler.onRequestSent();
  }
  onUpgrade(A, t, r) {
    this.handler.onUpgrade && this.handler.onUpgrade(A, t, r);
  }
  onConnect(A) {
    this.aborted ? A(this.reason) : this.abort = A;
  }
  onBodySent(A) {
    if (this.handler.onBodySent) return this.handler.onBodySent(A);
  }
  static [Tc](A, { state: t, opts: r }, s) {
    const { statusCode: o, code: n, headers: i } = A, { method: a, retryOptions: g } = r, {
      maxRetries: c,
      timeout: E,
      maxTimeout: l,
      timeoutFactor: Q,
      statusCodes: I,
      errorCodes: d,
      methods: h
    } = g;
    let { counter: C, currentTimeout: u } = t;
    if (u = u != null && u > 0 ? u : E, n && n !== "UND_ERR_REQ_RETRY" && n !== "UND_ERR_SOCKET" && !d.includes(n)) {
      s(A);
      return;
    }
    if (Array.isArray(h) && !h.includes(a)) {
      s(A);
      return;
    }
    if (o != null && Array.isArray(I) && !I.includes(o)) {
      s(A);
      return;
    }
    if (C > c) {
      s(A);
      return;
    }
    let B = i != null && i["retry-after"];
    B && (B = Number(B), B = isNaN(B) ? KI(B) : B * 1e3);
    const m = B > 0 ? Math.min(B, l) : Math.min(u * Q ** C, l);
    t.currentTimeout = m, setTimeout(() => s(null), m);
  }
  onHeaders(A, t, r, s) {
    const o = $I(t);
    if (this.retryCount += 1, A >= 300)
      return this.abort(
        new bs("Request failed", A, {
          headers: o,
          count: this.retryCount
        })
      ), !1;
    if (this.resume != null) {
      if (this.resume = null, A !== 206)
        return !0;
      const i = Fc(o["content-range"]);
      if (!i)
        return this.abort(
          new bs("Content-Range mismatch", A, {
            headers: o,
            count: this.retryCount
          })
        ), !1;
      if (this.etag != null && this.etag !== o.etag)
        return this.abort(
          new bs("ETag mismatch", A, {
            headers: o,
            count: this.retryCount
          })
        ), !1;
      const { start: a, size: g, end: c = g } = i;
      return ft(this.start === a, "content-range mismatch"), ft(this.end == null || this.end === c, "content-range mismatch"), this.resume = r, !0;
    }
    if (this.end == null) {
      if (A === 206) {
        const i = Fc(o["content-range"]);
        if (i == null)
          return this.handler.onHeaders(
            A,
            t,
            r,
            s
          );
        const { start: a, size: g, end: c = g } = i;
        ft(
          a != null && Number.isFinite(a) && this.start !== a,
          "content-range mismatch"
        ), ft(Number.isFinite(a)), ft(
          c != null && Number.isFinite(c) && this.end !== c,
          "invalid content-length"
        ), this.start = a, this.end = c;
      }
      if (this.end == null) {
        const i = o["content-length"];
        this.end = i != null ? Number(i) : null;
      }
      return ft(Number.isFinite(this.start)), ft(
        this.end == null || Number.isFinite(this.end),
        "invalid content-length"
      ), this.resume = r, this.etag = o.etag != null ? o.etag : null, this.handler.onHeaders(
        A,
        t,
        r,
        s
      );
    }
    const n = new bs("Request failed", A, {
      headers: o,
      count: this.retryCount
    });
    return this.abort(n), !1;
  }
  onData(A) {
    return this.start += A.length, this.handler.onData(A);
  }
  onComplete(A) {
    return this.retryCount = 0, this.handler.onComplete(A);
  }
  onError(A) {
    if (this.aborted || kc(this.opts.body))
      return this.handler.onError(A);
    this.retryOpts.retry(
      A,
      {
        state: { counter: this.retryCount++, currentTimeout: this.retryAfter },
        opts: { retryOptions: this.retryOpts, ...this.opts }
      },
      t.bind(this)
    );
    function t(r) {
      if (r != null || this.aborted || kc(this.opts.body))
        return this.handler.onError(r);
      this.start !== 0 && (this.opts = {
        ...this.opts,
        headers: {
          ...this.opts.headers,
          range: `bytes=${this.start}-${this.end ?? ""}`
        }
      });
      try {
        this.dispatch(this.opts, this);
      } catch (s) {
        this.handler.onError(s);
      }
    }
  }
};
var ZI = zI;
const UE = Symbol.for("undici.globalDispatcher.1"), { InvalidArgumentError: XI } = Re, ep = $s;
_E() === void 0 && GE(new ep());
function GE(e) {
  if (!e || typeof e.dispatch != "function")
    throw new XI("Argument agent must implement Agent");
  Object.defineProperty(globalThis, UE, {
    value: e,
    writable: !0,
    enumerable: !1,
    configurable: !1
  });
}
function _E() {
  return globalThis[UE];
}
var Zr = {
  setGlobalDispatcher: GE,
  getGlobalDispatcher: _E
}, Ap = class {
  constructor(A) {
    this.handler = A;
  }
  onConnect(...A) {
    return this.handler.onConnect(...A);
  }
  onError(...A) {
    return this.handler.onError(...A);
  }
  onUpgrade(...A) {
    return this.handler.onUpgrade(...A);
  }
  onHeaders(...A) {
    return this.handler.onHeaders(...A);
  }
  onData(...A) {
    return this.handler.onData(...A);
  }
  onComplete(...A) {
    return this.handler.onComplete(...A);
  }
  onBodySent(...A) {
    return this.handler.onBodySent(...A);
  }
}, cn, Sc;
function gr() {
  if (Sc) return cn;
  Sc = 1;
  const { kHeadersList: e, kConstruct: A } = Se, { kGuard: t } = Et(), { kEnumerableProperty: r } = we, {
    makeIterator: s,
    isValidHeaderName: o,
    isValidHeaderValue: n
  } = TA(), { webidl: i } = hA(), a = Me, g = Symbol("headers map"), c = Symbol("headers map sorted");
  function E(C) {
    return C === 10 || C === 13 || C === 9 || C === 32;
  }
  function l(C) {
    let u = 0, B = C.length;
    for (; B > u && E(C.charCodeAt(B - 1)); ) --B;
    for (; B > u && E(C.charCodeAt(u)); ) ++u;
    return u === 0 && B === C.length ? C : C.substring(u, B);
  }
  function Q(C, u) {
    if (Array.isArray(u))
      for (let B = 0; B < u.length; ++B) {
        const m = u[B];
        if (m.length !== 2)
          throw i.errors.exception({
            header: "Headers constructor",
            message: `expected name/value pair to be length 2, found ${m.length}.`
          });
        I(C, m[0], m[1]);
      }
    else if (typeof u == "object" && u !== null) {
      const B = Object.keys(u);
      for (let m = 0; m < B.length; ++m)
        I(C, B[m], u[B[m]]);
    } else
      throw i.errors.conversionFailed({
        prefix: "Headers constructor",
        argument: "Argument 1",
        types: ["sequence<sequence<ByteString>>", "record<ByteString, ByteString>"]
      });
  }
  function I(C, u, B) {
    if (B = l(B), o(u)) {
      if (!n(B))
        throw i.errors.invalidArgument({
          prefix: "Headers.append",
          value: B,
          type: "header value"
        });
    } else throw i.errors.invalidArgument({
      prefix: "Headers.append",
      value: u,
      type: "header name"
    });
    if (C[t] === "immutable")
      throw new TypeError("immutable");
    return C[t], C[e].append(u, B);
  }
  class d {
    /** @type {[string, string][]|null} */
    cookies = null;
    constructor(u) {
      u instanceof d ? (this[g] = new Map(u[g]), this[c] = u[c], this.cookies = u.cookies === null ? null : [...u.cookies]) : (this[g] = new Map(u), this[c] = null);
    }
    // https://fetch.spec.whatwg.org/#header-list-contains
    contains(u) {
      return u = u.toLowerCase(), this[g].has(u);
    }
    clear() {
      this[g].clear(), this[c] = null, this.cookies = null;
    }
    // https://fetch.spec.whatwg.org/#concept-header-list-append
    append(u, B) {
      this[c] = null;
      const m = u.toLowerCase(), f = this[g].get(m);
      if (f) {
        const y = m === "cookie" ? "; " : ", ";
        this[g].set(m, {
          name: f.name,
          value: `${f.value}${y}${B}`
        });
      } else
        this[g].set(m, { name: u, value: B });
      m === "set-cookie" && (this.cookies ??= [], this.cookies.push(B));
    }
    // https://fetch.spec.whatwg.org/#concept-header-list-set
    set(u, B) {
      this[c] = null;
      const m = u.toLowerCase();
      m === "set-cookie" && (this.cookies = [B]), this[g].set(m, { name: u, value: B });
    }
    // https://fetch.spec.whatwg.org/#concept-header-list-delete
    delete(u) {
      this[c] = null, u = u.toLowerCase(), u === "set-cookie" && (this.cookies = null), this[g].delete(u);
    }
    // https://fetch.spec.whatwg.org/#concept-header-list-get
    get(u) {
      const B = this[g].get(u.toLowerCase());
      return B === void 0 ? null : B.value;
    }
    *[Symbol.iterator]() {
      for (const [u, { value: B }] of this[g])
        yield [u, B];
    }
    get entries() {
      const u = {};
      if (this[g].size)
        for (const { name: B, value: m } of this[g].values())
          u[B] = m;
      return u;
    }
  }
  class h {
    constructor(u = void 0) {
      u !== A && (this[e] = new d(), this[t] = "none", u !== void 0 && (u = i.converters.HeadersInit(u), Q(this, u)));
    }
    // https://fetch.spec.whatwg.org/#dom-headers-append
    append(u, B) {
      return i.brandCheck(this, h), i.argumentLengthCheck(arguments, 2, { header: "Headers.append" }), u = i.converters.ByteString(u), B = i.converters.ByteString(B), I(this, u, B);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-delete
    delete(u) {
      if (i.brandCheck(this, h), i.argumentLengthCheck(arguments, 1, { header: "Headers.delete" }), u = i.converters.ByteString(u), !o(u))
        throw i.errors.invalidArgument({
          prefix: "Headers.delete",
          value: u,
          type: "header name"
        });
      if (this[t] === "immutable")
        throw new TypeError("immutable");
      this[t], this[e].contains(u) && this[e].delete(u);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-get
    get(u) {
      if (i.brandCheck(this, h), i.argumentLengthCheck(arguments, 1, { header: "Headers.get" }), u = i.converters.ByteString(u), !o(u))
        throw i.errors.invalidArgument({
          prefix: "Headers.get",
          value: u,
          type: "header name"
        });
      return this[e].get(u);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-has
    has(u) {
      if (i.brandCheck(this, h), i.argumentLengthCheck(arguments, 1, { header: "Headers.has" }), u = i.converters.ByteString(u), !o(u))
        throw i.errors.invalidArgument({
          prefix: "Headers.has",
          value: u,
          type: "header name"
        });
      return this[e].contains(u);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-set
    set(u, B) {
      if (i.brandCheck(this, h), i.argumentLengthCheck(arguments, 2, { header: "Headers.set" }), u = i.converters.ByteString(u), B = i.converters.ByteString(B), B = l(B), o(u)) {
        if (!n(B))
          throw i.errors.invalidArgument({
            prefix: "Headers.set",
            value: B,
            type: "header value"
          });
      } else throw i.errors.invalidArgument({
        prefix: "Headers.set",
        value: u,
        type: "header name"
      });
      if (this[t] === "immutable")
        throw new TypeError("immutable");
      this[t], this[e].set(u, B);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-getsetcookie
    getSetCookie() {
      i.brandCheck(this, h);
      const u = this[e].cookies;
      return u ? [...u] : [];
    }
    // https://fetch.spec.whatwg.org/#concept-header-list-sort-and-combine
    get [c]() {
      if (this[e][c])
        return this[e][c];
      const u = [], B = [...this[e]].sort((f, y) => f[0] < y[0] ? -1 : 1), m = this[e].cookies;
      for (let f = 0; f < B.length; ++f) {
        const [y, b] = B[f];
        if (y === "set-cookie")
          for (let w = 0; w < m.length; ++w)
            u.push([y, m[w]]);
        else
          a(b !== null), u.push([y, b]);
      }
      return this[e][c] = u, u;
    }
    keys() {
      if (i.brandCheck(this, h), this[t] === "immutable") {
        const u = this[c];
        return s(
          () => u,
          "Headers",
          "key"
        );
      }
      return s(
        () => [...this[c].values()],
        "Headers",
        "key"
      );
    }
    values() {
      if (i.brandCheck(this, h), this[t] === "immutable") {
        const u = this[c];
        return s(
          () => u,
          "Headers",
          "value"
        );
      }
      return s(
        () => [...this[c].values()],
        "Headers",
        "value"
      );
    }
    entries() {
      if (i.brandCheck(this, h), this[t] === "immutable") {
        const u = this[c];
        return s(
          () => u,
          "Headers",
          "key+value"
        );
      }
      return s(
        () => [...this[c].values()],
        "Headers",
        "key+value"
      );
    }
    /**
     * @param {(value: string, key: string, self: Headers) => void} callbackFn
     * @param {unknown} thisArg
     */
    forEach(u, B = globalThis) {
      if (i.brandCheck(this, h), i.argumentLengthCheck(arguments, 1, { header: "Headers.forEach" }), typeof u != "function")
        throw new TypeError(
          "Failed to execute 'forEach' on 'Headers': parameter 1 is not of type 'Function'."
        );
      for (const [m, f] of this)
        u.apply(B, [f, m, this]);
    }
    [Symbol.for("nodejs.util.inspect.custom")]() {
      return i.brandCheck(this, h), this[e];
    }
  }
  return h.prototype[Symbol.iterator] = h.prototype.entries, Object.defineProperties(h.prototype, {
    append: r,
    delete: r,
    get: r,
    has: r,
    set: r,
    getSetCookie: r,
    keys: r,
    values: r,
    entries: r,
    forEach: r,
    [Symbol.iterator]: { enumerable: !1 },
    [Symbol.toStringTag]: {
      value: "Headers",
      configurable: !0
    }
  }), i.converters.HeadersInit = function(C) {
    if (i.util.Type(C) === "Object")
      return C[Symbol.iterator] ? i.converters["sequence<sequence<ByteString>>"](C) : i.converters["record<ByteString, ByteString>"](C);
    throw i.errors.conversionFailed({
      prefix: "Headers constructor",
      argument: "Argument 1",
      types: ["sequence<sequence<ByteString>>", "record<ByteString, ByteString>"]
    });
  }, cn = {
    fill: Q,
    Headers: h,
    HeadersList: d
  }, cn;
}
var gn, Uc;
function Di() {
  if (Uc) return gn;
  Uc = 1;
  const { Headers: e, HeadersList: A, fill: t } = gr(), { extractBody: r, cloneBody: s, mixinBody: o } = Hs(), n = we, { kEnumerableProperty: i } = n, {
    isValidReasonPhrase: a,
    isCancelled: g,
    isAborted: c,
    isBlobLike: E,
    serializeJavascriptValueToJSONString: l,
    isErrorLike: Q,
    isomorphicEncode: I
  } = TA(), {
    redirectStatusSet: d,
    nullBodyStatus: h,
    DOMException: C
  } = _t(), { kState: u, kHeaders: B, kGuard: m, kRealm: f } = Et(), { webidl: y } = hA(), { FormData: b } = fi(), { getGlobalOrigin: w } = jr(), { URLSerializer: S } = MA(), { kHeadersList: v, kConstruct: N } = Se, F = Me, { types: j } = LA, M = globalThis.ReadableStream || ct.ReadableStream, K = new TextEncoder("utf-8");
  class ee {
    // Creates network error Response.
    static error() {
      const H = { settingsObject: {} }, $ = new ee();
      return $[u] = ge(), $[f] = H, $[B][v] = $[u].headersList, $[B][m] = "immutable", $[B][f] = H, $;
    }
    // https://fetch.spec.whatwg.org/#dom-response-json
    static json(H, $ = {}) {
      y.argumentLengthCheck(arguments, 1, { header: "Response.json" }), $ !== null && ($ = y.converters.ResponseInit($));
      const X = K.encode(
        l(H)
      ), z = r(X), W = { settingsObject: {} }, P = new ee();
      return P[f] = W, P[B][m] = "response", P[B][f] = W, de(P, $, { body: z[0], type: "application/json" }), P;
    }
    // Creates a redirect Response that redirects to url with status status.
    static redirect(H, $ = 302) {
      const X = { settingsObject: {} };
      y.argumentLengthCheck(arguments, 1, { header: "Response.redirect" }), H = y.converters.USVString(H), $ = y.converters["unsigned short"]($);
      let z;
      try {
        z = new URL(H, w());
      } catch (le) {
        throw Object.assign(new TypeError("Failed to parse URL from " + H), {
          cause: le
        });
      }
      if (!d.has($))
        throw new RangeError("Invalid status code " + $);
      const W = new ee();
      W[f] = X, W[B][m] = "immutable", W[B][f] = X, W[u].status = $;
      const P = I(S(z));
      return W[u].headersList.append("location", P), W;
    }
    // https://fetch.spec.whatwg.org/#dom-response
    constructor(H = null, $ = {}) {
      H !== null && (H = y.converters.BodyInit(H)), $ = y.converters.ResponseInit($), this[f] = { settingsObject: {} }, this[u] = re({}), this[B] = new e(N), this[B][m] = "response", this[B][v] = this[u].headersList, this[B][f] = this[f];
      let X = null;
      if (H != null) {
        const [z, W] = r(H);
        X = { body: z, type: W };
      }
      de(this, $, X);
    }
    // Returns response’s type, e.g., "cors".
    get type() {
      return y.brandCheck(this, ee), this[u].type;
    }
    // Returns response’s URL, if it has one; otherwise the empty string.
    get url() {
      y.brandCheck(this, ee);
      const H = this[u].urlList, $ = H[H.length - 1] ?? null;
      return $ === null ? "" : S($, !0);
    }
    // Returns whether response was obtained through a redirect.
    get redirected() {
      return y.brandCheck(this, ee), this[u].urlList.length > 1;
    }
    // Returns response’s status.
    get status() {
      return y.brandCheck(this, ee), this[u].status;
    }
    // Returns whether response’s status is an ok status.
    get ok() {
      return y.brandCheck(this, ee), this[u].status >= 200 && this[u].status <= 299;
    }
    // Returns response’s status message.
    get statusText() {
      return y.brandCheck(this, ee), this[u].statusText;
    }
    // Returns response’s headers as Headers.
    get headers() {
      return y.brandCheck(this, ee), this[B];
    }
    get body() {
      return y.brandCheck(this, ee), this[u].body ? this[u].body.stream : null;
    }
    get bodyUsed() {
      return y.brandCheck(this, ee), !!this[u].body && n.isDisturbed(this[u].body.stream);
    }
    // Returns a clone of response.
    clone() {
      if (y.brandCheck(this, ee), this.bodyUsed || this.body && this.body.locked)
        throw y.errors.exception({
          header: "Response.clone",
          message: "Body has already been consumed."
        });
      const H = ie(this[u]), $ = new ee();
      return $[u] = H, $[f] = this[f], $[B][v] = H.headersList, $[B][m] = this[B][m], $[B][f] = this[B][f], $;
    }
  }
  o(ee), Object.defineProperties(ee.prototype, {
    type: i,
    url: i,
    status: i,
    ok: i,
    redirected: i,
    statusText: i,
    headers: i,
    clone: i,
    body: i,
    bodyUsed: i,
    [Symbol.toStringTag]: {
      value: "Response",
      configurable: !0
    }
  }), Object.defineProperties(ee, {
    json: i,
    redirect: i,
    error: i
  });
  function ie(R) {
    if (R.internalResponse)
      return Ae(
        ie(R.internalResponse),
        R.type
      );
    const H = re({ ...R, body: null });
    return R.body != null && (H.body = s(R.body)), H;
  }
  function re(R) {
    return {
      aborted: !1,
      rangeRequested: !1,
      timingAllowPassed: !1,
      requestIncludesCredentials: !1,
      type: "default",
      status: 200,
      timingInfo: null,
      cacheState: "",
      statusText: "",
      ...R,
      headersList: R.headersList ? new A(R.headersList) : new A(),
      urlList: R.urlList ? [...R.urlList] : []
    };
  }
  function ge(R) {
    const H = Q(R);
    return re({
      type: "error",
      status: 0,
      error: H ? R : new Error(R && String(R)),
      aborted: R && R.name === "AbortError"
    });
  }
  function Y(R, H) {
    return H = {
      internalResponse: R,
      ...H
    }, new Proxy(R, {
      get($, X) {
        return X in H ? H[X] : $[X];
      },
      set($, X, z) {
        return F(!(X in H)), $[X] = z, !0;
      }
    });
  }
  function Ae(R, H) {
    if (H === "basic")
      return Y(R, {
        type: "basic",
        headersList: R.headersList
      });
    if (H === "cors")
      return Y(R, {
        type: "cors",
        headersList: R.headersList
      });
    if (H === "opaque")
      return Y(R, {
        type: "opaque",
        urlList: Object.freeze([]),
        status: 0,
        statusText: "",
        body: null
      });
    if (H === "opaqueredirect")
      return Y(R, {
        type: "opaqueredirect",
        status: 0,
        statusText: "",
        headersList: [],
        body: null
      });
    F(!1);
  }
  function ae(R, H = null) {
    return F(g(R)), c(R) ? ge(Object.assign(new C("The operation was aborted.", "AbortError"), { cause: H })) : ge(Object.assign(new C("Request was cancelled."), { cause: H }));
  }
  function de(R, H, $) {
    if (H.status !== null && (H.status < 200 || H.status > 599))
      throw new RangeError('init["status"] must be in the range of 200 to 599, inclusive.');
    if ("statusText" in H && H.statusText != null && !a(String(H.statusText)))
      throw new TypeError("Invalid statusText");
    if ("status" in H && H.status != null && (R[u].status = H.status), "statusText" in H && H.statusText != null && (R[u].statusText = H.statusText), "headers" in H && H.headers != null && t(R[B], H.headers), $) {
      if (h.includes(R.status))
        throw y.errors.exception({
          header: "Response constructor",
          message: "Invalid response status code " + R.status
        });
      R[u].body = $.body, $.type != null && !R[u].headersList.contains("Content-Type") && R[u].headersList.append("content-type", $.type);
    }
  }
  return y.converters.ReadableStream = y.interfaceConverter(
    M
  ), y.converters.FormData = y.interfaceConverter(
    b
  ), y.converters.URLSearchParams = y.interfaceConverter(
    URLSearchParams
  ), y.converters.XMLHttpRequestBodyInit = function(R) {
    return typeof R == "string" ? y.converters.USVString(R) : E(R) ? y.converters.Blob(R, { strict: !1 }) : j.isArrayBuffer(R) || j.isTypedArray(R) || j.isDataView(R) ? y.converters.BufferSource(R) : n.isFormDataLike(R) ? y.converters.FormData(R, { strict: !1 }) : R instanceof URLSearchParams ? y.converters.URLSearchParams(R) : y.converters.DOMString(R);
  }, y.converters.BodyInit = function(R) {
    return R instanceof M ? y.converters.ReadableStream(R) : R?.[Symbol.asyncIterator] ? R : y.converters.XMLHttpRequestBodyInit(R);
  }, y.converters.ResponseInit = y.dictionaryConverter([
    {
      key: "status",
      converter: y.converters["unsigned short"],
      defaultValue: 200
    },
    {
      key: "statusText",
      converter: y.converters.ByteString,
      defaultValue: ""
    },
    {
      key: "headers",
      converter: y.converters.HeadersInit
    }
  ]), gn = {
    makeNetworkError: ge,
    makeResponse: re,
    makeAppropriateNetworkError: ae,
    filterResponse: Ae,
    Response: ee,
    cloneResponse: ie
  }, gn;
}
var ln, Gc;
function Zs() {
  if (Gc) return ln;
  Gc = 1;
  const { extractBody: e, mixinBody: A, cloneBody: t } = Hs(), { Headers: r, fill: s, HeadersList: o } = gr(), { FinalizationRegistry: n } = gE(), i = we, {
    isValidHTTPToken: a,
    sameOrigin: g,
    normalizeMethod: c,
    makePolicyContainer: E,
    normalizeMethodRecord: l
  } = TA(), {
    forbiddenMethodsSet: Q,
    corsSafeListedMethodsSet: I,
    referrerPolicy: d,
    requestRedirect: h,
    requestMode: C,
    requestCredentials: u,
    requestCache: B,
    requestDuplex: m
  } = _t(), { kEnumerableProperty: f } = i, { kHeaders: y, kSignal: b, kState: w, kGuard: S, kRealm: v } = Et(), { webidl: N } = hA(), { getGlobalOrigin: F } = jr(), { URLSerializer: j } = MA(), { kHeadersList: M, kConstruct: K } = Se, ee = Me, { getMaxListeners: ie, setMaxListeners: re, getEventListeners: ge, defaultMaxListeners: Y } = nr;
  let Ae = globalThis.TransformStream;
  const ae = Symbol("abortController"), de = new n(({ signal: X, abort: z }) => {
    X.removeEventListener("abort", z);
  });
  class R {
    // https://fetch.spec.whatwg.org/#dom-request
    constructor(z, W = {}) {
      if (z === K)
        return;
      N.argumentLengthCheck(arguments, 1, { header: "Request constructor" }), z = N.converters.RequestInfo(z), W = N.converters.RequestInit(W), this[v] = {
        settingsObject: {
          baseUrl: F(),
          get origin() {
            return this.baseUrl?.origin;
          },
          policyContainer: E()
        }
      };
      let P = null, le = null;
      const Qe = this[v].settingsObject.baseUrl;
      let Ee = null;
      if (typeof z == "string") {
        let Be;
        try {
          Be = new URL(z, Qe);
        } catch (Te) {
          throw new TypeError("Failed to parse URL from " + z, { cause: Te });
        }
        if (Be.username || Be.password)
          throw new TypeError(
            "Request cannot be constructed from a URL that includes credentials: " + z
          );
        P = H({ urlList: [Be] }), le = "cors";
      } else
        ee(z instanceof R), P = z[w], Ee = z[b];
      const Ge = this[v].settingsObject.origin;
      let De = "client";
      if (P.window?.constructor?.name === "EnvironmentSettingsObject" && g(P.window, Ge) && (De = P.window), W.window != null)
        throw new TypeError(`'window' option '${De}' must be null`);
      "window" in W && (De = "no-window"), P = H({
        // URL request’s URL.
        // undici implementation note: this is set as the first item in request's urlList in makeRequest
        // method request’s method.
        method: P.method,
        // header list A copy of request’s header list.
        // undici implementation note: headersList is cloned in makeRequest
        headersList: P.headersList,
        // unsafe-request flag Set.
        unsafeRequest: P.unsafeRequest,
        // client This’s relevant settings object.
        client: this[v].settingsObject,
        // window window.
        window: De,
        // priority request’s priority.
        priority: P.priority,
        // origin request’s origin. The propagation of the origin is only significant for navigation requests
        // being handled by a service worker. In this scenario a request can have an origin that is different
        // from the current client.
        origin: P.origin,
        // referrer request’s referrer.
        referrer: P.referrer,
        // referrer policy request’s referrer policy.
        referrerPolicy: P.referrerPolicy,
        // mode request’s mode.
        mode: P.mode,
        // credentials mode request’s credentials mode.
        credentials: P.credentials,
        // cache mode request’s cache mode.
        cache: P.cache,
        // redirect mode request’s redirect mode.
        redirect: P.redirect,
        // integrity metadata request’s integrity metadata.
        integrity: P.integrity,
        // keepalive request’s keepalive.
        keepalive: P.keepalive,
        // reload-navigation flag request’s reload-navigation flag.
        reloadNavigation: P.reloadNavigation,
        // history-navigation flag request’s history-navigation flag.
        historyNavigation: P.historyNavigation,
        // URL list A clone of request’s URL list.
        urlList: [...P.urlList]
      });
      const Ue = Object.keys(W).length !== 0;
      if (Ue && (P.mode === "navigate" && (P.mode = "same-origin"), P.reloadNavigation = !1, P.historyNavigation = !1, P.origin = "client", P.referrer = "client", P.referrerPolicy = "", P.url = P.urlList[P.urlList.length - 1], P.urlList = [P.url]), W.referrer !== void 0) {
        const Be = W.referrer;
        if (Be === "")
          P.referrer = "no-referrer";
        else {
          let Te;
          try {
            Te = new URL(Be, Qe);
          } catch (eA) {
            throw new TypeError(`Referrer "${Be}" is not a valid URL.`, { cause: eA });
          }
          Te.protocol === "about:" && Te.hostname === "client" || Ge && !g(Te, this[v].settingsObject.baseUrl) ? P.referrer = "client" : P.referrer = Te;
        }
      }
      W.referrerPolicy !== void 0 && (P.referrerPolicy = W.referrerPolicy);
      let ye;
      if (W.mode !== void 0 ? ye = W.mode : ye = le, ye === "navigate")
        throw N.errors.exception({
          header: "Request constructor",
          message: "invalid request mode navigate."
        });
      if (ye != null && (P.mode = ye), W.credentials !== void 0 && (P.credentials = W.credentials), W.cache !== void 0 && (P.cache = W.cache), P.cache === "only-if-cached" && P.mode !== "same-origin")
        throw new TypeError(
          "'only-if-cached' can be set only with 'same-origin' mode"
        );
      if (W.redirect !== void 0 && (P.redirect = W.redirect), W.integrity != null && (P.integrity = String(W.integrity)), W.keepalive !== void 0 && (P.keepalive = !!W.keepalive), W.method !== void 0) {
        let Be = W.method;
        if (!a(Be))
          throw new TypeError(`'${Be}' is not a valid HTTP method.`);
        if (Q.has(Be.toUpperCase()))
          throw new TypeError(`'${Be}' HTTP method is unsupported.`);
        Be = l[Be] ?? c(Be), P.method = Be;
      }
      W.signal !== void 0 && (Ee = W.signal), this[w] = P;
      const Ce = new AbortController();
      if (this[b] = Ce.signal, this[b][v] = this[v], Ee != null) {
        if (!Ee || typeof Ee.aborted != "boolean" || typeof Ee.addEventListener != "function")
          throw new TypeError(
            "Failed to construct 'Request': member signal is not of type AbortSignal."
          );
        if (Ee.aborted)
          Ce.abort(Ee.reason);
        else {
          this[ae] = Ce;
          const Be = new WeakRef(Ce), Te = function() {
            const eA = Be.deref();
            eA !== void 0 && eA.abort(this.reason);
          };
          try {
            (typeof ie == "function" && ie(Ee) === Y || ge(Ee, "abort").length >= Y) && re(100, Ee);
          } catch {
          }
          i.addAbortListener(Ee, Te), de.register(Ce, { signal: Ee, abort: Te });
        }
      }
      if (this[y] = new r(K), this[y][M] = P.headersList, this[y][S] = "request", this[y][v] = this[v], ye === "no-cors") {
        if (!I.has(P.method))
          throw new TypeError(
            `'${P.method} is unsupported in no-cors mode.`
          );
        this[y][S] = "request-no-cors";
      }
      if (Ue) {
        const Be = this[y][M], Te = W.headers !== void 0 ? W.headers : new o(Be);
        if (Be.clear(), Te instanceof o) {
          for (const [eA, $e] of Te)
            Be.append(eA, $e);
          Be.cookies = Te.cookies;
        } else
          s(this[y], Te);
      }
      const Ie = z instanceof R ? z[w].body : null;
      if ((W.body != null || Ie != null) && (P.method === "GET" || P.method === "HEAD"))
        throw new TypeError("Request with GET/HEAD method cannot have body.");
      let me = null;
      if (W.body != null) {
        const [Be, Te] = e(
          W.body,
          P.keepalive
        );
        me = Be, Te && !this[y][M].contains("content-type") && this[y].append("content-type", Te);
      }
      const Ne = me ?? Ie;
      if (Ne != null && Ne.source == null) {
        if (me != null && W.duplex == null)
          throw new TypeError("RequestInit: duplex option is required when sending a body.");
        if (P.mode !== "same-origin" && P.mode !== "cors")
          throw new TypeError(
            'If request is made from ReadableStream, mode should be "same-origin" or "cors"'
          );
        P.useCORSPreflightFlag = !0;
      }
      let oA = Ne;
      if (me == null && Ie != null) {
        if (i.isDisturbed(Ie.stream) || Ie.stream.locked)
          throw new TypeError(
            "Cannot construct a Request with a Request object that has already been used."
          );
        Ae || (Ae = ct.TransformStream);
        const Be = new Ae();
        Ie.stream.pipeThrough(Be), oA = {
          source: Ie.source,
          length: Ie.length,
          stream: Be.readable
        };
      }
      this[w].body = oA;
    }
    // Returns request’s HTTP method, which is "GET" by default.
    get method() {
      return N.brandCheck(this, R), this[w].method;
    }
    // Returns the URL of request as a string.
    get url() {
      return N.brandCheck(this, R), j(this[w].url);
    }
    // Returns a Headers object consisting of the headers associated with request.
    // Note that headers added in the network layer by the user agent will not
    // be accounted for in this object, e.g., the "Host" header.
    get headers() {
      return N.brandCheck(this, R), this[y];
    }
    // Returns the kind of resource requested by request, e.g., "document"
    // or "script".
    get destination() {
      return N.brandCheck(this, R), this[w].destination;
    }
    // Returns the referrer of request. Its value can be a same-origin URL if
    // explicitly set in init, the empty string to indicate no referrer, and
    // "about:client" when defaulting to the global’s default. This is used
    // during fetching to determine the value of the `Referer` header of the
    // request being made.
    get referrer() {
      return N.brandCheck(this, R), this[w].referrer === "no-referrer" ? "" : this[w].referrer === "client" ? "about:client" : this[w].referrer.toString();
    }
    // Returns the referrer policy associated with request.
    // This is used during fetching to compute the value of the request’s
    // referrer.
    get referrerPolicy() {
      return N.brandCheck(this, R), this[w].referrerPolicy;
    }
    // Returns the mode associated with request, which is a string indicating
    // whether the request will use CORS, or will be restricted to same-origin
    // URLs.
    get mode() {
      return N.brandCheck(this, R), this[w].mode;
    }
    // Returns the credentials mode associated with request,
    // which is a string indicating whether credentials will be sent with the
    // request always, never, or only when sent to a same-origin URL.
    get credentials() {
      return this[w].credentials;
    }
    // Returns the cache mode associated with request,
    // which is a string indicating how the request will
    // interact with the browser’s cache when fetching.
    get cache() {
      return N.brandCheck(this, R), this[w].cache;
    }
    // Returns the redirect mode associated with request,
    // which is a string indicating how redirects for the
    // request will be handled during fetching. A request
    // will follow redirects by default.
    get redirect() {
      return N.brandCheck(this, R), this[w].redirect;
    }
    // Returns request’s subresource integrity metadata, which is a
    // cryptographic hash of the resource being fetched. Its value
    // consists of multiple hashes separated by whitespace. [SRI]
    get integrity() {
      return N.brandCheck(this, R), this[w].integrity;
    }
    // Returns a boolean indicating whether or not request can outlive the
    // global in which it was created.
    get keepalive() {
      return N.brandCheck(this, R), this[w].keepalive;
    }
    // Returns a boolean indicating whether or not request is for a reload
    // navigation.
    get isReloadNavigation() {
      return N.brandCheck(this, R), this[w].reloadNavigation;
    }
    // Returns a boolean indicating whether or not request is for a history
    // navigation (a.k.a. back-foward navigation).
    get isHistoryNavigation() {
      return N.brandCheck(this, R), this[w].historyNavigation;
    }
    // Returns the signal associated with request, which is an AbortSignal
    // object indicating whether or not request has been aborted, and its
    // abort event handler.
    get signal() {
      return N.brandCheck(this, R), this[b];
    }
    get body() {
      return N.brandCheck(this, R), this[w].body ? this[w].body.stream : null;
    }
    get bodyUsed() {
      return N.brandCheck(this, R), !!this[w].body && i.isDisturbed(this[w].body.stream);
    }
    get duplex() {
      return N.brandCheck(this, R), "half";
    }
    // Returns a clone of request.
    clone() {
      if (N.brandCheck(this, R), this.bodyUsed || this.body?.locked)
        throw new TypeError("unusable");
      const z = $(this[w]), W = new R(K);
      W[w] = z, W[v] = this[v], W[y] = new r(K), W[y][M] = z.headersList, W[y][S] = this[y][S], W[y][v] = this[y][v];
      const P = new AbortController();
      return this.signal.aborted ? P.abort(this.signal.reason) : i.addAbortListener(
        this.signal,
        () => {
          P.abort(this.signal.reason);
        }
      ), W[b] = P.signal, W;
    }
  }
  A(R);
  function H(X) {
    const z = {
      method: "GET",
      localURLsOnly: !1,
      unsafeRequest: !1,
      body: null,
      client: null,
      reservedClient: null,
      replacesClientId: "",
      window: "client",
      keepalive: !1,
      serviceWorkers: "all",
      initiator: "",
      destination: "",
      priority: null,
      origin: "client",
      policyContainer: "client",
      referrer: "client",
      referrerPolicy: "",
      mode: "no-cors",
      useCORSPreflightFlag: !1,
      credentials: "same-origin",
      useCredentials: !1,
      cache: "default",
      redirect: "follow",
      integrity: "",
      cryptoGraphicsNonceMetadata: "",
      parserMetadata: "",
      reloadNavigation: !1,
      historyNavigation: !1,
      userActivation: !1,
      taintedOrigin: !1,
      redirectCount: 0,
      responseTainting: "basic",
      preventNoCacheCacheControlHeaderModification: !1,
      done: !1,
      timingAllowFailed: !1,
      ...X,
      headersList: X.headersList ? new o(X.headersList) : new o()
    };
    return z.url = z.urlList[0], z;
  }
  function $(X) {
    const z = H({ ...X, body: null });
    return X.body != null && (z.body = t(X.body)), z;
  }
  return Object.defineProperties(R.prototype, {
    method: f,
    url: f,
    headers: f,
    redirect: f,
    clone: f,
    signal: f,
    duplex: f,
    destination: f,
    body: f,
    bodyUsed: f,
    isHistoryNavigation: f,
    isReloadNavigation: f,
    keepalive: f,
    integrity: f,
    cache: f,
    credentials: f,
    attribute: f,
    referrerPolicy: f,
    referrer: f,
    mode: f,
    [Symbol.toStringTag]: {
      value: "Request",
      configurable: !0
    }
  }), N.converters.Request = N.interfaceConverter(
    R
  ), N.converters.RequestInfo = function(X) {
    return typeof X == "string" ? N.converters.USVString(X) : X instanceof R ? N.converters.Request(X) : N.converters.USVString(X);
  }, N.converters.AbortSignal = N.interfaceConverter(
    AbortSignal
  ), N.converters.RequestInit = N.dictionaryConverter([
    {
      key: "method",
      converter: N.converters.ByteString
    },
    {
      key: "headers",
      converter: N.converters.HeadersInit
    },
    {
      key: "body",
      converter: N.nullableConverter(
        N.converters.BodyInit
      )
    },
    {
      key: "referrer",
      converter: N.converters.USVString
    },
    {
      key: "referrerPolicy",
      converter: N.converters.DOMString,
      // https://w3c.github.io/webappsec-referrer-policy/#referrer-policy
      allowedValues: d
    },
    {
      key: "mode",
      converter: N.converters.DOMString,
      // https://fetch.spec.whatwg.org/#concept-request-mode
      allowedValues: C
    },
    {
      key: "credentials",
      converter: N.converters.DOMString,
      // https://fetch.spec.whatwg.org/#requestcredentials
      allowedValues: u
    },
    {
      key: "cache",
      converter: N.converters.DOMString,
      // https://fetch.spec.whatwg.org/#requestcache
      allowedValues: B
    },
    {
      key: "redirect",
      converter: N.converters.DOMString,
      // https://fetch.spec.whatwg.org/#requestredirect
      allowedValues: h
    },
    {
      key: "integrity",
      converter: N.converters.DOMString
    },
    {
      key: "keepalive",
      converter: N.converters.boolean
    },
    {
      key: "signal",
      converter: N.nullableConverter(
        (X) => N.converters.AbortSignal(
          X,
          { strict: !1 }
        )
      )
    },
    {
      key: "window",
      converter: N.converters.any
    },
    {
      key: "duplex",
      converter: N.converters.DOMString,
      allowedValues: m
    }
  ]), ln = { Request: R, makeRequest: H }, ln;
}
var En, _c;
function Ti() {
  if (_c) return En;
  _c = 1;
  const {
    Response: e,
    makeNetworkError: A,
    makeAppropriateNetworkError: t,
    filterResponse: r,
    makeResponse: s
  } = Di(), { Headers: o } = gr(), { Request: n, makeRequest: i } = Zs(), a = qu, {
    bytesMatch: g,
    makePolicyContainer: c,
    clonePolicyContainer: E,
    requestBadPort: l,
    TAOCheck: Q,
    appendRequestOriginHeader: I,
    responseLocationURL: d,
    requestCurrentURL: h,
    setRequestReferrerPolicyOnRedirect: C,
    tryUpgradeRequestToAPotentiallyTrustworthyURL: u,
    createOpaqueTimingInfo: B,
    appendFetchMetadata: m,
    corsCheck: f,
    crossOriginResourcePolicyCheck: y,
    determineRequestsReferrer: b,
    coarsenedSharedCurrentTime: w,
    createDeferredPromise: S,
    isBlobLike: v,
    sameOrigin: N,
    isCancelled: F,
    isAborted: j,
    isErrorLike: M,
    fullyReadBody: K,
    readableStreamClose: ee,
    isomorphicEncode: ie,
    urlIsLocal: re,
    urlIsHttpHttpsScheme: ge,
    urlHasHttpsScheme: Y
  } = TA(), { kState: Ae, kHeaders: ae, kGuard: de, kRealm: R } = Et(), H = Me, { safelyExtractBody: $ } = Hs(), {
    redirectStatusSet: X,
    nullBodyStatus: z,
    safeMethodsSet: W,
    requestBodyHeader: P,
    subresourceSet: le,
    DOMException: Qe
  } = _t(), { kHeadersList: Ee } = Se, Ge = nr, { Readable: De, pipeline: Ue } = lt, { addAbortListener: ye, isErrored: Ce, isReadable: Ie, nodeMajor: me, nodeMinor: Ne } = we, { dataURLProcessor: oA, serializeAMimeType: Be } = MA(), { TransformStream: Te } = ct, { getGlobalDispatcher: eA } = Zr, { webidl: $e } = hA(), { STATUS_CODES: Nt } = or, T = ["GET", "HEAD"];
  let x, _ = globalThis.ReadableStream;
  class D extends Ge {
    constructor(te) {
      super(), this.dispatcher = te, this.connection = null, this.dump = !1, this.state = "ongoing", this.setMaxListeners(21);
    }
    terminate(te) {
      this.state === "ongoing" && (this.state = "terminated", this.connection?.destroy(te), this.emit("terminated", te));
    }
    // https://fetch.spec.whatwg.org/#fetch-controller-abort
    abort(te) {
      this.state === "ongoing" && (this.state = "aborted", te || (te = new Qe("The operation was aborted.", "AbortError")), this.serializedAbortReason = te, this.connection?.destroy(te), this.emit("terminated", te));
    }
  }
  function p(U, te = {}) {
    $e.argumentLengthCheck(arguments, 1, { header: "globalThis.fetch" });
    const q = S();
    let J;
    try {
      J = new n(U, te);
    } catch (ue) {
      return q.reject(ue), q.promise;
    }
    const ne = J[Ae];
    if (J.signal.aborted)
      return L(q, ne, null, J.signal.reason), q.promise;
    ne.client.globalObject?.constructor?.name === "ServiceWorkerGlobalScope" && (ne.serviceWorkers = "none");
    let pe = null;
    const AA = null;
    let dA = !1, Oe = null;
    return ye(
      J.signal,
      () => {
        dA = !0, H(Oe != null), Oe.abort(J.signal.reason), L(q, ne, pe, J.signal.reason);
      }
    ), Oe = V({
      request: ne,
      processResponseEndOfBody: (ue) => k(ue, "fetch"),
      processResponse: (ue) => {
        if (dA)
          return Promise.resolve();
        if (ue.aborted)
          return L(q, ne, pe, Oe.serializedAbortReason), Promise.resolve();
        if (ue.type === "error")
          return q.reject(
            Object.assign(new TypeError("fetch failed"), { cause: ue.error })
          ), Promise.resolve();
        pe = new e(), pe[Ae] = ue, pe[R] = AA, pe[ae][Ee] = ue.headersList, pe[ae][de] = "immutable", pe[ae][R] = AA, q.resolve(pe);
      },
      dispatcher: te.dispatcher ?? eA()
      // undici
    }), q.promise;
  }
  function k(U, te = "other") {
    if (U.type === "error" && U.aborted || !U.urlList?.length)
      return;
    const q = U.urlList[0];
    let J = U.timingInfo, ne = U.cacheState;
    ge(q) && J !== null && (U.timingAllowPassed || (J = B({
      startTime: J.startTime
    }), ne = ""), J.endTime = w(), U.timingInfo = J, G(
      J,
      q,
      te,
      globalThis,
      ne
    ));
  }
  function G(U, te, q, J, ne) {
    (me > 18 || me === 18 && Ne >= 2) && performance.markResourceTiming(U, te.href, q, J, ne);
  }
  function L(U, te, q, J) {
    if (J || (J = new Qe("The operation was aborted.", "AbortError")), U.reject(J), te.body != null && Ie(te.body?.stream) && te.body.stream.cancel(J).catch((Z) => {
      if (Z.code !== "ERR_INVALID_STATE")
        throw Z;
    }), q == null)
      return;
    const ne = q[Ae];
    ne.body != null && Ie(ne.body?.stream) && ne.body.stream.cancel(J).catch((Z) => {
      if (Z.code !== "ERR_INVALID_STATE")
        throw Z;
    });
  }
  function V({
    request: U,
    processRequestBodyChunkLength: te,
    processRequestEndOfBody: q,
    processResponse: J,
    processResponseEndOfBody: ne,
    processResponseConsumeBody: Z,
    useParallelQueue: pe = !1,
    dispatcher: AA
    // undici
  }) {
    let dA = null, Oe = !1;
    U.client != null && (dA = U.client.globalObject, Oe = U.client.crossOriginIsolatedCapability);
    const $A = w(Oe), rs = B({
      startTime: $A
    }), ue = {
      controller: new D(AA),
      request: U,
      timingInfo: rs,
      processRequestBodyChunkLength: te,
      processRequestEndOfBody: q,
      processResponse: J,
      processResponseConsumeBody: Z,
      processResponseEndOfBody: ne,
      taskDestination: dA,
      crossOriginIsolatedCapability: Oe
    };
    return H(!U.body || U.body.stream), U.window === "client" && (U.window = U.client?.globalObject?.constructor?.name === "Window" ? U.client : "no-window"), U.origin === "client" && (U.origin = U.client?.origin), U.policyContainer === "client" && (U.client != null ? U.policyContainer = E(
      U.client.policyContainer
    ) : U.policyContainer = c()), U.headersList.contains("accept") || U.headersList.append("accept", "*/*"), U.headersList.contains("accept-language") || U.headersList.append("accept-language", "*"), U.priority, le.has(U.destination), se(ue).catch((lA) => {
      ue.controller.terminate(lA);
    }), ue.controller;
  }
  async function se(U, te = !1) {
    const q = U.request;
    let J = null;
    if (q.localURLsOnly && !re(h(q)) && (J = A("local URLs only")), u(q), l(q) === "blocked" && (J = A("bad port")), q.referrerPolicy === "" && (q.referrerPolicy = q.policyContainer.referrerPolicy), q.referrer !== "no-referrer" && (q.referrer = b(q)), J === null && (J = await (async () => {
      const Z = h(q);
      return (
        // - request’s current URL’s origin is same origin with request’s origin,
        //   and request’s response tainting is "basic"
        N(Z, q.url) && q.responseTainting === "basic" || // request’s current URL’s scheme is "data"
        Z.protocol === "data:" || // - request’s mode is "navigate" or "websocket"
        q.mode === "navigate" || q.mode === "websocket" ? (q.responseTainting = "basic", await fe(U)) : q.mode === "same-origin" ? A('request mode cannot be "same-origin"') : q.mode === "no-cors" ? q.redirect !== "follow" ? A(
          'redirect mode cannot be "follow" for "no-cors" request'
        ) : (q.responseTainting = "opaque", await fe(U)) : ge(h(q)) ? (q.responseTainting = "cors", await jA(U)) : A("URL scheme must be a HTTP(S) scheme")
      );
    })()), te)
      return J;
    J.status !== 0 && !J.internalResponse && (q.responseTainting, q.responseTainting === "basic" ? J = r(J, "basic") : q.responseTainting === "cors" ? J = r(J, "cors") : q.responseTainting === "opaque" ? J = r(J, "opaque") : H(!1));
    let ne = J.status === 0 ? J : J.internalResponse;
    if (ne.urlList.length === 0 && ne.urlList.push(...q.urlList), q.timingAllowFailed || (J.timingAllowPassed = !0), J.type === "opaque" && ne.status === 206 && ne.rangeRequested && !q.headers.contains("range") && (J = ne = A()), J.status !== 0 && (q.method === "HEAD" || q.method === "CONNECT" || z.includes(ne.status)) && (ne.body = null, U.controller.dump = !0), q.integrity) {
      const Z = (AA) => xe(U, A(AA));
      if (q.responseTainting === "opaque" || J.body == null) {
        Z(J.error);
        return;
      }
      const pe = (AA) => {
        if (!g(AA, q.integrity)) {
          Z("integrity mismatch");
          return;
        }
        J.body = $(AA)[0], xe(U, J);
      };
      await K(J.body, pe, Z);
    } else
      xe(U, J);
  }
  function fe(U) {
    if (F(U) && U.request.redirectCount === 0)
      return Promise.resolve(t(U));
    const { request: te } = U, { protocol: q } = h(te);
    switch (q) {
      case "about:":
        return Promise.resolve(A("about scheme is not supported"));
      case "blob:": {
        x || (x = Gt.resolveObjectURL);
        const J = h(te);
        if (J.search.length !== 0)
          return Promise.resolve(A("NetworkError when attempting to fetch resource."));
        const ne = x(J.toString());
        if (te.method !== "GET" || !v(ne))
          return Promise.resolve(A("invalid method"));
        const Z = $(ne), pe = Z[0], AA = ie(`${pe.length}`), dA = Z[1] ?? "", Oe = s({
          statusText: "OK",
          headersList: [
            ["content-length", { name: "Content-Length", value: AA }],
            ["content-type", { name: "Content-Type", value: dA }]
          ]
        });
        return Oe.body = pe, Promise.resolve(Oe);
      }
      case "data:": {
        const J = h(te), ne = oA(J);
        if (ne === "failure")
          return Promise.resolve(A("failed to fetch the data URL"));
        const Z = Be(ne.mimeType);
        return Promise.resolve(s({
          statusText: "OK",
          headersList: [
            ["content-type", { name: "Content-Type", value: Z }]
          ],
          body: $(ne.body)[0]
        }));
      }
      case "file:":
        return Promise.resolve(A("not implemented... yet..."));
      case "http:":
      case "https:":
        return jA(U).catch((J) => A(J));
      default:
        return Promise.resolve(A("unknown scheme"));
    }
  }
  function Ve(U, te) {
    U.request.done = !0, U.processResponseDone != null && queueMicrotask(() => U.processResponseDone(te));
  }
  function xe(U, te) {
    te.type === "error" && (te.urlList = [U.request.urlList[0]], te.timingInfo = B({
      startTime: U.timingInfo.startTime
    }));
    const q = () => {
      U.request.done = !0, U.processResponseEndOfBody != null && queueMicrotask(() => U.processResponseEndOfBody(te));
    };
    if (U.processResponse != null && queueMicrotask(() => U.processResponse(te)), te.body == null)
      q();
    else {
      const J = (Z, pe) => {
        pe.enqueue(Z);
      }, ne = new Te({
        start() {
        },
        transform: J,
        flush: q
      }, {
        size() {
          return 1;
        }
      }, {
        size() {
          return 1;
        }
      });
      te.body = { stream: te.body.stream.pipeThrough(ne) };
    }
    if (U.processResponseConsumeBody != null) {
      const J = (Z) => U.processResponseConsumeBody(te, Z), ne = (Z) => U.processResponseConsumeBody(te, Z);
      if (te.body == null)
        queueMicrotask(() => J(null));
      else
        return K(te.body, J, ne);
      return Promise.resolve();
    }
  }
  async function jA(U) {
    const te = U.request;
    let q = null, J = null;
    const ne = U.timingInfo;
    if (te.serviceWorkers, q === null) {
      if (te.redirect === "follow" && (te.serviceWorkers = "none"), J = q = await ur(U), te.responseTainting === "cors" && f(te, q) === "failure")
        return A("cors failure");
      Q(te, q) === "failure" && (te.timingAllowFailed = !0);
    }
    return (te.responseTainting === "opaque" || q.type === "opaque") && y(
      te.origin,
      te.client,
      te.destination,
      J
    ) === "blocked" ? A("blocked") : (X.has(J.status) && (te.redirect !== "manual" && U.controller.connection.destroy(), te.redirect === "error" ? q = A("unexpected redirect") : te.redirect === "manual" ? q = J : te.redirect === "follow" ? q = await oo(U, q) : H(!1)), q.timingInfo = ne, q);
  }
  function oo(U, te) {
    const q = U.request, J = te.internalResponse ? te.internalResponse : te;
    let ne;
    try {
      if (ne = d(
        J,
        h(q).hash
      ), ne == null)
        return te;
    } catch (pe) {
      return Promise.resolve(A(pe));
    }
    if (!ge(ne))
      return Promise.resolve(A("URL scheme must be a HTTP(S) scheme"));
    if (q.redirectCount === 20)
      return Promise.resolve(A("redirect count exceeded"));
    if (q.redirectCount += 1, q.mode === "cors" && (ne.username || ne.password) && !N(q, ne))
      return Promise.resolve(A('cross origin not allowed for request mode "cors"'));
    if (q.responseTainting === "cors" && (ne.username || ne.password))
      return Promise.resolve(A(
        'URL cannot contain credentials for request mode "cors"'
      ));
    if (J.status !== 303 && q.body != null && q.body.source == null)
      return Promise.resolve(A());
    if ([301, 302].includes(J.status) && q.method === "POST" || J.status === 303 && !T.includes(q.method)) {
      q.method = "GET", q.body = null;
      for (const pe of P)
        q.headersList.delete(pe);
    }
    N(h(q), ne) || (q.headersList.delete("authorization"), q.headersList.delete("proxy-authorization", !0), q.headersList.delete("cookie"), q.headersList.delete("host")), q.body != null && (H(q.body.source != null), q.body = $(q.body.source)[0]);
    const Z = U.timingInfo;
    return Z.redirectEndTime = Z.postRedirectStartTime = w(U.crossOriginIsolatedCapability), Z.redirectStartTime === 0 && (Z.redirectStartTime = Z.startTime), q.urlList.push(ne), C(q, J), se(U, !0);
  }
  async function ur(U, te = !1, q = !1) {
    const J = U.request;
    let ne = null, Z = null, pe = null;
    J.window === "no-window" && J.redirect === "error" ? (ne = U, Z = J) : (Z = i(J), ne = { ...U }, ne.request = Z);
    const AA = J.credentials === "include" || J.credentials === "same-origin" && J.responseTainting === "basic", dA = Z.body ? Z.body.length : null;
    let Oe = null;
    if (Z.body == null && ["POST", "PUT"].includes(Z.method) && (Oe = "0"), dA != null && (Oe = ie(`${dA}`)), Oe != null && Z.headersList.append("content-length", Oe), dA != null && Z.keepalive, Z.referrer instanceof URL && Z.headersList.append("referer", ie(Z.referrer.href)), I(Z), m(Z), Z.headersList.contains("user-agent") || Z.headersList.append("user-agent", typeof esbuildDetection > "u" ? "undici" : "node"), Z.cache === "default" && (Z.headersList.contains("if-modified-since") || Z.headersList.contains("if-none-match") || Z.headersList.contains("if-unmodified-since") || Z.headersList.contains("if-match") || Z.headersList.contains("if-range")) && (Z.cache = "no-store"), Z.cache === "no-cache" && !Z.preventNoCacheCacheControlHeaderModification && !Z.headersList.contains("cache-control") && Z.headersList.append("cache-control", "max-age=0"), (Z.cache === "no-store" || Z.cache === "reload") && (Z.headersList.contains("pragma") || Z.headersList.append("pragma", "no-cache"), Z.headersList.contains("cache-control") || Z.headersList.append("cache-control", "no-cache")), Z.headersList.contains("range") && Z.headersList.append("accept-encoding", "identity"), Z.headersList.contains("accept-encoding") || (Y(h(Z)) ? Z.headersList.append("accept-encoding", "br, gzip, deflate") : Z.headersList.append("accept-encoding", "gzip, deflate")), Z.headersList.delete("host"), Z.cache = "no-store", Z.mode !== "no-store" && Z.mode, pe == null) {
      if (Z.mode === "only-if-cached")
        return A("only if cached");
      const $A = await Pu(
        ne,
        AA,
        q
      );
      !W.has(Z.method) && $A.status >= 200 && $A.status <= 399, pe == null && (pe = $A);
    }
    if (pe.urlList = [...Z.urlList], Z.headersList.contains("range") && (pe.rangeRequested = !0), pe.requestIncludesCredentials = AA, pe.status === 407)
      return J.window === "no-window" ? A() : F(U) ? t(U) : A("proxy authentication required");
    if (
      // response’s status is 421
      pe.status === 421 && // isNewConnectionFetch is false
      !q && // request’s body is null, or request’s body is non-null and request’s body’s source is non-null
      (J.body == null || J.body.source != null)
    ) {
      if (F(U))
        return t(U);
      U.controller.connection.destroy(), pe = await ur(
        U,
        te,
        !0
      );
    }
    return pe;
  }
  async function Pu(U, te = !1, q = !1) {
    H(!U.controller.connection || U.controller.connection.destroyed), U.controller.connection = {
      abort: null,
      destroyed: !1,
      destroy(ue) {
        this.destroyed || (this.destroyed = !0, this.abort?.(ue ?? new Qe("The operation was aborted.", "AbortError")));
      }
    };
    const J = U.request;
    let ne = null;
    const Z = U.timingInfo;
    J.cache = "no-store", J.mode;
    let pe = null;
    if (J.body == null && U.processRequestEndOfBody)
      queueMicrotask(() => U.processRequestEndOfBody());
    else if (J.body != null) {
      const ue = async function* (Ke) {
        F(U) || (yield Ke, U.processRequestBodyChunkLength?.(Ke.byteLength));
      }, lA = () => {
        F(U) || U.processRequestEndOfBody && U.processRequestEndOfBody();
      }, kA = (Ke) => {
        F(U) || (Ke.name === "AbortError" ? U.controller.abort() : U.controller.terminate(Ke));
      };
      pe = async function* () {
        try {
          for await (const Ke of J.body.stream)
            yield* ue(Ke);
          lA();
        } catch (Ke) {
          kA(Ke);
        }
      }();
    }
    try {
      const { body: ue, status: lA, statusText: kA, headersList: Ke, socket: ss } = await rs({ body: pe });
      if (ss)
        ne = s({ status: lA, statusText: kA, headersList: Ke, socket: ss });
      else {
        const Je = ue[Symbol.asyncIterator]();
        U.controller.next = () => Je.next(), ne = s({ status: lA, statusText: kA, headersList: Ke });
      }
    } catch (ue) {
      return ue.name === "AbortError" ? (U.controller.connection.destroy(), t(U, ue)) : A(ue);
    }
    const AA = () => {
      U.controller.resume();
    }, dA = (ue) => {
      U.controller.abort(ue);
    };
    _ || (_ = ct.ReadableStream);
    const Oe = new _(
      {
        async start(ue) {
          U.controller.controller = ue;
        },
        async pull(ue) {
          await AA();
        },
        async cancel(ue) {
          await dA(ue);
        }
      },
      {
        highWaterMark: 0,
        size() {
          return 1;
        }
      }
    );
    ne.body = { stream: Oe }, U.controller.on("terminated", $A), U.controller.resume = async () => {
      for (; ; ) {
        let ue, lA;
        try {
          const { done: kA, value: Ke } = await U.controller.next();
          if (j(U))
            break;
          ue = kA ? void 0 : Ke;
        } catch (kA) {
          U.controller.ended && !Z.encodedBodySize ? ue = void 0 : (ue = kA, lA = !0);
        }
        if (ue === void 0) {
          ee(U.controller.controller), Ve(U, ne);
          return;
        }
        if (Z.decodedBodySize += ue?.byteLength ?? 0, lA) {
          U.controller.terminate(ue);
          return;
        }
        if (U.controller.controller.enqueue(new Uint8Array(ue)), Ce(Oe)) {
          U.controller.terminate();
          return;
        }
        if (!U.controller.controller.desiredSize)
          return;
      }
    };
    function $A(ue) {
      j(U) ? (ne.aborted = !0, Ie(Oe) && U.controller.controller.error(
        U.controller.serializedAbortReason
      )) : Ie(Oe) && U.controller.controller.error(new TypeError("terminated", {
        cause: M(ue) ? ue : void 0
      })), U.controller.connection.destroy();
    }
    return ne;
    async function rs({ body: ue }) {
      const lA = h(J), kA = U.controller.dispatcher;
      return new Promise((Ke, ss) => kA.dispatch(
        {
          path: lA.pathname + lA.search,
          origin: lA.origin,
          method: J.method,
          body: U.controller.dispatcher.isMockActive ? J.body && (J.body.source || J.body.stream) : ue,
          headers: J.headersList.entries,
          maxRedirections: 0,
          upgrade: J.mode === "websocket" ? "websocket" : void 0
        },
        {
          body: null,
          abort: null,
          onConnect(Je) {
            const { connection: tA } = U.controller;
            tA.destroyed ? Je(new Qe("The operation was aborted.", "AbortError")) : (U.controller.on("terminated", Je), this.abort = tA.abort = Je);
          },
          onHeaders(Je, tA, no, os) {
            if (Je < 200)
              return;
            let KA = [], hr = "";
            const dr = new o();
            if (Array.isArray(tA))
              for (let yA = 0; yA < tA.length; yA += 2) {
                const zA = tA[yA + 0].toString("latin1"), ut = tA[yA + 1].toString("latin1");
                zA.toLowerCase() === "content-encoding" ? KA = ut.toLowerCase().split(",").map((io) => io.trim()) : zA.toLowerCase() === "location" && (hr = ut), dr[Ee].append(zA, ut);
              }
            else {
              const yA = Object.keys(tA);
              for (const zA of yA) {
                const ut = tA[zA];
                zA.toLowerCase() === "content-encoding" ? KA = ut.toLowerCase().split(",").map((io) => io.trim()).reverse() : zA.toLowerCase() === "location" && (hr = ut), dr[Ee].append(zA, ut);
              }
            }
            this.body = new De({ read: no });
            const vt = [], Yu = J.redirect === "follow" && hr && X.has(Je);
            if (J.method !== "HEAD" && J.method !== "CONNECT" && !z.includes(Je) && !Yu)
              for (const yA of KA)
                if (yA === "x-gzip" || yA === "gzip")
                  vt.push(a.createGunzip({
                    // Be less strict when decoding compressed responses, since sometimes
                    // servers send slightly invalid responses that are still accepted
                    // by common browsers.
                    // Always using Z_SYNC_FLUSH is what cURL does.
                    flush: a.constants.Z_SYNC_FLUSH,
                    finishFlush: a.constants.Z_SYNC_FLUSH
                  }));
                else if (yA === "deflate")
                  vt.push(a.createInflate());
                else if (yA === "br")
                  vt.push(a.createBrotliDecompress());
                else {
                  vt.length = 0;
                  break;
                }
            return Ke({
              status: Je,
              statusText: os,
              headersList: dr[Ee],
              body: vt.length ? Ue(this.body, ...vt, () => {
              }) : this.body.on("error", () => {
              })
            }), !0;
          },
          onData(Je) {
            if (U.controller.dump)
              return;
            const tA = Je;
            return Z.encodedBodySize += tA.byteLength, this.body.push(tA);
          },
          onComplete() {
            this.abort && U.controller.off("terminated", this.abort), U.controller.ended = !0, this.body.push(null);
          },
          onError(Je) {
            this.abort && U.controller.off("terminated", this.abort), this.body?.destroy(Je), U.controller.terminate(Je), ss(Je);
          },
          onUpgrade(Je, tA, no) {
            if (Je !== 101)
              return;
            const os = new o();
            for (let KA = 0; KA < tA.length; KA += 2) {
              const hr = tA[KA + 0].toString("latin1"), dr = tA[KA + 1].toString("latin1");
              os[Ee].append(hr, dr);
            }
            return Ke({
              status: Je,
              statusText: Nt[Je],
              headersList: os[Ee],
              socket: no
            }), !0;
          }
        }
      ));
    }
  }
  return En = {
    fetch: p,
    Fetch: D,
    fetching: V,
    finalizeAndReportTiming: k
  }, En;
}
var un, Nc;
function NE() {
  return Nc || (Nc = 1, un = {
    kState: Symbol("FileReader state"),
    kResult: Symbol("FileReader result"),
    kError: Symbol("FileReader error"),
    kLastProgressEventFired: Symbol("FileReader last progress event fired timestamp"),
    kEvents: Symbol("FileReader events"),
    kAborted: Symbol("FileReader aborted")
  }), un;
}
var hn, vc;
function tp() {
  if (vc) return hn;
  vc = 1;
  const { webidl: e } = hA(), A = Symbol("ProgressEvent state");
  class t extends Event {
    constructor(s, o = {}) {
      s = e.converters.DOMString(s), o = e.converters.ProgressEventInit(o ?? {}), super(s, o), this[A] = {
        lengthComputable: o.lengthComputable,
        loaded: o.loaded,
        total: o.total
      };
    }
    get lengthComputable() {
      return e.brandCheck(this, t), this[A].lengthComputable;
    }
    get loaded() {
      return e.brandCheck(this, t), this[A].loaded;
    }
    get total() {
      return e.brandCheck(this, t), this[A].total;
    }
  }
  return e.converters.ProgressEventInit = e.dictionaryConverter([
    {
      key: "lengthComputable",
      converter: e.converters.boolean,
      defaultValue: !1
    },
    {
      key: "loaded",
      converter: e.converters["unsigned long long"],
      defaultValue: 0
    },
    {
      key: "total",
      converter: e.converters["unsigned long long"],
      defaultValue: 0
    },
    {
      key: "bubbles",
      converter: e.converters.boolean,
      defaultValue: !1
    },
    {
      key: "cancelable",
      converter: e.converters.boolean,
      defaultValue: !1
    },
    {
      key: "composed",
      converter: e.converters.boolean,
      defaultValue: !1
    }
  ]), hn = {
    ProgressEvent: t
  }, hn;
}
var dn, Lc;
function rp() {
  if (Lc) return dn;
  Lc = 1;
  function e(A) {
    if (!A)
      return "failure";
    switch (A.trim().toLowerCase()) {
      case "unicode-1-1-utf-8":
      case "unicode11utf8":
      case "unicode20utf8":
      case "utf-8":
      case "utf8":
      case "x-unicode20utf8":
        return "UTF-8";
      case "866":
      case "cp866":
      case "csibm866":
      case "ibm866":
        return "IBM866";
      case "csisolatin2":
      case "iso-8859-2":
      case "iso-ir-101":
      case "iso8859-2":
      case "iso88592":
      case "iso_8859-2":
      case "iso_8859-2:1987":
      case "l2":
      case "latin2":
        return "ISO-8859-2";
      case "csisolatin3":
      case "iso-8859-3":
      case "iso-ir-109":
      case "iso8859-3":
      case "iso88593":
      case "iso_8859-3":
      case "iso_8859-3:1988":
      case "l3":
      case "latin3":
        return "ISO-8859-3";
      case "csisolatin4":
      case "iso-8859-4":
      case "iso-ir-110":
      case "iso8859-4":
      case "iso88594":
      case "iso_8859-4":
      case "iso_8859-4:1988":
      case "l4":
      case "latin4":
        return "ISO-8859-4";
      case "csisolatincyrillic":
      case "cyrillic":
      case "iso-8859-5":
      case "iso-ir-144":
      case "iso8859-5":
      case "iso88595":
      case "iso_8859-5":
      case "iso_8859-5:1988":
        return "ISO-8859-5";
      case "arabic":
      case "asmo-708":
      case "csiso88596e":
      case "csiso88596i":
      case "csisolatinarabic":
      case "ecma-114":
      case "iso-8859-6":
      case "iso-8859-6-e":
      case "iso-8859-6-i":
      case "iso-ir-127":
      case "iso8859-6":
      case "iso88596":
      case "iso_8859-6":
      case "iso_8859-6:1987":
        return "ISO-8859-6";
      case "csisolatingreek":
      case "ecma-118":
      case "elot_928":
      case "greek":
      case "greek8":
      case "iso-8859-7":
      case "iso-ir-126":
      case "iso8859-7":
      case "iso88597":
      case "iso_8859-7":
      case "iso_8859-7:1987":
      case "sun_eu_greek":
        return "ISO-8859-7";
      case "csiso88598e":
      case "csisolatinhebrew":
      case "hebrew":
      case "iso-8859-8":
      case "iso-8859-8-e":
      case "iso-ir-138":
      case "iso8859-8":
      case "iso88598":
      case "iso_8859-8":
      case "iso_8859-8:1988":
      case "visual":
        return "ISO-8859-8";
      case "csiso88598i":
      case "iso-8859-8-i":
      case "logical":
        return "ISO-8859-8-I";
      case "csisolatin6":
      case "iso-8859-10":
      case "iso-ir-157":
      case "iso8859-10":
      case "iso885910":
      case "l6":
      case "latin6":
        return "ISO-8859-10";
      case "iso-8859-13":
      case "iso8859-13":
      case "iso885913":
        return "ISO-8859-13";
      case "iso-8859-14":
      case "iso8859-14":
      case "iso885914":
        return "ISO-8859-14";
      case "csisolatin9":
      case "iso-8859-15":
      case "iso8859-15":
      case "iso885915":
      case "iso_8859-15":
      case "l9":
        return "ISO-8859-15";
      case "iso-8859-16":
        return "ISO-8859-16";
      case "cskoi8r":
      case "koi":
      case "koi8":
      case "koi8-r":
      case "koi8_r":
        return "KOI8-R";
      case "koi8-ru":
      case "koi8-u":
        return "KOI8-U";
      case "csmacintosh":
      case "mac":
      case "macintosh":
      case "x-mac-roman":
        return "macintosh";
      case "iso-8859-11":
      case "iso8859-11":
      case "iso885911":
      case "tis-620":
      case "windows-874":
        return "windows-874";
      case "cp1250":
      case "windows-1250":
      case "x-cp1250":
        return "windows-1250";
      case "cp1251":
      case "windows-1251":
      case "x-cp1251":
        return "windows-1251";
      case "ansi_x3.4-1968":
      case "ascii":
      case "cp1252":
      case "cp819":
      case "csisolatin1":
      case "ibm819":
      case "iso-8859-1":
      case "iso-ir-100":
      case "iso8859-1":
      case "iso88591":
      case "iso_8859-1":
      case "iso_8859-1:1987":
      case "l1":
      case "latin1":
      case "us-ascii":
      case "windows-1252":
      case "x-cp1252":
        return "windows-1252";
      case "cp1253":
      case "windows-1253":
      case "x-cp1253":
        return "windows-1253";
      case "cp1254":
      case "csisolatin5":
      case "iso-8859-9":
      case "iso-ir-148":
      case "iso8859-9":
      case "iso88599":
      case "iso_8859-9":
      case "iso_8859-9:1989":
      case "l5":
      case "latin5":
      case "windows-1254":
      case "x-cp1254":
        return "windows-1254";
      case "cp1255":
      case "windows-1255":
      case "x-cp1255":
        return "windows-1255";
      case "cp1256":
      case "windows-1256":
      case "x-cp1256":
        return "windows-1256";
      case "cp1257":
      case "windows-1257":
      case "x-cp1257":
        return "windows-1257";
      case "cp1258":
      case "windows-1258":
      case "x-cp1258":
        return "windows-1258";
      case "x-mac-cyrillic":
      case "x-mac-ukrainian":
        return "x-mac-cyrillic";
      case "chinese":
      case "csgb2312":
      case "csiso58gb231280":
      case "gb2312":
      case "gb_2312":
      case "gb_2312-80":
      case "gbk":
      case "iso-ir-58":
      case "x-gbk":
        return "GBK";
      case "gb18030":
        return "gb18030";
      case "big5":
      case "big5-hkscs":
      case "cn-big5":
      case "csbig5":
      case "x-x-big5":
        return "Big5";
      case "cseucpkdfmtjapanese":
      case "euc-jp":
      case "x-euc-jp":
        return "EUC-JP";
      case "csiso2022jp":
      case "iso-2022-jp":
        return "ISO-2022-JP";
      case "csshiftjis":
      case "ms932":
      case "ms_kanji":
      case "shift-jis":
      case "shift_jis":
      case "sjis":
      case "windows-31j":
      case "x-sjis":
        return "Shift_JIS";
      case "cseuckr":
      case "csksc56011987":
      case "euc-kr":
      case "iso-ir-149":
      case "korean":
      case "ks_c_5601-1987":
      case "ks_c_5601-1989":
      case "ksc5601":
      case "ksc_5601":
      case "windows-949":
        return "EUC-KR";
      case "csiso2022kr":
      case "hz-gb-2312":
      case "iso-2022-cn":
      case "iso-2022-cn-ext":
      case "iso-2022-kr":
      case "replacement":
        return "replacement";
      case "unicodefffe":
      case "utf-16be":
        return "UTF-16BE";
      case "csunicode":
      case "iso-10646-ucs-2":
      case "ucs-2":
      case "unicode":
      case "unicodefeff":
      case "utf-16":
      case "utf-16le":
        return "UTF-16LE";
      case "x-user-defined":
        return "x-user-defined";
      default:
        return "failure";
    }
  }
  return dn = {
    getEncoding: e
  }, dn;
}
var Qn, Mc;
function sp() {
  if (Mc) return Qn;
  Mc = 1;
  const {
    kState: e,
    kError: A,
    kResult: t,
    kAborted: r,
    kLastProgressEventFired: s
  } = NE(), { ProgressEvent: o } = tp(), { getEncoding: n } = rp(), { DOMException: i } = _t(), { serializeAMimeType: a, parseMIMEType: g } = MA(), { types: c } = LA, { StringDecoder: E } = Zg, { btoa: l } = Gt, Q = {
    enumerable: !0,
    writable: !1,
    configurable: !1
  };
  function I(m, f, y, b) {
    if (m[e] === "loading")
      throw new i("Invalid state", "InvalidStateError");
    m[e] = "loading", m[t] = null, m[A] = null;
    const S = f.stream().getReader(), v = [];
    let N = S.read(), F = !0;
    (async () => {
      for (; !m[r]; )
        try {
          const { done: j, value: M } = await N;
          if (F && !m[r] && queueMicrotask(() => {
            d("loadstart", m);
          }), F = !1, !j && c.isUint8Array(M))
            v.push(M), (m[s] === void 0 || Date.now() - m[s] >= 50) && !m[r] && (m[s] = Date.now(), queueMicrotask(() => {
              d("progress", m);
            })), N = S.read();
          else if (j) {
            queueMicrotask(() => {
              m[e] = "done";
              try {
                const K = h(v, y, f.type, b);
                if (m[r])
                  return;
                m[t] = K, d("load", m);
              } catch (K) {
                m[A] = K, d("error", m);
              }
              m[e] !== "loading" && d("loadend", m);
            });
            break;
          }
        } catch (j) {
          if (m[r])
            return;
          queueMicrotask(() => {
            m[e] = "done", m[A] = j, d("error", m), m[e] !== "loading" && d("loadend", m);
          });
          break;
        }
    })();
  }
  function d(m, f) {
    const y = new o(m, {
      bubbles: !1,
      cancelable: !1
    });
    f.dispatchEvent(y);
  }
  function h(m, f, y, b) {
    switch (f) {
      case "DataURL": {
        let w = "data:";
        const S = g(y || "application/octet-stream");
        S !== "failure" && (w += a(S)), w += ";base64,";
        const v = new E("latin1");
        for (const N of m)
          w += l(v.write(N));
        return w += l(v.end()), w;
      }
      case "Text": {
        let w = "failure";
        if (b && (w = n(b)), w === "failure" && y) {
          const S = g(y);
          S !== "failure" && (w = n(S.parameters.get("charset")));
        }
        return w === "failure" && (w = "UTF-8"), C(m, w);
      }
      case "ArrayBuffer":
        return B(m).buffer;
      case "BinaryString": {
        let w = "";
        const S = new E("latin1");
        for (const v of m)
          w += S.write(v);
        return w += S.end(), w;
      }
    }
  }
  function C(m, f) {
    const y = B(m), b = u(y);
    let w = 0;
    b !== null && (f = b, w = b === "UTF-8" ? 3 : 2);
    const S = y.slice(w);
    return new TextDecoder(f).decode(S);
  }
  function u(m) {
    const [f, y, b] = m;
    return f === 239 && y === 187 && b === 191 ? "UTF-8" : f === 254 && y === 255 ? "UTF-16BE" : f === 255 && y === 254 ? "UTF-16LE" : null;
  }
  function B(m) {
    const f = m.reduce((b, w) => b + w.byteLength, 0);
    let y = 0;
    return m.reduce((b, w) => (b.set(w, y), y += w.byteLength, b), new Uint8Array(f));
  }
  return Qn = {
    staticPropertyDescriptors: Q,
    readOperation: I,
    fireAProgressEvent: d
  }, Qn;
}
var Cn, Oc;
function op() {
  if (Oc) return Cn;
  Oc = 1;
  const {
    staticPropertyDescriptors: e,
    readOperation: A,
    fireAProgressEvent: t
  } = sp(), {
    kState: r,
    kError: s,
    kResult: o,
    kEvents: n,
    kAborted: i
  } = NE(), { webidl: a } = hA(), { kEnumerableProperty: g } = we;
  class c extends EventTarget {
    constructor() {
      super(), this[r] = "empty", this[o] = null, this[s] = null, this[n] = {
        loadend: null,
        error: null,
        abort: null,
        load: null,
        progress: null,
        loadstart: null
      };
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dfn-readAsArrayBuffer
     * @param {import('buffer').Blob} blob
     */
    readAsArrayBuffer(l) {
      a.brandCheck(this, c), a.argumentLengthCheck(arguments, 1, { header: "FileReader.readAsArrayBuffer" }), l = a.converters.Blob(l, { strict: !1 }), A(this, l, "ArrayBuffer");
    }
    /**
     * @see https://w3c.github.io/FileAPI/#readAsBinaryString
     * @param {import('buffer').Blob} blob
     */
    readAsBinaryString(l) {
      a.brandCheck(this, c), a.argumentLengthCheck(arguments, 1, { header: "FileReader.readAsBinaryString" }), l = a.converters.Blob(l, { strict: !1 }), A(this, l, "BinaryString");
    }
    /**
     * @see https://w3c.github.io/FileAPI/#readAsDataText
     * @param {import('buffer').Blob} blob
     * @param {string?} encoding
     */
    readAsText(l, Q = void 0) {
      a.brandCheck(this, c), a.argumentLengthCheck(arguments, 1, { header: "FileReader.readAsText" }), l = a.converters.Blob(l, { strict: !1 }), Q !== void 0 && (Q = a.converters.DOMString(Q)), A(this, l, "Text", Q);
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dfn-readAsDataURL
     * @param {import('buffer').Blob} blob
     */
    readAsDataURL(l) {
      a.brandCheck(this, c), a.argumentLengthCheck(arguments, 1, { header: "FileReader.readAsDataURL" }), l = a.converters.Blob(l, { strict: !1 }), A(this, l, "DataURL");
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dfn-abort
     */
    abort() {
      if (this[r] === "empty" || this[r] === "done") {
        this[o] = null;
        return;
      }
      this[r] === "loading" && (this[r] = "done", this[o] = null), this[i] = !0, t("abort", this), this[r] !== "loading" && t("loadend", this);
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dom-filereader-readystate
     */
    get readyState() {
      switch (a.brandCheck(this, c), this[r]) {
        case "empty":
          return this.EMPTY;
        case "loading":
          return this.LOADING;
        case "done":
          return this.DONE;
      }
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dom-filereader-result
     */
    get result() {
      return a.brandCheck(this, c), this[o];
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dom-filereader-error
     */
    get error() {
      return a.brandCheck(this, c), this[s];
    }
    get onloadend() {
      return a.brandCheck(this, c), this[n].loadend;
    }
    set onloadend(l) {
      a.brandCheck(this, c), this[n].loadend && this.removeEventListener("loadend", this[n].loadend), typeof l == "function" ? (this[n].loadend = l, this.addEventListener("loadend", l)) : this[n].loadend = null;
    }
    get onerror() {
      return a.brandCheck(this, c), this[n].error;
    }
    set onerror(l) {
      a.brandCheck(this, c), this[n].error && this.removeEventListener("error", this[n].error), typeof l == "function" ? (this[n].error = l, this.addEventListener("error", l)) : this[n].error = null;
    }
    get onloadstart() {
      return a.brandCheck(this, c), this[n].loadstart;
    }
    set onloadstart(l) {
      a.brandCheck(this, c), this[n].loadstart && this.removeEventListener("loadstart", this[n].loadstart), typeof l == "function" ? (this[n].loadstart = l, this.addEventListener("loadstart", l)) : this[n].loadstart = null;
    }
    get onprogress() {
      return a.brandCheck(this, c), this[n].progress;
    }
    set onprogress(l) {
      a.brandCheck(this, c), this[n].progress && this.removeEventListener("progress", this[n].progress), typeof l == "function" ? (this[n].progress = l, this.addEventListener("progress", l)) : this[n].progress = null;
    }
    get onload() {
      return a.brandCheck(this, c), this[n].load;
    }
    set onload(l) {
      a.brandCheck(this, c), this[n].load && this.removeEventListener("load", this[n].load), typeof l == "function" ? (this[n].load = l, this.addEventListener("load", l)) : this[n].load = null;
    }
    get onabort() {
      return a.brandCheck(this, c), this[n].abort;
    }
    set onabort(l) {
      a.brandCheck(this, c), this[n].abort && this.removeEventListener("abort", this[n].abort), typeof l == "function" ? (this[n].abort = l, this.addEventListener("abort", l)) : this[n].abort = null;
    }
  }
  return c.EMPTY = c.prototype.EMPTY = 0, c.LOADING = c.prototype.LOADING = 1, c.DONE = c.prototype.DONE = 2, Object.defineProperties(c.prototype, {
    EMPTY: e,
    LOADING: e,
    DONE: e,
    readAsArrayBuffer: g,
    readAsBinaryString: g,
    readAsText: g,
    readAsDataURL: g,
    abort: g,
    readyState: g,
    result: g,
    error: g,
    onloadstart: g,
    onprogress: g,
    onload: g,
    onabort: g,
    onerror: g,
    onloadend: g,
    [Symbol.toStringTag]: {
      value: "FileReader",
      writable: !1,
      enumerable: !1,
      configurable: !0
    }
  }), Object.defineProperties(c, {
    EMPTY: e,
    LOADING: e,
    DONE: e
  }), Cn = {
    FileReader: c
  }, Cn;
}
var Bn, Pc;
function ki() {
  return Pc || (Pc = 1, Bn = {
    kConstruct: Se.kConstruct
  }), Bn;
}
var In, Yc;
function np() {
  if (Yc) return In;
  Yc = 1;
  const e = Me, { URLSerializer: A } = MA(), { isValidHeaderName: t } = TA();
  function r(o, n, i = !1) {
    const a = A(o, i), g = A(n, i);
    return a === g;
  }
  function s(o) {
    e(o !== null);
    const n = [];
    for (let i of o.split(",")) {
      if (i = i.trim(), i.length) {
        if (!t(i))
          continue;
      } else continue;
      n.push(i);
    }
    return n;
  }
  return In = {
    urlEquals: r,
    fieldValues: s
  }, In;
}
var pn, xc;
function ip() {
  if (xc) return pn;
  xc = 1;
  const { kConstruct: e } = ki(), { urlEquals: A, fieldValues: t } = np(), { kEnumerableProperty: r, isDisturbed: s } = we, { kHeadersList: o } = Se, { webidl: n } = hA(), { Response: i, cloneResponse: a } = Di(), { Request: g } = Zs(), { kState: c, kHeaders: E, kGuard: l, kRealm: Q } = Et(), { fetching: I } = Ti(), { urlIsHttpHttpsScheme: d, createDeferredPromise: h, readAllBytes: C } = TA(), u = Me, { getGlobalDispatcher: B } = Zr;
  class m {
    /**
     * @see https://w3c.github.io/ServiceWorker/#dfn-relevant-request-response-list
     * @type {requestResponseList}
     */
    #e;
    constructor() {
      arguments[0] !== e && n.illegalConstructor(), this.#e = arguments[1];
    }
    async match(b, w = {}) {
      n.brandCheck(this, m), n.argumentLengthCheck(arguments, 1, { header: "Cache.match" }), b = n.converters.RequestInfo(b), w = n.converters.CacheQueryOptions(w);
      const S = await this.matchAll(b, w);
      if (S.length !== 0)
        return S[0];
    }
    async matchAll(b = void 0, w = {}) {
      n.brandCheck(this, m), b !== void 0 && (b = n.converters.RequestInfo(b)), w = n.converters.CacheQueryOptions(w);
      let S = null;
      if (b !== void 0)
        if (b instanceof g) {
          if (S = b[c], S.method !== "GET" && !w.ignoreMethod)
            return [];
        } else typeof b == "string" && (S = new g(b)[c]);
      const v = [];
      if (b === void 0)
        for (const F of this.#e)
          v.push(F[1]);
      else {
        const F = this.#r(S, w);
        for (const j of F)
          v.push(j[1]);
      }
      const N = [];
      for (const F of v) {
        const j = new i(F.body?.source ?? null), M = j[c].body;
        j[c] = F, j[c].body = M, j[E][o] = F.headersList, j[E][l] = "immutable", N.push(j);
      }
      return Object.freeze(N);
    }
    async add(b) {
      n.brandCheck(this, m), n.argumentLengthCheck(arguments, 1, { header: "Cache.add" }), b = n.converters.RequestInfo(b);
      const w = [b];
      return await this.addAll(w);
    }
    async addAll(b) {
      n.brandCheck(this, m), n.argumentLengthCheck(arguments, 1, { header: "Cache.addAll" }), b = n.converters["sequence<RequestInfo>"](b);
      const w = [], S = [];
      for (const ie of b) {
        if (typeof ie == "string")
          continue;
        const re = ie[c];
        if (!d(re.url) || re.method !== "GET")
          throw n.errors.exception({
            header: "Cache.addAll",
            message: "Expected http/s scheme when method is not GET."
          });
      }
      const v = [];
      for (const ie of b) {
        const re = new g(ie)[c];
        if (!d(re.url))
          throw n.errors.exception({
            header: "Cache.addAll",
            message: "Expected http/s scheme."
          });
        re.initiator = "fetch", re.destination = "subresource", S.push(re);
        const ge = h();
        v.push(I({
          request: re,
          dispatcher: B(),
          processResponse(Y) {
            if (Y.type === "error" || Y.status === 206 || Y.status < 200 || Y.status > 299)
              ge.reject(n.errors.exception({
                header: "Cache.addAll",
                message: "Received an invalid status code or the request failed."
              }));
            else if (Y.headersList.contains("vary")) {
              const Ae = t(Y.headersList.get("vary"));
              for (const ae of Ae)
                if (ae === "*") {
                  ge.reject(n.errors.exception({
                    header: "Cache.addAll",
                    message: "invalid vary field value"
                  }));
                  for (const de of v)
                    de.abort();
                  return;
                }
            }
          },
          processResponseEndOfBody(Y) {
            if (Y.aborted) {
              ge.reject(new DOMException("aborted", "AbortError"));
              return;
            }
            ge.resolve(Y);
          }
        })), w.push(ge.promise);
      }
      const F = await Promise.all(w), j = [];
      let M = 0;
      for (const ie of F) {
        const re = {
          type: "put",
          // 7.3.2
          request: S[M],
          // 7.3.3
          response: ie
          // 7.3.4
        };
        j.push(re), M++;
      }
      const K = h();
      let ee = null;
      try {
        this.#t(j);
      } catch (ie) {
        ee = ie;
      }
      return queueMicrotask(() => {
        ee === null ? K.resolve(void 0) : K.reject(ee);
      }), K.promise;
    }
    async put(b, w) {
      n.brandCheck(this, m), n.argumentLengthCheck(arguments, 2, { header: "Cache.put" }), b = n.converters.RequestInfo(b), w = n.converters.Response(w);
      let S = null;
      if (b instanceof g ? S = b[c] : S = new g(b)[c], !d(S.url) || S.method !== "GET")
        throw n.errors.exception({
          header: "Cache.put",
          message: "Expected an http/s scheme when method is not GET"
        });
      const v = w[c];
      if (v.status === 206)
        throw n.errors.exception({
          header: "Cache.put",
          message: "Got 206 status"
        });
      if (v.headersList.contains("vary")) {
        const re = t(v.headersList.get("vary"));
        for (const ge of re)
          if (ge === "*")
            throw n.errors.exception({
              header: "Cache.put",
              message: "Got * vary field value"
            });
      }
      if (v.body && (s(v.body.stream) || v.body.stream.locked))
        throw n.errors.exception({
          header: "Cache.put",
          message: "Response body is locked or disturbed"
        });
      const N = a(v), F = h();
      if (v.body != null) {
        const ge = v.body.stream.getReader();
        C(ge).then(F.resolve, F.reject);
      } else
        F.resolve(void 0);
      const j = [], M = {
        type: "put",
        // 14.
        request: S,
        // 15.
        response: N
        // 16.
      };
      j.push(M);
      const K = await F.promise;
      N.body != null && (N.body.source = K);
      const ee = h();
      let ie = null;
      try {
        this.#t(j);
      } catch (re) {
        ie = re;
      }
      return queueMicrotask(() => {
        ie === null ? ee.resolve() : ee.reject(ie);
      }), ee.promise;
    }
    async delete(b, w = {}) {
      n.brandCheck(this, m), n.argumentLengthCheck(arguments, 1, { header: "Cache.delete" }), b = n.converters.RequestInfo(b), w = n.converters.CacheQueryOptions(w);
      let S = null;
      if (b instanceof g) {
        if (S = b[c], S.method !== "GET" && !w.ignoreMethod)
          return !1;
      } else
        u(typeof b == "string"), S = new g(b)[c];
      const v = [], N = {
        type: "delete",
        request: S,
        options: w
      };
      v.push(N);
      const F = h();
      let j = null, M;
      try {
        M = this.#t(v);
      } catch (K) {
        j = K;
      }
      return queueMicrotask(() => {
        j === null ? F.resolve(!!M?.length) : F.reject(j);
      }), F.promise;
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#dom-cache-keys
     * @param {any} request
     * @param {import('../../types/cache').CacheQueryOptions} options
     * @returns {readonly Request[]}
     */
    async keys(b = void 0, w = {}) {
      n.brandCheck(this, m), b !== void 0 && (b = n.converters.RequestInfo(b)), w = n.converters.CacheQueryOptions(w);
      let S = null;
      if (b !== void 0)
        if (b instanceof g) {
          if (S = b[c], S.method !== "GET" && !w.ignoreMethod)
            return [];
        } else typeof b == "string" && (S = new g(b)[c]);
      const v = h(), N = [];
      if (b === void 0)
        for (const F of this.#e)
          N.push(F[0]);
      else {
        const F = this.#r(S, w);
        for (const j of F)
          N.push(j[0]);
      }
      return queueMicrotask(() => {
        const F = [];
        for (const j of N) {
          const M = new g("https://a");
          M[c] = j, M[E][o] = j.headersList, M[E][l] = "immutable", M[Q] = j.client, F.push(M);
        }
        v.resolve(Object.freeze(F));
      }), v.promise;
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#batch-cache-operations-algorithm
     * @param {CacheBatchOperation[]} operations
     * @returns {requestResponseList}
     */
    #t(b) {
      const w = this.#e, S = [...w], v = [], N = [];
      try {
        for (const F of b) {
          if (F.type !== "delete" && F.type !== "put")
            throw n.errors.exception({
              header: "Cache.#batchCacheOperations",
              message: 'operation type does not match "delete" or "put"'
            });
          if (F.type === "delete" && F.response != null)
            throw n.errors.exception({
              header: "Cache.#batchCacheOperations",
              message: "delete operation should not have an associated response"
            });
          if (this.#r(F.request, F.options, v).length)
            throw new DOMException("???", "InvalidStateError");
          let j;
          if (F.type === "delete") {
            if (j = this.#r(F.request, F.options), j.length === 0)
              return [];
            for (const M of j) {
              const K = w.indexOf(M);
              u(K !== -1), w.splice(K, 1);
            }
          } else if (F.type === "put") {
            if (F.response == null)
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "put operation should have an associated response"
              });
            const M = F.request;
            if (!d(M.url))
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "expected http or https scheme"
              });
            if (M.method !== "GET")
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "not get method"
              });
            if (F.options != null)
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "options must not be defined"
              });
            j = this.#r(F.request);
            for (const K of j) {
              const ee = w.indexOf(K);
              u(ee !== -1), w.splice(ee, 1);
            }
            w.push([F.request, F.response]), v.push([F.request, F.response]);
          }
          N.push([F.request, F.response]);
        }
        return N;
      } catch (F) {
        throw this.#e.length = 0, this.#e = S, F;
      }
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#query-cache
     * @param {any} requestQuery
     * @param {import('../../types/cache').CacheQueryOptions} options
     * @param {requestResponseList} targetStorage
     * @returns {requestResponseList}
     */
    #r(b, w, S) {
      const v = [], N = S ?? this.#e;
      for (const F of N) {
        const [j, M] = F;
        this.#A(b, j, M, w) && v.push(F);
      }
      return v;
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#request-matches-cached-item-algorithm
     * @param {any} requestQuery
     * @param {any} request
     * @param {any | null} response
     * @param {import('../../types/cache').CacheQueryOptions | undefined} options
     * @returns {boolean}
     */
    #A(b, w, S = null, v) {
      const N = new URL(b.url), F = new URL(w.url);
      if (v?.ignoreSearch && (F.search = "", N.search = ""), !A(N, F, !0))
        return !1;
      if (S == null || v?.ignoreVary || !S.headersList.contains("vary"))
        return !0;
      const j = t(S.headersList.get("vary"));
      for (const M of j) {
        if (M === "*")
          return !1;
        const K = w.headersList.get(M), ee = b.headersList.get(M);
        if (K !== ee)
          return !1;
      }
      return !0;
    }
  }
  Object.defineProperties(m.prototype, {
    [Symbol.toStringTag]: {
      value: "Cache",
      configurable: !0
    },
    match: r,
    matchAll: r,
    add: r,
    addAll: r,
    put: r,
    delete: r,
    keys: r
  });
  const f = [
    {
      key: "ignoreSearch",
      converter: n.converters.boolean,
      defaultValue: !1
    },
    {
      key: "ignoreMethod",
      converter: n.converters.boolean,
      defaultValue: !1
    },
    {
      key: "ignoreVary",
      converter: n.converters.boolean,
      defaultValue: !1
    }
  ];
  return n.converters.CacheQueryOptions = n.dictionaryConverter(f), n.converters.MultiCacheQueryOptions = n.dictionaryConverter([
    ...f,
    {
      key: "cacheName",
      converter: n.converters.DOMString
    }
  ]), n.converters.Response = n.interfaceConverter(i), n.converters["sequence<RequestInfo>"] = n.sequenceConverter(
    n.converters.RequestInfo
  ), pn = {
    Cache: m
  }, pn;
}
var fn, Jc;
function ap() {
  if (Jc) return fn;
  Jc = 1;
  const { kConstruct: e } = ki(), { Cache: A } = ip(), { webidl: t } = hA(), { kEnumerableProperty: r } = we;
  class s {
    /**
     * @see https://w3c.github.io/ServiceWorker/#dfn-relevant-name-to-cache-map
     * @type {Map<string, import('./cache').requestResponseList}
     */
    #e = /* @__PURE__ */ new Map();
    constructor() {
      arguments[0] !== e && t.illegalConstructor();
    }
    async match(n, i = {}) {
      if (t.brandCheck(this, s), t.argumentLengthCheck(arguments, 1, { header: "CacheStorage.match" }), n = t.converters.RequestInfo(n), i = t.converters.MultiCacheQueryOptions(i), i.cacheName != null) {
        if (this.#e.has(i.cacheName)) {
          const a = this.#e.get(i.cacheName);
          return await new A(e, a).match(n, i);
        }
      } else
        for (const a of this.#e.values()) {
          const c = await new A(e, a).match(n, i);
          if (c !== void 0)
            return c;
        }
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#cache-storage-has
     * @param {string} cacheName
     * @returns {Promise<boolean>}
     */
    async has(n) {
      return t.brandCheck(this, s), t.argumentLengthCheck(arguments, 1, { header: "CacheStorage.has" }), n = t.converters.DOMString(n), this.#e.has(n);
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#dom-cachestorage-open
     * @param {string} cacheName
     * @returns {Promise<Cache>}
     */
    async open(n) {
      if (t.brandCheck(this, s), t.argumentLengthCheck(arguments, 1, { header: "CacheStorage.open" }), n = t.converters.DOMString(n), this.#e.has(n)) {
        const a = this.#e.get(n);
        return new A(e, a);
      }
      const i = [];
      return this.#e.set(n, i), new A(e, i);
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#cache-storage-delete
     * @param {string} cacheName
     * @returns {Promise<boolean>}
     */
    async delete(n) {
      return t.brandCheck(this, s), t.argumentLengthCheck(arguments, 1, { header: "CacheStorage.delete" }), n = t.converters.DOMString(n), this.#e.delete(n);
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#cache-storage-keys
     * @returns {string[]}
     */
    async keys() {
      return t.brandCheck(this, s), [...this.#e.keys()];
    }
  }
  return Object.defineProperties(s.prototype, {
    [Symbol.toStringTag]: {
      value: "CacheStorage",
      configurable: !0
    },
    match: r,
    has: r,
    open: r,
    delete: r,
    keys: r
  }), fn = {
    CacheStorage: s
  }, fn;
}
var mn, Hc;
function cp() {
  return Hc || (Hc = 1, mn = {
    maxAttributeValueSize: 1024,
    maxNameValuePairSize: 4096
  }), mn;
}
var wn, Vc;
function vE() {
  if (Vc) return wn;
  Vc = 1;
  const e = Me, { kHeadersList: A } = Se;
  function t(l) {
    if (l.length === 0)
      return !1;
    for (const Q of l) {
      const I = Q.charCodeAt(0);
      if (I >= 0 || I <= 8 || I >= 10 || I <= 31 || I === 127)
        return !1;
    }
  }
  function r(l) {
    for (const Q of l) {
      const I = Q.charCodeAt(0);
      if (I <= 32 || I > 127 || Q === "(" || Q === ")" || Q === ">" || Q === "<" || Q === "@" || Q === "," || Q === ";" || Q === ":" || Q === "\\" || Q === '"' || Q === "/" || Q === "[" || Q === "]" || Q === "?" || Q === "=" || Q === "{" || Q === "}")
        throw new Error("Invalid cookie name");
    }
  }
  function s(l) {
    for (const Q of l) {
      const I = Q.charCodeAt(0);
      if (I < 33 || // exclude CTLs (0-31)
      I === 34 || I === 44 || I === 59 || I === 92 || I > 126)
        throw new Error("Invalid header value");
    }
  }
  function o(l) {
    for (const Q of l)
      if (Q.charCodeAt(0) < 33 || Q === ";")
        throw new Error("Invalid cookie path");
  }
  function n(l) {
    if (l.startsWith("-") || l.endsWith(".") || l.endsWith("-"))
      throw new Error("Invalid cookie domain");
  }
  function i(l) {
    typeof l == "number" && (l = new Date(l));
    const Q = [
      "Sun",
      "Mon",
      "Tue",
      "Wed",
      "Thu",
      "Fri",
      "Sat"
    ], I = [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec"
    ], d = Q[l.getUTCDay()], h = l.getUTCDate().toString().padStart(2, "0"), C = I[l.getUTCMonth()], u = l.getUTCFullYear(), B = l.getUTCHours().toString().padStart(2, "0"), m = l.getUTCMinutes().toString().padStart(2, "0"), f = l.getUTCSeconds().toString().padStart(2, "0");
    return `${d}, ${h} ${C} ${u} ${B}:${m}:${f} GMT`;
  }
  function a(l) {
    if (l < 0)
      throw new Error("Invalid cookie max-age");
  }
  function g(l) {
    if (l.name.length === 0)
      return null;
    r(l.name), s(l.value);
    const Q = [`${l.name}=${l.value}`];
    l.name.startsWith("__Secure-") && (l.secure = !0), l.name.startsWith("__Host-") && (l.secure = !0, l.domain = null, l.path = "/"), l.secure && Q.push("Secure"), l.httpOnly && Q.push("HttpOnly"), typeof l.maxAge == "number" && (a(l.maxAge), Q.push(`Max-Age=${l.maxAge}`)), l.domain && (n(l.domain), Q.push(`Domain=${l.domain}`)), l.path && (o(l.path), Q.push(`Path=${l.path}`)), l.expires && l.expires.toString() !== "Invalid Date" && Q.push(`Expires=${i(l.expires)}`), l.sameSite && Q.push(`SameSite=${l.sameSite}`);
    for (const I of l.unparsed) {
      if (!I.includes("="))
        throw new Error("Invalid unparsed");
      const [d, ...h] = I.split("=");
      Q.push(`${d.trim()}=${h.join("=")}`);
    }
    return Q.join("; ");
  }
  let c;
  function E(l) {
    if (l[A])
      return l[A];
    c || (c = Object.getOwnPropertySymbols(l).find(
      (I) => I.description === "headers list"
    ), e(c, "Headers cannot be parsed"));
    const Q = l[c];
    return e(Q), Q;
  }
  return wn = {
    isCTLExcludingHtab: t,
    stringify: g,
    getHeadersList: E
  }, wn;
}
var yn, qc;
function gp() {
  if (qc) return yn;
  qc = 1;
  const { maxNameValuePairSize: e, maxAttributeValueSize: A } = cp(), { isCTLExcludingHtab: t } = vE(), { collectASequenceOfCodePointsFast: r } = MA(), s = Me;
  function o(i) {
    if (t(i))
      return null;
    let a = "", g = "", c = "", E = "";
    if (i.includes(";")) {
      const l = { position: 0 };
      a = r(";", i, l), g = i.slice(l.position);
    } else
      a = i;
    if (!a.includes("="))
      E = a;
    else {
      const l = { position: 0 };
      c = r(
        "=",
        a,
        l
      ), E = a.slice(l.position + 1);
    }
    return c = c.trim(), E = E.trim(), c.length + E.length > e ? null : {
      name: c,
      value: E,
      ...n(g)
    };
  }
  function n(i, a = {}) {
    if (i.length === 0)
      return a;
    s(i[0] === ";"), i = i.slice(1);
    let g = "";
    i.includes(";") ? (g = r(
      ";",
      i,
      { position: 0 }
    ), i = i.slice(g.length)) : (g = i, i = "");
    let c = "", E = "";
    if (g.includes("=")) {
      const Q = { position: 0 };
      c = r(
        "=",
        g,
        Q
      ), E = g.slice(Q.position + 1);
    } else
      c = g;
    if (c = c.trim(), E = E.trim(), E.length > A)
      return n(i, a);
    const l = c.toLowerCase();
    if (l === "expires") {
      const Q = new Date(E);
      a.expires = Q;
    } else if (l === "max-age") {
      const Q = E.charCodeAt(0);
      if ((Q < 48 || Q > 57) && E[0] !== "-" || !/^\d+$/.test(E))
        return n(i, a);
      const I = Number(E);
      a.maxAge = I;
    } else if (l === "domain") {
      let Q = E;
      Q[0] === "." && (Q = Q.slice(1)), Q = Q.toLowerCase(), a.domain = Q;
    } else if (l === "path") {
      let Q = "";
      E.length === 0 || E[0] !== "/" ? Q = "/" : Q = E, a.path = Q;
    } else if (l === "secure")
      a.secure = !0;
    else if (l === "httponly")
      a.httpOnly = !0;
    else if (l === "samesite") {
      let Q = "Default";
      const I = E.toLowerCase();
      I.includes("none") && (Q = "None"), I.includes("strict") && (Q = "Strict"), I.includes("lax") && (Q = "Lax"), a.sameSite = Q;
    } else
      a.unparsed ??= [], a.unparsed.push(`${c}=${E}`);
    return n(i, a);
  }
  return yn = {
    parseSetCookie: o,
    parseUnparsedAttributes: n
  }, yn;
}
var bn, Wc;
function lp() {
  if (Wc) return bn;
  Wc = 1;
  const { parseSetCookie: e } = gp(), { stringify: A, getHeadersList: t } = vE(), { webidl: r } = hA(), { Headers: s } = gr();
  function o(g) {
    r.argumentLengthCheck(arguments, 1, { header: "getCookies" }), r.brandCheck(g, s, { strict: !1 });
    const c = g.get("cookie"), E = {};
    if (!c)
      return E;
    for (const l of c.split(";")) {
      const [Q, ...I] = l.split("=");
      E[Q.trim()] = I.join("=");
    }
    return E;
  }
  function n(g, c, E) {
    r.argumentLengthCheck(arguments, 2, { header: "deleteCookie" }), r.brandCheck(g, s, { strict: !1 }), c = r.converters.DOMString(c), E = r.converters.DeleteCookieAttributes(E), a(g, {
      name: c,
      value: "",
      expires: /* @__PURE__ */ new Date(0),
      ...E
    });
  }
  function i(g) {
    r.argumentLengthCheck(arguments, 1, { header: "getSetCookies" }), r.brandCheck(g, s, { strict: !1 });
    const c = t(g).cookies;
    return c ? c.map((E) => e(Array.isArray(E) ? E[1] : E)) : [];
  }
  function a(g, c) {
    r.argumentLengthCheck(arguments, 2, { header: "setCookie" }), r.brandCheck(g, s, { strict: !1 }), c = r.converters.Cookie(c), A(c) && g.append("Set-Cookie", A(c));
  }
  return r.converters.DeleteCookieAttributes = r.dictionaryConverter([
    {
      converter: r.nullableConverter(r.converters.DOMString),
      key: "path",
      defaultValue: null
    },
    {
      converter: r.nullableConverter(r.converters.DOMString),
      key: "domain",
      defaultValue: null
    }
  ]), r.converters.Cookie = r.dictionaryConverter([
    {
      converter: r.converters.DOMString,
      key: "name"
    },
    {
      converter: r.converters.DOMString,
      key: "value"
    },
    {
      converter: r.nullableConverter((g) => typeof g == "number" ? r.converters["unsigned long long"](g) : new Date(g)),
      key: "expires",
      defaultValue: null
    },
    {
      converter: r.nullableConverter(r.converters["long long"]),
      key: "maxAge",
      defaultValue: null
    },
    {
      converter: r.nullableConverter(r.converters.DOMString),
      key: "domain",
      defaultValue: null
    },
    {
      converter: r.nullableConverter(r.converters.DOMString),
      key: "path",
      defaultValue: null
    },
    {
      converter: r.nullableConverter(r.converters.boolean),
      key: "secure",
      defaultValue: null
    },
    {
      converter: r.nullableConverter(r.converters.boolean),
      key: "httpOnly",
      defaultValue: null
    },
    {
      converter: r.converters.USVString,
      key: "sameSite",
      allowedValues: ["Strict", "Lax", "None"]
    },
    {
      converter: r.sequenceConverter(r.converters.DOMString),
      key: "unparsed",
      defaultValue: []
    }
  ]), bn = {
    getCookies: o,
    deleteCookie: n,
    getSetCookies: i,
    setCookie: a
  }, bn;
}
var Rn, jc;
function Xr() {
  if (jc) return Rn;
  jc = 1;
  const e = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", A = {
    enumerable: !0,
    writable: !1,
    configurable: !1
  }, t = {
    CONNECTING: 0,
    OPEN: 1,
    CLOSING: 2,
    CLOSED: 3
  }, r = {
    CONTINUATION: 0,
    TEXT: 1,
    BINARY: 2,
    CLOSE: 8,
    PING: 9,
    PONG: 10
  }, s = 2 ** 16 - 1, o = {
    INFO: 0,
    PAYLOADLENGTH_16: 2,
    PAYLOADLENGTH_64: 3,
    READ_DATA: 4
  }, n = Buffer.allocUnsafe(0);
  return Rn = {
    uid: e,
    staticPropertyDescriptors: A,
    states: t,
    opcodes: r,
    maxUnsigned16Bit: s,
    parserStates: o,
    emptyBuffer: n
  }, Rn;
}
var Dn, $c;
function Xs() {
  return $c || ($c = 1, Dn = {
    kWebSocketURL: Symbol("url"),
    kReadyState: Symbol("ready state"),
    kController: Symbol("controller"),
    kResponse: Symbol("response"),
    kBinaryType: Symbol("binary type"),
    kSentClose: Symbol("sent close"),
    kReceivedClose: Symbol("received close"),
    kByteParser: Symbol("byte parser")
  }), Dn;
}
var Tn, Kc;
function LE() {
  if (Kc) return Tn;
  Kc = 1;
  const { webidl: e } = hA(), { kEnumerableProperty: A } = we, { MessagePort: t } = Kg;
  class r extends Event {
    #e;
    constructor(a, g = {}) {
      e.argumentLengthCheck(arguments, 1, { header: "MessageEvent constructor" }), a = e.converters.DOMString(a), g = e.converters.MessageEventInit(g), super(a, g), this.#e = g;
    }
    get data() {
      return e.brandCheck(this, r), this.#e.data;
    }
    get origin() {
      return e.brandCheck(this, r), this.#e.origin;
    }
    get lastEventId() {
      return e.brandCheck(this, r), this.#e.lastEventId;
    }
    get source() {
      return e.brandCheck(this, r), this.#e.source;
    }
    get ports() {
      return e.brandCheck(this, r), Object.isFrozen(this.#e.ports) || Object.freeze(this.#e.ports), this.#e.ports;
    }
    initMessageEvent(a, g = !1, c = !1, E = null, l = "", Q = "", I = null, d = []) {
      return e.brandCheck(this, r), e.argumentLengthCheck(arguments, 1, { header: "MessageEvent.initMessageEvent" }), new r(a, {
        bubbles: g,
        cancelable: c,
        data: E,
        origin: l,
        lastEventId: Q,
        source: I,
        ports: d
      });
    }
  }
  class s extends Event {
    #e;
    constructor(a, g = {}) {
      e.argumentLengthCheck(arguments, 1, { header: "CloseEvent constructor" }), a = e.converters.DOMString(a), g = e.converters.CloseEventInit(g), super(a, g), this.#e = g;
    }
    get wasClean() {
      return e.brandCheck(this, s), this.#e.wasClean;
    }
    get code() {
      return e.brandCheck(this, s), this.#e.code;
    }
    get reason() {
      return e.brandCheck(this, s), this.#e.reason;
    }
  }
  class o extends Event {
    #e;
    constructor(a, g) {
      e.argumentLengthCheck(arguments, 1, { header: "ErrorEvent constructor" }), super(a, g), a = e.converters.DOMString(a), g = e.converters.ErrorEventInit(g ?? {}), this.#e = g;
    }
    get message() {
      return e.brandCheck(this, o), this.#e.message;
    }
    get filename() {
      return e.brandCheck(this, o), this.#e.filename;
    }
    get lineno() {
      return e.brandCheck(this, o), this.#e.lineno;
    }
    get colno() {
      return e.brandCheck(this, o), this.#e.colno;
    }
    get error() {
      return e.brandCheck(this, o), this.#e.error;
    }
  }
  Object.defineProperties(r.prototype, {
    [Symbol.toStringTag]: {
      value: "MessageEvent",
      configurable: !0
    },
    data: A,
    origin: A,
    lastEventId: A,
    source: A,
    ports: A,
    initMessageEvent: A
  }), Object.defineProperties(s.prototype, {
    [Symbol.toStringTag]: {
      value: "CloseEvent",
      configurable: !0
    },
    reason: A,
    code: A,
    wasClean: A
  }), Object.defineProperties(o.prototype, {
    [Symbol.toStringTag]: {
      value: "ErrorEvent",
      configurable: !0
    },
    message: A,
    filename: A,
    lineno: A,
    colno: A,
    error: A
  }), e.converters.MessagePort = e.interfaceConverter(t), e.converters["sequence<MessagePort>"] = e.sequenceConverter(
    e.converters.MessagePort
  );
  const n = [
    {
      key: "bubbles",
      converter: e.converters.boolean,
      defaultValue: !1
    },
    {
      key: "cancelable",
      converter: e.converters.boolean,
      defaultValue: !1
    },
    {
      key: "composed",
      converter: e.converters.boolean,
      defaultValue: !1
    }
  ];
  return e.converters.MessageEventInit = e.dictionaryConverter([
    ...n,
    {
      key: "data",
      converter: e.converters.any,
      defaultValue: null
    },
    {
      key: "origin",
      converter: e.converters.USVString,
      defaultValue: ""
    },
    {
      key: "lastEventId",
      converter: e.converters.DOMString,
      defaultValue: ""
    },
    {
      key: "source",
      // Node doesn't implement WindowProxy or ServiceWorker, so the only
      // valid value for source is a MessagePort.
      converter: e.nullableConverter(e.converters.MessagePort),
      defaultValue: null
    },
    {
      key: "ports",
      converter: e.converters["sequence<MessagePort>"],
      get defaultValue() {
        return [];
      }
    }
  ]), e.converters.CloseEventInit = e.dictionaryConverter([
    ...n,
    {
      key: "wasClean",
      converter: e.converters.boolean,
      defaultValue: !1
    },
    {
      key: "code",
      converter: e.converters["unsigned short"],
      defaultValue: 0
    },
    {
      key: "reason",
      converter: e.converters.USVString,
      defaultValue: ""
    }
  ]), e.converters.ErrorEventInit = e.dictionaryConverter([
    ...n,
    {
      key: "message",
      converter: e.converters.DOMString,
      defaultValue: ""
    },
    {
      key: "filename",
      converter: e.converters.USVString,
      defaultValue: ""
    },
    {
      key: "lineno",
      converter: e.converters["unsigned long"],
      defaultValue: 0
    },
    {
      key: "colno",
      converter: e.converters["unsigned long"],
      defaultValue: 0
    },
    {
      key: "error",
      converter: e.converters.any
    }
  ]), Tn = {
    MessageEvent: r,
    CloseEvent: s,
    ErrorEvent: o
  }, Tn;
}
var kn, zc;
function Fi() {
  if (zc) return kn;
  zc = 1;
  const { kReadyState: e, kController: A, kResponse: t, kBinaryType: r, kWebSocketURL: s } = Xs(), { states: o, opcodes: n } = Xr(), { MessageEvent: i, ErrorEvent: a } = LE();
  function g(C) {
    return C[e] === o.OPEN;
  }
  function c(C) {
    return C[e] === o.CLOSING;
  }
  function E(C) {
    return C[e] === o.CLOSED;
  }
  function l(C, u, B = Event, m) {
    const f = new B(C, m);
    u.dispatchEvent(f);
  }
  function Q(C, u, B) {
    if (C[e] !== o.OPEN)
      return;
    let m;
    if (u === n.TEXT)
      try {
        m = new TextDecoder("utf-8", { fatal: !0 }).decode(B);
      } catch {
        h(C, "Received invalid UTF-8 in text frame.");
        return;
      }
    else u === n.BINARY && (C[r] === "blob" ? m = new Blob([B]) : m = new Uint8Array(B).buffer);
    l("message", C, i, {
      origin: C[s].origin,
      data: m
    });
  }
  function I(C) {
    if (C.length === 0)
      return !1;
    for (const u of C) {
      const B = u.charCodeAt(0);
      if (B < 33 || B > 126 || u === "(" || u === ")" || u === "<" || u === ">" || u === "@" || u === "," || u === ";" || u === ":" || u === "\\" || u === '"' || u === "/" || u === "[" || u === "]" || u === "?" || u === "=" || u === "{" || u === "}" || B === 32 || // SP
      B === 9)
        return !1;
    }
    return !0;
  }
  function d(C) {
    return C >= 1e3 && C < 1015 ? C !== 1004 && // reserved
    C !== 1005 && // "MUST NOT be set as a status code"
    C !== 1006 : C >= 3e3 && C <= 4999;
  }
  function h(C, u) {
    const { [A]: B, [t]: m } = C;
    B.abort(), m?.socket && !m.socket.destroyed && m.socket.destroy(), u && l("error", C, a, {
      error: new Error(u)
    });
  }
  return kn = {
    isEstablished: g,
    isClosing: c,
    isClosed: E,
    fireEvent: l,
    isValidSubprotocol: I,
    isValidStatusCode: d,
    failWebsocketConnection: h,
    websocketMessageReceived: Q
  }, kn;
}
var Fn, Zc;
function Ep() {
  if (Zc) return Fn;
  Zc = 1;
  const e = Xg, { uid: A, states: t } = Xr(), {
    kReadyState: r,
    kSentClose: s,
    kByteParser: o,
    kReceivedClose: n
  } = Xs(), { fireEvent: i, failWebsocketConnection: a } = Fi(), { CloseEvent: g } = LE(), { makeRequest: c } = Zs(), { fetching: E } = Ti(), { Headers: l } = gr(), { getGlobalDispatcher: Q } = Zr, { kHeadersList: I } = Se, d = {};
  d.open = e.channel("undici:websocket:open"), d.close = e.channel("undici:websocket:close"), d.socketError = e.channel("undici:websocket:socket_error");
  let h;
  try {
    h = require("crypto");
  } catch {
  }
  function C(f, y, b, w, S) {
    const v = f;
    v.protocol = f.protocol === "ws:" ? "http:" : "https:";
    const N = c({
      urlList: [v],
      serviceWorkers: "none",
      referrer: "no-referrer",
      mode: "websocket",
      credentials: "include",
      cache: "no-store",
      redirect: "error"
    });
    if (S.headers) {
      const K = new l(S.headers)[I];
      N.headersList = K;
    }
    const F = h.randomBytes(16).toString("base64");
    N.headersList.append("sec-websocket-key", F), N.headersList.append("sec-websocket-version", "13");
    for (const K of y)
      N.headersList.append("sec-websocket-protocol", K);
    const j = "";
    return E({
      request: N,
      useParallelQueue: !0,
      dispatcher: S.dispatcher ?? Q(),
      processResponse(K) {
        if (K.type === "error" || K.status !== 101) {
          a(b, "Received network error or non-101 status code.");
          return;
        }
        if (y.length !== 0 && !K.headersList.get("Sec-WebSocket-Protocol")) {
          a(b, "Server did not respond with sent protocols.");
          return;
        }
        if (K.headersList.get("Upgrade")?.toLowerCase() !== "websocket") {
          a(b, 'Server did not set Upgrade header to "websocket".');
          return;
        }
        if (K.headersList.get("Connection")?.toLowerCase() !== "upgrade") {
          a(b, 'Server did not set Connection header to "upgrade".');
          return;
        }
        const ee = K.headersList.get("Sec-WebSocket-Accept"), ie = h.createHash("sha1").update(F + A).digest("base64");
        if (ee !== ie) {
          a(b, "Incorrect hash received in Sec-WebSocket-Accept header.");
          return;
        }
        const re = K.headersList.get("Sec-WebSocket-Extensions");
        if (re !== null && re !== j) {
          a(b, "Received different permessage-deflate than the one set.");
          return;
        }
        const ge = K.headersList.get("Sec-WebSocket-Protocol");
        if (ge !== null && ge !== N.headersList.get("Sec-WebSocket-Protocol")) {
          a(b, "Protocol was not set in the opening handshake.");
          return;
        }
        K.socket.on("data", u), K.socket.on("close", B), K.socket.on("error", m), d.open.hasSubscribers && d.open.publish({
          address: K.socket.address(),
          protocol: ge,
          extensions: re
        }), w(K);
      }
    });
  }
  function u(f) {
    this.ws[o].write(f) || this.pause();
  }
  function B() {
    const { ws: f } = this, y = f[s] && f[n];
    let b = 1005, w = "";
    const S = f[o].closingInfo;
    S ? (b = S.code ?? 1005, w = S.reason) : f[s] || (b = 1006), f[r] = t.CLOSED, i("close", f, g, {
      wasClean: y,
      code: b,
      reason: w
    }), d.close.hasSubscribers && d.close.publish({
      websocket: f,
      code: b,
      reason: w
    });
  }
  function m(f) {
    const { ws: y } = this;
    y[r] = t.CLOSING, d.socketError.hasSubscribers && d.socketError.publish(f), this.destroy();
  }
  return Fn = {
    establishWebSocketConnection: C
  }, Fn;
}
var Sn, Xc;
function ME() {
  if (Xc) return Sn;
  Xc = 1;
  const { maxUnsigned16Bit: e } = Xr();
  let A;
  try {
    A = require("crypto");
  } catch {
  }
  class t {
    /**
     * @param {Buffer|undefined} data
     */
    constructor(s) {
      this.frameData = s, this.maskKey = A.randomBytes(4);
    }
    createFrame(s) {
      const o = this.frameData?.byteLength ?? 0;
      let n = o, i = 6;
      o > e ? (i += 8, n = 127) : o > 125 && (i += 2, n = 126);
      const a = Buffer.allocUnsafe(o + i);
      a[0] = a[1] = 0, a[0] |= 128, a[0] = (a[0] & 240) + s;
      /*! ws. MIT License. Einar Otto Stangvik <einaros@gmail.com> */
      a[i - 4] = this.maskKey[0], a[i - 3] = this.maskKey[1], a[i - 2] = this.maskKey[2], a[i - 1] = this.maskKey[3], a[1] = n, n === 126 ? a.writeUInt16BE(o, 2) : n === 127 && (a[2] = a[3] = 0, a.writeUIntBE(o, 4, 6)), a[1] |= 128;
      for (let g = 0; g < o; g++)
        a[i + g] = this.frameData[g] ^ this.maskKey[g % 4];
      return a;
    }
  }
  return Sn = {
    WebsocketFrameSend: t
  }, Sn;
}
var Un, eg;
function up() {
  if (eg) return Un;
  eg = 1;
  const { Writable: e } = lt, A = Xg, { parserStates: t, opcodes: r, states: s, emptyBuffer: o } = Xr(), { kReadyState: n, kSentClose: i, kResponse: a, kReceivedClose: g } = Xs(), { isValidStatusCode: c, failWebsocketConnection: E, websocketMessageReceived: l } = Fi(), { WebsocketFrameSend: Q } = ME(), I = {};
  I.ping = A.channel("undici:websocket:ping"), I.pong = A.channel("undici:websocket:pong");
  class d extends e {
    #e = [];
    #t = 0;
    #r = t.INFO;
    #A = {};
    #s = [];
    constructor(C) {
      super(), this.ws = C;
    }
    /**
     * @param {Buffer} chunk
     * @param {() => void} callback
     */
    _write(C, u, B) {
      this.#e.push(C), this.#t += C.length, this.run(B);
    }
    /**
     * Runs whenever a new chunk is received.
     * Callback is called whenever there are no more chunks buffering,
     * or not enough bytes are buffered to parse.
     */
    run(C) {
      for (; ; ) {
        if (this.#r === t.INFO) {
          if (this.#t < 2)
            return C();
          const u = this.consume(2);
          if (this.#A.fin = (u[0] & 128) !== 0, this.#A.opcode = u[0] & 15, this.#A.originalOpcode ??= this.#A.opcode, this.#A.fragmented = !this.#A.fin && this.#A.opcode !== r.CONTINUATION, this.#A.fragmented && this.#A.opcode !== r.BINARY && this.#A.opcode !== r.TEXT) {
            E(this.ws, "Invalid frame type was fragmented.");
            return;
          }
          const B = u[1] & 127;
          if (B <= 125 ? (this.#A.payloadLength = B, this.#r = t.READ_DATA) : B === 126 ? this.#r = t.PAYLOADLENGTH_16 : B === 127 && (this.#r = t.PAYLOADLENGTH_64), this.#A.fragmented && B > 125) {
            E(this.ws, "Fragmented frame exceeded 125 bytes.");
            return;
          } else if ((this.#A.opcode === r.PING || this.#A.opcode === r.PONG || this.#A.opcode === r.CLOSE) && B > 125) {
            E(this.ws, "Payload length for control frame exceeded 125 bytes.");
            return;
          } else if (this.#A.opcode === r.CLOSE) {
            if (B === 1) {
              E(this.ws, "Received close frame with a 1-byte body.");
              return;
            }
            const m = this.consume(B);
            if (this.#A.closeInfo = this.parseCloseBody(!1, m), !this.ws[i]) {
              const f = Buffer.allocUnsafe(2);
              f.writeUInt16BE(this.#A.closeInfo.code, 0);
              const y = new Q(f);
              this.ws[a].socket.write(
                y.createFrame(r.CLOSE),
                (b) => {
                  b || (this.ws[i] = !0);
                }
              );
            }
            this.ws[n] = s.CLOSING, this.ws[g] = !0, this.end();
            return;
          } else if (this.#A.opcode === r.PING) {
            const m = this.consume(B);
            if (!this.ws[g]) {
              const f = new Q(m);
              this.ws[a].socket.write(f.createFrame(r.PONG)), I.ping.hasSubscribers && I.ping.publish({
                payload: m
              });
            }
            if (this.#r = t.INFO, this.#t > 0)
              continue;
            C();
            return;
          } else if (this.#A.opcode === r.PONG) {
            const m = this.consume(B);
            if (I.pong.hasSubscribers && I.pong.publish({
              payload: m
            }), this.#t > 0)
              continue;
            C();
            return;
          }
        } else if (this.#r === t.PAYLOADLENGTH_16) {
          if (this.#t < 2)
            return C();
          const u = this.consume(2);
          this.#A.payloadLength = u.readUInt16BE(0), this.#r = t.READ_DATA;
        } else if (this.#r === t.PAYLOADLENGTH_64) {
          if (this.#t < 8)
            return C();
          const u = this.consume(8), B = u.readUInt32BE(0);
          if (B > 2 ** 31 - 1) {
            E(this.ws, "Received payload length > 2^31 bytes.");
            return;
          }
          const m = u.readUInt32BE(4);
          this.#A.payloadLength = (B << 8) + m, this.#r = t.READ_DATA;
        } else if (this.#r === t.READ_DATA) {
          if (this.#t < this.#A.payloadLength)
            return C();
          if (this.#t >= this.#A.payloadLength) {
            const u = this.consume(this.#A.payloadLength);
            if (this.#s.push(u), !this.#A.fragmented || this.#A.fin && this.#A.opcode === r.CONTINUATION) {
              const B = Buffer.concat(this.#s);
              l(this.ws, this.#A.originalOpcode, B), this.#A = {}, this.#s.length = 0;
            }
            this.#r = t.INFO;
          }
        }
        if (!(this.#t > 0)) {
          C();
          break;
        }
      }
    }
    /**
     * Take n bytes from the buffered Buffers
     * @param {number} n
     * @returns {Buffer|null}
     */
    consume(C) {
      if (C > this.#t)
        return null;
      if (C === 0)
        return o;
      if (this.#e[0].length === C)
        return this.#t -= this.#e[0].length, this.#e.shift();
      const u = Buffer.allocUnsafe(C);
      let B = 0;
      for (; B !== C; ) {
        const m = this.#e[0], { length: f } = m;
        if (f + B === C) {
          u.set(this.#e.shift(), B);
          break;
        } else if (f + B > C) {
          u.set(m.subarray(0, C - B), B), this.#e[0] = m.subarray(C - B);
          break;
        } else
          u.set(this.#e.shift(), B), B += m.length;
      }
      return this.#t -= C, u;
    }
    parseCloseBody(C, u) {
      let B;
      if (u.length >= 2 && (B = u.readUInt16BE(0)), C)
        return c(B) ? { code: B } : null;
      let m = u.subarray(2);
      if (m[0] === 239 && m[1] === 187 && m[2] === 191 && (m = m.subarray(3)), B !== void 0 && !c(B))
        return null;
      try {
        m = new TextDecoder("utf-8", { fatal: !0 }).decode(m);
      } catch {
        return null;
      }
      return { code: B, reason: m };
    }
    get closingInfo() {
      return this.#A.closeInfo;
    }
  }
  return Un = {
    ByteParser: d
  }, Un;
}
var Gn, Ag;
function hp() {
  if (Ag) return Gn;
  Ag = 1;
  const { webidl: e } = hA(), { DOMException: A } = _t(), { URLSerializer: t } = MA(), { getGlobalOrigin: r } = jr(), { staticPropertyDescriptors: s, states: o, opcodes: n, emptyBuffer: i } = Xr(), {
    kWebSocketURL: a,
    kReadyState: g,
    kController: c,
    kBinaryType: E,
    kResponse: l,
    kSentClose: Q,
    kByteParser: I
  } = Xs(), { isEstablished: d, isClosing: h, isValidSubprotocol: C, failWebsocketConnection: u, fireEvent: B } = Fi(), { establishWebSocketConnection: m } = Ep(), { WebsocketFrameSend: f } = ME(), { ByteParser: y } = up(), { kEnumerableProperty: b, isBlobLike: w } = we, { getGlobalDispatcher: S } = Zr, { types: v } = LA;
  let N = !1;
  class F extends EventTarget {
    #e = {
      open: null,
      error: null,
      close: null,
      message: null
    };
    #t = 0;
    #r = "";
    #A = "";
    /**
     * @param {string} url
     * @param {string|string[]} protocols
     */
    constructor(M, K = []) {
      super(), e.argumentLengthCheck(arguments, 1, { header: "WebSocket constructor" }), N || (N = !0, process.emitWarning("WebSockets are experimental, expect them to change at any time.", {
        code: "UNDICI-WS"
      }));
      const ee = e.converters["DOMString or sequence<DOMString> or WebSocketInit"](K);
      M = e.converters.USVString(M), K = ee.protocols;
      const ie = r();
      let re;
      try {
        re = new URL(M, ie);
      } catch (ge) {
        throw new A(ge, "SyntaxError");
      }
      if (re.protocol === "http:" ? re.protocol = "ws:" : re.protocol === "https:" && (re.protocol = "wss:"), re.protocol !== "ws:" && re.protocol !== "wss:")
        throw new A(
          `Expected a ws: or wss: protocol, got ${re.protocol}`,
          "SyntaxError"
        );
      if (re.hash || re.href.endsWith("#"))
        throw new A("Got fragment", "SyntaxError");
      if (typeof K == "string" && (K = [K]), K.length !== new Set(K.map((ge) => ge.toLowerCase())).size)
        throw new A("Invalid Sec-WebSocket-Protocol value", "SyntaxError");
      if (K.length > 0 && !K.every((ge) => C(ge)))
        throw new A("Invalid Sec-WebSocket-Protocol value", "SyntaxError");
      this[a] = new URL(re.href), this[c] = m(
        re,
        K,
        this,
        (ge) => this.#s(ge),
        ee
      ), this[g] = F.CONNECTING, this[E] = "blob";
    }
    /**
     * @see https://websockets.spec.whatwg.org/#dom-websocket-close
     * @param {number|undefined} code
     * @param {string|undefined} reason
     */
    close(M = void 0, K = void 0) {
      if (e.brandCheck(this, F), M !== void 0 && (M = e.converters["unsigned short"](M, { clamp: !0 })), K !== void 0 && (K = e.converters.USVString(K)), M !== void 0 && M !== 1e3 && (M < 3e3 || M > 4999))
        throw new A("invalid code", "InvalidAccessError");
      let ee = 0;
      if (K !== void 0 && (ee = Buffer.byteLength(K), ee > 123))
        throw new A(
          `Reason must be less than 123 bytes; received ${ee}`,
          "SyntaxError"
        );
      if (!(this[g] === F.CLOSING || this[g] === F.CLOSED)) if (!d(this))
        u(this, "Connection was closed before it was established."), this[g] = F.CLOSING;
      else if (h(this))
        this[g] = F.CLOSING;
      else {
        const ie = new f();
        M !== void 0 && K === void 0 ? (ie.frameData = Buffer.allocUnsafe(2), ie.frameData.writeUInt16BE(M, 0)) : M !== void 0 && K !== void 0 ? (ie.frameData = Buffer.allocUnsafe(2 + ee), ie.frameData.writeUInt16BE(M, 0), ie.frameData.write(K, 2, "utf-8")) : ie.frameData = i, this[l].socket.write(ie.createFrame(n.CLOSE), (ge) => {
          ge || (this[Q] = !0);
        }), this[g] = o.CLOSING;
      }
    }
    /**
     * @see https://websockets.spec.whatwg.org/#dom-websocket-send
     * @param {NodeJS.TypedArray|ArrayBuffer|Blob|string} data
     */
    send(M) {
      if (e.brandCheck(this, F), e.argumentLengthCheck(arguments, 1, { header: "WebSocket.send" }), M = e.converters.WebSocketSendData(M), this[g] === F.CONNECTING)
        throw new A("Sent before connected.", "InvalidStateError");
      if (!d(this) || h(this))
        return;
      const K = this[l].socket;
      if (typeof M == "string") {
        const ee = Buffer.from(M), re = new f(ee).createFrame(n.TEXT);
        this.#t += ee.byteLength, K.write(re, () => {
          this.#t -= ee.byteLength;
        });
      } else if (v.isArrayBuffer(M)) {
        const ee = Buffer.from(M), re = new f(ee).createFrame(n.BINARY);
        this.#t += ee.byteLength, K.write(re, () => {
          this.#t -= ee.byteLength;
        });
      } else if (ArrayBuffer.isView(M)) {
        const ee = Buffer.from(M, M.byteOffset, M.byteLength), re = new f(ee).createFrame(n.BINARY);
        this.#t += ee.byteLength, K.write(re, () => {
          this.#t -= ee.byteLength;
        });
      } else if (w(M)) {
        const ee = new f();
        M.arrayBuffer().then((ie) => {
          const re = Buffer.from(ie);
          ee.frameData = re;
          const ge = ee.createFrame(n.BINARY);
          this.#t += re.byteLength, K.write(ge, () => {
            this.#t -= re.byteLength;
          });
        });
      }
    }
    get readyState() {
      return e.brandCheck(this, F), this[g];
    }
    get bufferedAmount() {
      return e.brandCheck(this, F), this.#t;
    }
    get url() {
      return e.brandCheck(this, F), t(this[a]);
    }
    get extensions() {
      return e.brandCheck(this, F), this.#A;
    }
    get protocol() {
      return e.brandCheck(this, F), this.#r;
    }
    get onopen() {
      return e.brandCheck(this, F), this.#e.open;
    }
    set onopen(M) {
      e.brandCheck(this, F), this.#e.open && this.removeEventListener("open", this.#e.open), typeof M == "function" ? (this.#e.open = M, this.addEventListener("open", M)) : this.#e.open = null;
    }
    get onerror() {
      return e.brandCheck(this, F), this.#e.error;
    }
    set onerror(M) {
      e.brandCheck(this, F), this.#e.error && this.removeEventListener("error", this.#e.error), typeof M == "function" ? (this.#e.error = M, this.addEventListener("error", M)) : this.#e.error = null;
    }
    get onclose() {
      return e.brandCheck(this, F), this.#e.close;
    }
    set onclose(M) {
      e.brandCheck(this, F), this.#e.close && this.removeEventListener("close", this.#e.close), typeof M == "function" ? (this.#e.close = M, this.addEventListener("close", M)) : this.#e.close = null;
    }
    get onmessage() {
      return e.brandCheck(this, F), this.#e.message;
    }
    set onmessage(M) {
      e.brandCheck(this, F), this.#e.message && this.removeEventListener("message", this.#e.message), typeof M == "function" ? (this.#e.message = M, this.addEventListener("message", M)) : this.#e.message = null;
    }
    get binaryType() {
      return e.brandCheck(this, F), this[E];
    }
    set binaryType(M) {
      e.brandCheck(this, F), M !== "blob" && M !== "arraybuffer" ? this[E] = "blob" : this[E] = M;
    }
    /**
     * @see https://websockets.spec.whatwg.org/#feedback-from-the-protocol
     */
    #s(M) {
      this[l] = M;
      const K = new y(this);
      K.on("drain", function() {
        this.ws[l].socket.resume();
      }), M.socket.ws = this, this[I] = K, this[g] = o.OPEN;
      const ee = M.headersList.get("sec-websocket-extensions");
      ee !== null && (this.#A = ee);
      const ie = M.headersList.get("sec-websocket-protocol");
      ie !== null && (this.#r = ie), B("open", this);
    }
  }
  return F.CONNECTING = F.prototype.CONNECTING = o.CONNECTING, F.OPEN = F.prototype.OPEN = o.OPEN, F.CLOSING = F.prototype.CLOSING = o.CLOSING, F.CLOSED = F.prototype.CLOSED = o.CLOSED, Object.defineProperties(F.prototype, {
    CONNECTING: s,
    OPEN: s,
    CLOSING: s,
    CLOSED: s,
    url: b,
    readyState: b,
    bufferedAmount: b,
    onopen: b,
    onerror: b,
    onclose: b,
    close: b,
    onmessage: b,
    binaryType: b,
    send: b,
    extensions: b,
    protocol: b,
    [Symbol.toStringTag]: {
      value: "WebSocket",
      writable: !1,
      enumerable: !1,
      configurable: !0
    }
  }), Object.defineProperties(F, {
    CONNECTING: s,
    OPEN: s,
    CLOSING: s,
    CLOSED: s
  }), e.converters["sequence<DOMString>"] = e.sequenceConverter(
    e.converters.DOMString
  ), e.converters["DOMString or sequence<DOMString>"] = function(j) {
    return e.util.Type(j) === "Object" && Symbol.iterator in j ? e.converters["sequence<DOMString>"](j) : e.converters.DOMString(j);
  }, e.converters.WebSocketInit = e.dictionaryConverter([
    {
      key: "protocols",
      converter: e.converters["DOMString or sequence<DOMString>"],
      get defaultValue() {
        return [];
      }
    },
    {
      key: "dispatcher",
      converter: (j) => j,
      get defaultValue() {
        return S();
      }
    },
    {
      key: "headers",
      converter: e.nullableConverter(e.converters.HeadersInit)
    }
  ]), e.converters["DOMString or sequence<DOMString> or WebSocketInit"] = function(j) {
    return e.util.Type(j) === "Object" && !(Symbol.iterator in j) ? e.converters.WebSocketInit(j) : { protocols: e.converters["DOMString or sequence<DOMString>"](j) };
  }, e.converters.WebSocketSendData = function(j) {
    if (e.util.Type(j) === "Object") {
      if (w(j))
        return e.converters.Blob(j, { strict: !1 });
      if (ArrayBuffer.isView(j) || v.isAnyArrayBuffer(j))
        return e.converters.BufferSource(j);
    }
    return e.converters.USVString(j);
  }, Gn = {
    WebSocket: F
  }, Gn;
}
const dp = js, OE = mi, PE = Re, Qp = $r, Cp = QC, Bp = $s, Dt = we, { InvalidArgumentError: Rs } = PE, lr = cr, Ip = qs, pp = kE, fp = GI, mp = FE, wp = wE, yp = jI, bp = ZI, { getGlobalDispatcher: YE, setGlobalDispatcher: Rp } = Zr, Dp = Ap, Tp = Ol, kp = yi;
let ri;
try {
  require("crypto"), ri = !0;
} catch {
  ri = !1;
}
Object.assign(OE.prototype, lr);
he.Dispatcher = OE;
he.Client = dp;
he.Pool = Qp;
he.BalancedPool = Cp;
he.Agent = Bp;
he.ProxyAgent = yp;
he.RetryHandler = bp;
he.DecoratorHandler = Dp;
he.RedirectHandler = Tp;
he.createRedirectInterceptor = kp;
he.buildConnector = Ip;
he.errors = PE;
function es(e) {
  return (A, t, r) => {
    if (typeof t == "function" && (r = t, t = null), !A || typeof A != "string" && typeof A != "object" && !(A instanceof URL))
      throw new Rs("invalid url");
    if (t != null && typeof t != "object")
      throw new Rs("invalid opts");
    if (t && t.path != null) {
      if (typeof t.path != "string")
        throw new Rs("invalid opts.path");
      let n = t.path;
      t.path.startsWith("/") || (n = `/${n}`), A = new URL(Dt.parseOrigin(A).origin + n);
    } else
      t || (t = typeof A == "object" ? A : {}), A = Dt.parseURL(A);
    const { agent: s, dispatcher: o = YE() } = t;
    if (s)
      throw new Rs("unsupported opts.agent. Did you mean opts.client?");
    return e.call(o, {
      ...t,
      origin: A.origin,
      path: A.search ? `${A.pathname}${A.search}` : A.pathname,
      method: t.method || (t.body ? "PUT" : "GET")
    }, r);
  };
}
he.setGlobalDispatcher = Rp;
he.getGlobalDispatcher = YE;
if (Dt.nodeMajor > 16 || Dt.nodeMajor === 16 && Dt.nodeMinor >= 8) {
  let e = null;
  he.fetch = async function(n) {
    e || (e = Ti().fetch);
    try {
      return await e(...arguments);
    } catch (i) {
      throw typeof i == "object" && Error.captureStackTrace(i, this), i;
    }
  }, he.Headers = gr().Headers, he.Response = Di().Response, he.Request = Zs().Request, he.FormData = fi().FormData, he.File = pi().File, he.FileReader = op().FileReader;
  const { setGlobalOrigin: A, getGlobalOrigin: t } = jr();
  he.setGlobalOrigin = A, he.getGlobalOrigin = t;
  const { CacheStorage: r } = ap(), { kConstruct: s } = ki();
  he.caches = new r(s);
}
if (Dt.nodeMajor >= 16) {
  const { deleteCookie: e, getCookies: A, getSetCookies: t, setCookie: r } = lp();
  he.deleteCookie = e, he.getCookies = A, he.getSetCookies = t, he.setCookie = r;
  const { parseMIMEType: s, serializeAMimeType: o } = MA();
  he.parseMIMEType = s, he.serializeAMimeType = o;
}
if (Dt.nodeMajor >= 18 && ri) {
  const { WebSocket: e } = hp();
  he.WebSocket = e;
}
he.request = es(lr.request);
he.stream = es(lr.stream);
he.pipeline = es(lr.pipeline);
he.connect = es(lr.connect);
he.upgrade = es(lr.upgrade);
he.MockClient = pp;
he.MockPool = mp;
he.MockAgent = fp;
he.mockErrors = wp;
var Fp = O && O.__createBinding || (Object.create ? function(e, A, t, r) {
  r === void 0 && (r = t);
  var s = Object.getOwnPropertyDescriptor(A, t);
  (!s || ("get" in s ? !A.__esModule : s.writable || s.configurable)) && (s = { enumerable: !0, get: function() {
    return A[t];
  } }), Object.defineProperty(e, r, s);
} : function(e, A, t, r) {
  r === void 0 && (r = t), e[r] = A[t];
}), Sp = O && O.__setModuleDefault || (Object.create ? function(e, A) {
  Object.defineProperty(e, "default", { enumerable: !0, value: A });
} : function(e, A) {
  e.default = A;
}), eo = O && O.__importStar || function(e) {
  if (e && e.__esModule) return e;
  var A = {};
  if (e != null) for (var t in e) t !== "default" && Object.prototype.hasOwnProperty.call(e, t) && Fp(A, e, t);
  return Sp(A, e), A;
}, Ye = O && O.__awaiter || function(e, A, t, r) {
  function s(o) {
    return o instanceof t ? o : new t(function(n) {
      n(o);
    });
  }
  return new (t || (t = Promise))(function(o, n) {
    function i(c) {
      try {
        g(r.next(c));
      } catch (E) {
        n(E);
      }
    }
    function a(c) {
      try {
        g(r.throw(c));
      } catch (E) {
        n(E);
      }
    }
    function g(c) {
      c.done ? o(c.value) : s(c.value).then(i, a);
    }
    g((r = r.apply(e, A || [])).next());
  });
};
Object.defineProperty(We, "__esModule", { value: !0 });
We.HttpClient = We.isHttps = We.HttpClientResponse = We.HttpClientError = We.getProxyUrl = We.MediaTypes = We.Headers = We.HttpCodes = void 0;
const _n = eo(or), tg = eo(Wg), si = eo(Zt), Ds = eo(ih), Up = he;
var wA;
(function(e) {
  e[e.OK = 200] = "OK", e[e.MultipleChoices = 300] = "MultipleChoices", e[e.MovedPermanently = 301] = "MovedPermanently", e[e.ResourceMoved = 302] = "ResourceMoved", e[e.SeeOther = 303] = "SeeOther", e[e.NotModified = 304] = "NotModified", e[e.UseProxy = 305] = "UseProxy", e[e.SwitchProxy = 306] = "SwitchProxy", e[e.TemporaryRedirect = 307] = "TemporaryRedirect", e[e.PermanentRedirect = 308] = "PermanentRedirect", e[e.BadRequest = 400] = "BadRequest", e[e.Unauthorized = 401] = "Unauthorized", e[e.PaymentRequired = 402] = "PaymentRequired", e[e.Forbidden = 403] = "Forbidden", e[e.NotFound = 404] = "NotFound", e[e.MethodNotAllowed = 405] = "MethodNotAllowed", e[e.NotAcceptable = 406] = "NotAcceptable", e[e.ProxyAuthenticationRequired = 407] = "ProxyAuthenticationRequired", e[e.RequestTimeout = 408] = "RequestTimeout", e[e.Conflict = 409] = "Conflict", e[e.Gone = 410] = "Gone", e[e.TooManyRequests = 429] = "TooManyRequests", e[e.InternalServerError = 500] = "InternalServerError", e[e.NotImplemented = 501] = "NotImplemented", e[e.BadGateway = 502] = "BadGateway", e[e.ServiceUnavailable = 503] = "ServiceUnavailable", e[e.GatewayTimeout = 504] = "GatewayTimeout";
})(wA || (We.HttpCodes = wA = {}));
var rA;
(function(e) {
  e.Accept = "accept", e.ContentType = "content-type";
})(rA || (We.Headers = rA = {}));
var xA;
(function(e) {
  e.ApplicationJson = "application/json";
})(xA || (We.MediaTypes = xA = {}));
function Gp(e) {
  const A = si.getProxyUrl(new URL(e));
  return A ? A.href : "";
}
We.getProxyUrl = Gp;
const _p = [
  wA.MovedPermanently,
  wA.ResourceMoved,
  wA.SeeOther,
  wA.TemporaryRedirect,
  wA.PermanentRedirect
], Np = [
  wA.BadGateway,
  wA.ServiceUnavailable,
  wA.GatewayTimeout
], vp = ["OPTIONS", "GET", "DELETE", "HEAD"], Lp = 10, Mp = 5;
class Ao extends Error {
  constructor(A, t) {
    super(A), this.name = "HttpClientError", this.statusCode = t, Object.setPrototypeOf(this, Ao.prototype);
  }
}
We.HttpClientError = Ao;
class xE {
  constructor(A) {
    this.message = A;
  }
  readBody() {
    return Ye(this, void 0, void 0, function* () {
      return new Promise((A) => Ye(this, void 0, void 0, function* () {
        let t = Buffer.alloc(0);
        this.message.on("data", (r) => {
          t = Buffer.concat([t, r]);
        }), this.message.on("end", () => {
          A(t.toString());
        });
      }));
    });
  }
  readBodyBuffer() {
    return Ye(this, void 0, void 0, function* () {
      return new Promise((A) => Ye(this, void 0, void 0, function* () {
        const t = [];
        this.message.on("data", (r) => {
          t.push(r);
        }), this.message.on("end", () => {
          A(Buffer.concat(t));
        });
      }));
    });
  }
}
We.HttpClientResponse = xE;
function Op(e) {
  return new URL(e).protocol === "https:";
}
We.isHttps = Op;
class Pp {
  constructor(A, t, r) {
    this._ignoreSslError = !1, this._allowRedirects = !0, this._allowRedirectDowngrade = !1, this._maxRedirects = 50, this._allowRetries = !1, this._maxRetries = 1, this._keepAlive = !1, this._disposed = !1, this.userAgent = A, this.handlers = t || [], this.requestOptions = r, r && (r.ignoreSslError != null && (this._ignoreSslError = r.ignoreSslError), this._socketTimeout = r.socketTimeout, r.allowRedirects != null && (this._allowRedirects = r.allowRedirects), r.allowRedirectDowngrade != null && (this._allowRedirectDowngrade = r.allowRedirectDowngrade), r.maxRedirects != null && (this._maxRedirects = Math.max(r.maxRedirects, 0)), r.keepAlive != null && (this._keepAlive = r.keepAlive), r.allowRetries != null && (this._allowRetries = r.allowRetries), r.maxRetries != null && (this._maxRetries = r.maxRetries));
  }
  options(A, t) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("OPTIONS", A, null, t || {});
    });
  }
  get(A, t) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("GET", A, null, t || {});
    });
  }
  del(A, t) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("DELETE", A, null, t || {});
    });
  }
  post(A, t, r) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("POST", A, t, r || {});
    });
  }
  patch(A, t, r) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("PATCH", A, t, r || {});
    });
  }
  put(A, t, r) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("PUT", A, t, r || {});
    });
  }
  head(A, t) {
    return Ye(this, void 0, void 0, function* () {
      return this.request("HEAD", A, null, t || {});
    });
  }
  sendStream(A, t, r, s) {
    return Ye(this, void 0, void 0, function* () {
      return this.request(A, t, r, s);
    });
  }
  /**
   * Gets a typed object from an endpoint
   * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
   */
  getJson(A, t = {}) {
    return Ye(this, void 0, void 0, function* () {
      t[rA.Accept] = this._getExistingOrDefaultHeader(t, rA.Accept, xA.ApplicationJson);
      const r = yield this.get(A, t);
      return this._processResponse(r, this.requestOptions);
    });
  }
  postJson(A, t, r = {}) {
    return Ye(this, void 0, void 0, function* () {
      const s = JSON.stringify(t, null, 2);
      r[rA.Accept] = this._getExistingOrDefaultHeader(r, rA.Accept, xA.ApplicationJson), r[rA.ContentType] = this._getExistingOrDefaultHeader(r, rA.ContentType, xA.ApplicationJson);
      const o = yield this.post(A, s, r);
      return this._processResponse(o, this.requestOptions);
    });
  }
  putJson(A, t, r = {}) {
    return Ye(this, void 0, void 0, function* () {
      const s = JSON.stringify(t, null, 2);
      r[rA.Accept] = this._getExistingOrDefaultHeader(r, rA.Accept, xA.ApplicationJson), r[rA.ContentType] = this._getExistingOrDefaultHeader(r, rA.ContentType, xA.ApplicationJson);
      const o = yield this.put(A, s, r);
      return this._processResponse(o, this.requestOptions);
    });
  }
  patchJson(A, t, r = {}) {
    return Ye(this, void 0, void 0, function* () {
      const s = JSON.stringify(t, null, 2);
      r[rA.Accept] = this._getExistingOrDefaultHeader(r, rA.Accept, xA.ApplicationJson), r[rA.ContentType] = this._getExistingOrDefaultHeader(r, rA.ContentType, xA.ApplicationJson);
      const o = yield this.patch(A, s, r);
      return this._processResponse(o, this.requestOptions);
    });
  }
  /**
   * Makes a raw http request.
   * All other methods such as get, post, patch, and request ultimately call this.
   * Prefer get, del, post and patch
   */
  request(A, t, r, s) {
    return Ye(this, void 0, void 0, function* () {
      if (this._disposed)
        throw new Error("Client has already been disposed.");
      const o = new URL(t);
      let n = this._prepareRequest(A, o, s);
      const i = this._allowRetries && vp.includes(A) ? this._maxRetries + 1 : 1;
      let a = 0, g;
      do {
        if (g = yield this.requestRaw(n, r), g && g.message && g.message.statusCode === wA.Unauthorized) {
          let E;
          for (const l of this.handlers)
            if (l.canHandleAuthentication(g)) {
              E = l;
              break;
            }
          return E ? E.handleAuthentication(this, n, r) : g;
        }
        let c = this._maxRedirects;
        for (; g.message.statusCode && _p.includes(g.message.statusCode) && this._allowRedirects && c > 0; ) {
          const E = g.message.headers.location;
          if (!E)
            break;
          const l = new URL(E);
          if (o.protocol === "https:" && o.protocol !== l.protocol && !this._allowRedirectDowngrade)
            throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
          if (yield g.readBody(), l.hostname !== o.hostname)
            for (const Q in s)
              Q.toLowerCase() === "authorization" && delete s[Q];
          n = this._prepareRequest(A, l, s), g = yield this.requestRaw(n, r), c--;
        }
        if (!g.message.statusCode || !Np.includes(g.message.statusCode))
          return g;
        a += 1, a < i && (yield g.readBody(), yield this._performExponentialBackoff(a));
      } while (a < i);
      return g;
    });
  }
  /**
   * Needs to be called if keepAlive is set to true in request options.
   */
  dispose() {
    this._agent && this._agent.destroy(), this._disposed = !0;
  }
  /**
   * Raw request.
   * @param info
   * @param data
   */
  requestRaw(A, t) {
    return Ye(this, void 0, void 0, function* () {
      return new Promise((r, s) => {
        function o(n, i) {
          n ? s(n) : i ? r(i) : s(new Error("Unknown error"));
        }
        this.requestRawWithCallback(A, t, o);
      });
    });
  }
  /**
   * Raw request with callback.
   * @param info
   * @param data
   * @param onResult
   */
  requestRawWithCallback(A, t, r) {
    typeof t == "string" && (A.options.headers || (A.options.headers = {}), A.options.headers["Content-Length"] = Buffer.byteLength(t, "utf8"));
    let s = !1;
    function o(a, g) {
      s || (s = !0, r(a, g));
    }
    const n = A.httpModule.request(A.options, (a) => {
      const g = new xE(a);
      o(void 0, g);
    });
    let i;
    n.on("socket", (a) => {
      i = a;
    }), n.setTimeout(this._socketTimeout || 3 * 6e4, () => {
      i && i.end(), o(new Error(`Request timeout: ${A.options.path}`));
    }), n.on("error", function(a) {
      o(a);
    }), t && typeof t == "string" && n.write(t, "utf8"), t && typeof t != "string" ? (t.on("close", function() {
      n.end();
    }), t.pipe(n)) : n.end();
  }
  /**
   * Gets an http agent. This function is useful when you need an http agent that handles
   * routing through a proxy server - depending upon the url and proxy environment variables.
   * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
   */
  getAgent(A) {
    const t = new URL(A);
    return this._getAgent(t);
  }
  getAgentDispatcher(A) {
    const t = new URL(A), r = si.getProxyUrl(t);
    if (r && r.hostname)
      return this._getProxyAgentDispatcher(t, r);
  }
  _prepareRequest(A, t, r) {
    const s = {};
    s.parsedUrl = t;
    const o = s.parsedUrl.protocol === "https:";
    s.httpModule = o ? tg : _n;
    const n = o ? 443 : 80;
    if (s.options = {}, s.options.host = s.parsedUrl.hostname, s.options.port = s.parsedUrl.port ? parseInt(s.parsedUrl.port) : n, s.options.path = (s.parsedUrl.pathname || "") + (s.parsedUrl.search || ""), s.options.method = A, s.options.headers = this._mergeHeaders(r), this.userAgent != null && (s.options.headers["user-agent"] = this.userAgent), s.options.agent = this._getAgent(s.parsedUrl), this.handlers)
      for (const i of this.handlers)
        i.prepareRequest(s.options);
    return s;
  }
  _mergeHeaders(A) {
    return this.requestOptions && this.requestOptions.headers ? Object.assign({}, Ts(this.requestOptions.headers), Ts(A || {})) : Ts(A || {});
  }
  _getExistingOrDefaultHeader(A, t, r) {
    let s;
    return this.requestOptions && this.requestOptions.headers && (s = Ts(this.requestOptions.headers)[t]), A[t] || s || r;
  }
  _getAgent(A) {
    let t;
    const r = si.getProxyUrl(A), s = r && r.hostname;
    if (this._keepAlive && s && (t = this._proxyAgent), s || (t = this._agent), t)
      return t;
    const o = A.protocol === "https:";
    let n = 100;
    if (this.requestOptions && (n = this.requestOptions.maxSockets || _n.globalAgent.maxSockets), r && r.hostname) {
      const i = {
        maxSockets: n,
        keepAlive: this._keepAlive,
        proxy: Object.assign(Object.assign({}, (r.username || r.password) && {
          proxyAuth: `${r.username}:${r.password}`
        }), { host: r.hostname, port: r.port })
      };
      let a;
      const g = r.protocol === "https:";
      o ? a = g ? Ds.httpsOverHttps : Ds.httpsOverHttp : a = g ? Ds.httpOverHttps : Ds.httpOverHttp, t = a(i), this._proxyAgent = t;
    }
    if (!t) {
      const i = { keepAlive: this._keepAlive, maxSockets: n };
      t = o ? new tg.Agent(i) : new _n.Agent(i), this._agent = t;
    }
    return o && this._ignoreSslError && (t.options = Object.assign(t.options || {}, {
      rejectUnauthorized: !1
    })), t;
  }
  _getProxyAgentDispatcher(A, t) {
    let r;
    if (this._keepAlive && (r = this._proxyAgentDispatcher), r)
      return r;
    const s = A.protocol === "https:";
    return r = new Up.ProxyAgent(Object.assign({ uri: t.href, pipelining: this._keepAlive ? 1 : 0 }, (t.username || t.password) && {
      token: `Basic ${Buffer.from(`${t.username}:${t.password}`).toString("base64")}`
    })), this._proxyAgentDispatcher = r, s && this._ignoreSslError && (r.options = Object.assign(r.options.requestTls || {}, {
      rejectUnauthorized: !1
    })), r;
  }
  _performExponentialBackoff(A) {
    return Ye(this, void 0, void 0, function* () {
      A = Math.min(Lp, A);
      const t = Mp * Math.pow(2, A);
      return new Promise((r) => setTimeout(() => r(), t));
    });
  }
  _processResponse(A, t) {
    return Ye(this, void 0, void 0, function* () {
      return new Promise((r, s) => Ye(this, void 0, void 0, function* () {
        const o = A.message.statusCode || 0, n = {
          statusCode: o,
          result: null,
          headers: {}
        };
        o === wA.NotFound && r(n);
        function i(c, E) {
          if (typeof E == "string") {
            const l = new Date(E);
            if (!isNaN(l.valueOf()))
              return l;
          }
          return E;
        }
        let a, g;
        try {
          g = yield A.readBody(), g && g.length > 0 && (t && t.deserializeDates ? a = JSON.parse(g, i) : a = JSON.parse(g), n.result = a), n.headers = A.message.headers;
        } catch {
        }
        if (o > 299) {
          let c;
          a && a.message ? c = a.message : g && g.length > 0 ? c = g : c = `Failed request: (${o})`;
          const E = new Ao(c, o);
          E.result = n.result, s(E);
        } else
          r(n);
      }));
    });
  }
}
We.HttpClient = Pp;
const Ts = (e) => Object.keys(e).reduce((A, t) => (A[t.toLowerCase()] = e[t], A), {});
var Yp = O && O.__createBinding || (Object.create ? function(e, A, t, r) {
  r === void 0 && (r = t);
  var s = Object.getOwnPropertyDescriptor(A, t);
  (!s || ("get" in s ? !A.__esModule : s.writable || s.configurable)) && (s = { enumerable: !0, get: function() {
    return A[t];
  } }), Object.defineProperty(e, r, s);
} : function(e, A, t, r) {
  r === void 0 && (r = t), e[r] = A[t];
}), xp = O && O.__setModuleDefault || (Object.create ? function(e, A) {
  Object.defineProperty(e, "default", { enumerable: !0, value: A });
} : function(e, A) {
  e.default = A;
}), Jp = O && O.__importStar || function(e) {
  if (e && e.__esModule) return e;
  var A = {};
  if (e != null) for (var t in e) t !== "default" && Object.prototype.hasOwnProperty.call(e, t) && Yp(A, e, t);
  return xp(A, e), A;
}, Hp = O && O.__awaiter || function(e, A, t, r) {
  function s(o) {
    return o instanceof t ? o : new t(function(n) {
      n(o);
    });
  }
  return new (t || (t = Promise))(function(o, n) {
    function i(c) {
      try {
        g(r.next(c));
      } catch (E) {
        n(E);
      }
    }
    function a(c) {
      try {
        g(r.throw(c));
      } catch (E) {
        n(E);
      }
    }
    function g(c) {
      c.done ? o(c.value) : s(c.value).then(i, a);
    }
    g((r = r.apply(e, A || [])).next());
  });
};
Object.defineProperty(mA, "__esModule", { value: !0 });
mA.getApiBaseUrl = mA.getProxyFetch = mA.getProxyAgentDispatcher = mA.getProxyAgent = mA.getAuthString = void 0;
const JE = Jp(We), Vp = he;
function qp(e, A) {
  if (!e && !A.auth)
    throw new Error("Parameter token or opts.auth is required");
  if (e && A.auth)
    throw new Error("Parameters token and opts.auth may not both be specified");
  return typeof A.auth == "string" ? A.auth : `token ${e}`;
}
mA.getAuthString = qp;
function Wp(e) {
  return new JE.HttpClient().getAgent(e);
}
mA.getProxyAgent = Wp;
function HE(e) {
  return new JE.HttpClient().getAgentDispatcher(e);
}
mA.getProxyAgentDispatcher = HE;
function jp(e) {
  const A = HE(e);
  return (r, s) => Hp(this, void 0, void 0, function* () {
    return (0, Vp.fetch)(r, Object.assign(Object.assign({}, s), { dispatcher: A }));
  });
}
mA.getProxyFetch = jp;
function $p() {
  return process.env.GITHUB_API_URL || "https://api.github.com";
}
mA.getApiBaseUrl = $p;
function to() {
  return typeof navigator == "object" && "userAgent" in navigator ? navigator.userAgent : typeof process == "object" && process.version !== void 0 ? `Node.js/${process.version.substr(1)} (${process.platform}; ${process.arch})` : "<environment undetectable>";
}
var ro = { exports: {} }, Kp = VE;
function VE(e, A, t, r) {
  if (typeof t != "function")
    throw new Error("method for before hook must be a function");
  return r || (r = {}), Array.isArray(A) ? A.reverse().reduce(function(s, o) {
    return VE.bind(null, e, o, s, r);
  }, t)() : Promise.resolve().then(function() {
    return e.registry[A] ? e.registry[A].reduce(function(s, o) {
      return o.hook.bind(null, s, r);
    }, t)() : t(r);
  });
}
var zp = Zp;
function Zp(e, A, t, r) {
  var s = r;
  e.registry[t] || (e.registry[t] = []), A === "before" && (r = function(o, n) {
    return Promise.resolve().then(s.bind(null, n)).then(o.bind(null, n));
  }), A === "after" && (r = function(o, n) {
    var i;
    return Promise.resolve().then(o.bind(null, n)).then(function(a) {
      return i = a, s(i, n);
    }).then(function() {
      return i;
    });
  }), A === "error" && (r = function(o, n) {
    return Promise.resolve().then(o.bind(null, n)).catch(function(i) {
      return s(i, n);
    });
  }), e.registry[t].push({
    hook: r,
    orig: s
  });
}
var Xp = ef;
function ef(e, A, t) {
  if (e.registry[A]) {
    var r = e.registry[A].map(function(s) {
      return s.orig;
    }).indexOf(t);
    r !== -1 && e.registry[A].splice(r, 1);
  }
}
var qE = Kp, Af = zp, tf = Xp, rg = Function.bind, sg = rg.bind(rg);
function WE(e, A, t) {
  var r = sg(tf, null).apply(
    null,
    t ? [A, t] : [A]
  );
  e.api = { remove: r }, e.remove = r, ["before", "error", "after", "wrap"].forEach(function(s) {
    var o = t ? [A, s, t] : [A, s];
    e[s] = e.api[s] = sg(Af, null).apply(null, o);
  });
}
function rf() {
  var e = "h", A = {
    registry: {}
  }, t = qE.bind(null, A, e);
  return WE(t, A, e), t;
}
function jE() {
  var e = {
    registry: {}
  }, A = qE.bind(null, e);
  return WE(A, e), A;
}
var og = !1;
function Er() {
  return og || (console.warn(
    '[before-after-hook]: "Hook()" repurposing warning, use "Hook.Collection()". Read more: https://git.io/upgrade-before-after-hook-to-1.4'
  ), og = !0), jE();
}
Er.Singular = rf.bind();
Er.Collection = jE.bind();
ro.exports = Er;
ro.exports.Hook = Er;
ro.exports.Singular = Er.Singular;
var sf = ro.exports.Collection = Er.Collection, of = "9.0.5", nf = `octokit-endpoint.js/${of} ${to()}`, af = {
  method: "GET",
  baseUrl: "https://api.github.com",
  headers: {
    accept: "application/vnd.github.v3+json",
    "user-agent": nf
  },
  mediaType: {
    format: ""
  }
};
function cf(e) {
  return e ? Object.keys(e).reduce((A, t) => (A[t.toLowerCase()] = e[t], A), {}) : {};
}
function gf(e) {
  if (typeof e != "object" || e === null || Object.prototype.toString.call(e) !== "[object Object]")
    return !1;
  const A = Object.getPrototypeOf(e);
  if (A === null)
    return !0;
  const t = Object.prototype.hasOwnProperty.call(A, "constructor") && A.constructor;
  return typeof t == "function" && t instanceof t && Function.prototype.call(t) === Function.prototype.call(e);
}
function $E(e, A) {
  const t = Object.assign({}, e);
  return Object.keys(A).forEach((r) => {
    gf(A[r]) ? r in e ? t[r] = $E(e[r], A[r]) : Object.assign(t, { [r]: A[r] }) : Object.assign(t, { [r]: A[r] });
  }), t;
}
function ng(e) {
  for (const A in e)
    e[A] === void 0 && delete e[A];
  return e;
}
function oi(e, A, t) {
  if (typeof A == "string") {
    let [s, o] = A.split(" ");
    t = Object.assign(o ? { method: s, url: o } : { url: s }, t);
  } else
    t = Object.assign({}, A);
  t.headers = cf(t.headers), ng(t), ng(t.headers);
  const r = $E(e || {}, t);
  return t.url === "/graphql" && (e && e.mediaType.previews?.length && (r.mediaType.previews = e.mediaType.previews.filter(
    (s) => !r.mediaType.previews.includes(s)
  ).concat(r.mediaType.previews)), r.mediaType.previews = (r.mediaType.previews || []).map((s) => s.replace(/-preview/, ""))), r;
}
function lf(e, A) {
  const t = /\?/.test(e) ? "&" : "?", r = Object.keys(A);
  return r.length === 0 ? e : e + t + r.map((s) => s === "q" ? "q=" + A.q.split("+").map(encodeURIComponent).join("+") : `${s}=${encodeURIComponent(A[s])}`).join("&");
}
var Ef = /\{[^}]+\}/g;
function uf(e) {
  return e.replace(/^\W+|\W+$/g, "").split(/,/);
}
function hf(e) {
  const A = e.match(Ef);
  return A ? A.map(uf).reduce((t, r) => t.concat(r), []) : [];
}
function ig(e, A) {
  const t = { __proto__: null };
  for (const r of Object.keys(e))
    A.indexOf(r) === -1 && (t[r] = e[r]);
  return t;
}
function KE(e) {
  return e.split(/(%[0-9A-Fa-f]{2})/g).map(function(A) {
    return /%[0-9A-Fa-f]/.test(A) || (A = encodeURI(A).replace(/%5B/g, "[").replace(/%5D/g, "]")), A;
  }).join("");
}
function qt(e) {
  return encodeURIComponent(e).replace(/[!'()*]/g, function(A) {
    return "%" + A.charCodeAt(0).toString(16).toUpperCase();
  });
}
function Rr(e, A, t) {
  return A = e === "+" || e === "#" ? KE(A) : qt(A), t ? qt(t) + "=" + A : A;
}
function Jt(e) {
  return e != null;
}
function Nn(e) {
  return e === ";" || e === "&" || e === "?";
}
function df(e, A, t, r) {
  var s = e[t], o = [];
  if (Jt(s) && s !== "")
    if (typeof s == "string" || typeof s == "number" || typeof s == "boolean")
      s = s.toString(), r && r !== "*" && (s = s.substring(0, parseInt(r, 10))), o.push(
        Rr(A, s, Nn(A) ? t : "")
      );
    else if (r === "*")
      Array.isArray(s) ? s.filter(Jt).forEach(function(n) {
        o.push(
          Rr(A, n, Nn(A) ? t : "")
        );
      }) : Object.keys(s).forEach(function(n) {
        Jt(s[n]) && o.push(Rr(A, s[n], n));
      });
    else {
      const n = [];
      Array.isArray(s) ? s.filter(Jt).forEach(function(i) {
        n.push(Rr(A, i));
      }) : Object.keys(s).forEach(function(i) {
        Jt(s[i]) && (n.push(qt(i)), n.push(Rr(A, s[i].toString())));
      }), Nn(A) ? o.push(qt(t) + "=" + n.join(",")) : n.length !== 0 && o.push(n.join(","));
    }
  else
    A === ";" ? Jt(s) && o.push(qt(t)) : s === "" && (A === "&" || A === "?") ? o.push(qt(t) + "=") : s === "" && o.push("");
  return o;
}
function Qf(e) {
  return {
    expand: Cf.bind(null, e)
  };
}
function Cf(e, A) {
  var t = ["+", "#", ".", "/", ";", "?", "&"];
  return e = e.replace(
    /\{([^\{\}]+)\}|([^\{\}]+)/g,
    function(r, s, o) {
      if (s) {
        let i = "";
        const a = [];
        if (t.indexOf(s.charAt(0)) !== -1 && (i = s.charAt(0), s = s.substr(1)), s.split(/,/g).forEach(function(g) {
          var c = /([^:\*]*)(?::(\d+)|(\*))?/.exec(g);
          a.push(df(A, i, c[1], c[2] || c[3]));
        }), i && i !== "+") {
          var n = ",";
          return i === "?" ? n = "&" : i !== "#" && (n = i), (a.length !== 0 ? i : "") + a.join(n);
        } else
          return a.join(",");
      } else
        return KE(o);
    }
  ), e === "/" ? e : e.replace(/\/$/, "");
}
function zE(e) {
  let A = e.method.toUpperCase(), t = (e.url || "/").replace(/:([a-z]\w+)/g, "{$1}"), r = Object.assign({}, e.headers), s, o = ig(e, [
    "method",
    "baseUrl",
    "url",
    "headers",
    "request",
    "mediaType"
  ]);
  const n = hf(t);
  t = Qf(t).expand(o), /^http/.test(t) || (t = e.baseUrl + t);
  const i = Object.keys(e).filter((c) => n.includes(c)).concat("baseUrl"), a = ig(o, i);
  if (!/application\/octet-stream/i.test(r.accept) && (e.mediaType.format && (r.accept = r.accept.split(/,/).map(
    (c) => c.replace(
      /application\/vnd(\.\w+)(\.v3)?(\.\w+)?(\+json)?$/,
      `application/vnd$1$2.${e.mediaType.format}`
    )
  ).join(",")), t.endsWith("/graphql") && e.mediaType.previews?.length)) {
    const c = r.accept.match(/[\w-]+(?=-preview)/g) || [];
    r.accept = c.concat(e.mediaType.previews).map((E) => {
      const l = e.mediaType.format ? `.${e.mediaType.format}` : "+json";
      return `application/vnd.github.${E}-preview${l}`;
    }).join(",");
  }
  return ["GET", "HEAD"].includes(A) ? t = lf(t, a) : "data" in a ? s = a.data : Object.keys(a).length && (s = a), !r["content-type"] && typeof s < "u" && (r["content-type"] = "application/json; charset=utf-8"), ["PATCH", "PUT"].includes(A) && typeof s > "u" && (s = ""), Object.assign(
    { method: A, url: t, headers: r },
    typeof s < "u" ? { body: s } : null,
    e.request ? { request: e.request } : null
  );
}
function Bf(e, A, t) {
  return zE(oi(e, A, t));
}
function ZE(e, A) {
  const t = oi(e, A), r = Bf.bind(null, t);
  return Object.assign(r, {
    DEFAULTS: t,
    defaults: ZE.bind(null, t),
    merge: oi.bind(null, t),
    parse: zE
  });
}
var If = ZE(null, af);
class ag extends Error {
  constructor(A) {
    super(A), Error.captureStackTrace && Error.captureStackTrace(this, this.constructor), this.name = "Deprecation";
  }
}
var Si = { exports: {} }, pf = XE;
function XE(e, A) {
  if (e && A) return XE(e)(A);
  if (typeof e != "function")
    throw new TypeError("need wrapper function");
  return Object.keys(e).forEach(function(r) {
    t[r] = e[r];
  }), t;
  function t() {
    for (var r = new Array(arguments.length), s = 0; s < r.length; s++)
      r[s] = arguments[s];
    var o = e.apply(this, r), n = r[r.length - 1];
    return typeof o == "function" && o !== n && Object.keys(n).forEach(function(i) {
      o[i] = n[i];
    }), o;
  }
}
var eu = pf;
Si.exports = eu(_s);
Si.exports.strict = eu(Au);
_s.proto = _s(function() {
  Object.defineProperty(Function.prototype, "once", {
    value: function() {
      return _s(this);
    },
    configurable: !0
  }), Object.defineProperty(Function.prototype, "onceStrict", {
    value: function() {
      return Au(this);
    },
    configurable: !0
  });
});
function _s(e) {
  var A = function() {
    return A.called ? A.value : (A.called = !0, A.value = e.apply(this, arguments));
  };
  return A.called = !1, A;
}
function Au(e) {
  var A = function() {
    if (A.called)
      throw new Error(A.onceError);
    return A.called = !0, A.value = e.apply(this, arguments);
  }, t = e.name || "Function wrapped with `once`";
  return A.onceError = t + " shouldn't be called more than once", A.called = !1, A;
}
var ff = Si.exports;
const tu = /* @__PURE__ */ el(ff);
var mf = tu((e) => console.warn(e)), wf = tu((e) => console.warn(e)), Dr = class extends Error {
  constructor(A, t, r) {
    super(A), Error.captureStackTrace && Error.captureStackTrace(this, this.constructor), this.name = "HttpError", this.status = t;
    let s;
    "headers" in r && typeof r.headers < "u" && (s = r.headers), "response" in r && (this.response = r.response, s = r.response.headers);
    const o = Object.assign({}, r.request);
    r.request.headers.authorization && (o.headers = Object.assign({}, r.request.headers, {
      authorization: r.request.headers.authorization.replace(
        / .*$/,
        " [REDACTED]"
      )
    })), o.url = o.url.replace(/\bclient_secret=\w+/g, "client_secret=[REDACTED]").replace(/\baccess_token=\w+/g, "access_token=[REDACTED]"), this.request = o, Object.defineProperty(this, "code", {
      get() {
        return mf(
          new ag(
            "[@octokit/request-error] `error.code` is deprecated, use `error.status`."
          )
        ), t;
      }
    }), Object.defineProperty(this, "headers", {
      get() {
        return wf(
          new ag(
            "[@octokit/request-error] `error.headers` is deprecated, use `error.response.headers`."
          )
        ), s || {};
      }
    });
  }
}, yf = "8.4.0";
function bf(e) {
  if (typeof e != "object" || e === null || Object.prototype.toString.call(e) !== "[object Object]")
    return !1;
  const A = Object.getPrototypeOf(e);
  if (A === null)
    return !0;
  const t = Object.prototype.hasOwnProperty.call(A, "constructor") && A.constructor;
  return typeof t == "function" && t instanceof t && Function.prototype.call(t) === Function.prototype.call(e);
}
function Rf(e) {
  return e.arrayBuffer();
}
function cg(e) {
  const A = e.request && e.request.log ? e.request.log : console, t = e.request?.parseSuccessResponseBody !== !1;
  (bf(e.body) || Array.isArray(e.body)) && (e.body = JSON.stringify(e.body));
  let r = {}, s, o, { fetch: n } = globalThis;
  if (e.request?.fetch && (n = e.request.fetch), !n)
    throw new Error(
      "fetch is not set. Please pass a fetch implementation as new Octokit({ request: { fetch }}). Learn more at https://github.com/octokit/octokit.js/#fetch-missing"
    );
  return n(e.url, {
    method: e.method,
    body: e.body,
    redirect: e.request?.redirect,
    headers: e.headers,
    signal: e.request?.signal,
    // duplex must be set if request.body is ReadableStream or Async Iterables.
    // See https://fetch.spec.whatwg.org/#dom-requestinit-duplex.
    ...e.body && { duplex: "half" }
  }).then(async (i) => {
    o = i.url, s = i.status;
    for (const a of i.headers)
      r[a[0]] = a[1];
    if ("deprecation" in r) {
      const a = r.link && r.link.match(/<([^>]+)>; rel="deprecation"/), g = a && a.pop();
      A.warn(
        `[@octokit/request] "${e.method} ${e.url}" is deprecated. It is scheduled to be removed on ${r.sunset}${g ? `. See ${g}` : ""}`
      );
    }
    if (!(s === 204 || s === 205)) {
      if (e.method === "HEAD") {
        if (s < 400)
          return;
        throw new Dr(i.statusText, s, {
          response: {
            url: o,
            status: s,
            headers: r,
            data: void 0
          },
          request: e
        });
      }
      if (s === 304)
        throw new Dr("Not modified", s, {
          response: {
            url: o,
            status: s,
            headers: r,
            data: await vn(i)
          },
          request: e
        });
      if (s >= 400) {
        const a = await vn(i);
        throw new Dr(Df(a), s, {
          response: {
            url: o,
            status: s,
            headers: r,
            data: a
          },
          request: e
        });
      }
      return t ? await vn(i) : i.body;
    }
  }).then((i) => ({
    status: s,
    url: o,
    headers: r,
    data: i
  })).catch((i) => {
    if (i instanceof Dr)
      throw i;
    if (i.name === "AbortError")
      throw i;
    let a = i.message;
    throw i.name === "TypeError" && "cause" in i && (i.cause instanceof Error ? a = i.cause.message : typeof i.cause == "string" && (a = i.cause)), new Dr(a, 500, {
      request: e
    });
  });
}
async function vn(e) {
  const A = e.headers.get("content-type");
  return /application\/json/.test(A) ? e.json().catch(() => e.text()).catch(() => "") : !A || /^text\/|charset=utf-8$/.test(A) ? e.text() : Rf(e);
}
function Df(e) {
  if (typeof e == "string")
    return e;
  let A;
  return "documentation_url" in e ? A = ` - ${e.documentation_url}` : A = "", "message" in e ? Array.isArray(e.errors) ? `${e.message}: ${e.errors.map(JSON.stringify).join(", ")}${A}` : `${e.message}${A}` : `Unknown error: ${JSON.stringify(e)}`;
}
function ni(e, A) {
  const t = e.defaults(A);
  return Object.assign(function(s, o) {
    const n = t.merge(s, o);
    if (!n.request || !n.request.hook)
      return cg(t.parse(n));
    const i = (a, g) => cg(
      t.parse(t.merge(a, g))
    );
    return Object.assign(i, {
      endpoint: t,
      defaults: ni.bind(null, t)
    }), n.request.hook(i, n);
  }, {
    endpoint: t,
    defaults: ni.bind(null, t)
  });
}
var ii = ni(If, {
  headers: {
    "user-agent": `octokit-request.js/${yf} ${to()}`
  }
}), Tf = "7.1.0";
function kf(e) {
  return `Request failed due to following response errors:
` + e.errors.map((A) => ` - ${A.message}`).join(`
`);
}
var Ff = class extends Error {
  constructor(A, t, r) {
    super(kf(r)), this.request = A, this.headers = t, this.response = r, this.name = "GraphqlResponseError", this.errors = r.errors, this.data = r.data, Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
  }
}, Sf = [
  "method",
  "baseUrl",
  "url",
  "headers",
  "request",
  "query",
  "mediaType"
], Uf = ["query", "method", "url"], gg = /\/api\/v3\/?$/;
function Gf(e, A, t) {
  if (t) {
    if (typeof A == "string" && "query" in t)
      return Promise.reject(
        new Error('[@octokit/graphql] "query" cannot be used as variable name')
      );
    for (const n in t)
      if (Uf.includes(n))
        return Promise.reject(
          new Error(
            `[@octokit/graphql] "${n}" cannot be used as variable name`
          )
        );
  }
  const r = typeof A == "string" ? Object.assign({ query: A }, t) : A, s = Object.keys(
    r
  ).reduce((n, i) => Sf.includes(i) ? (n[i] = r[i], n) : (n.variables || (n.variables = {}), n.variables[i] = r[i], n), {}), o = r.baseUrl || e.endpoint.DEFAULTS.baseUrl;
  return gg.test(o) && (s.url = o.replace(gg, "/api/graphql")), e(s).then((n) => {
    if (n.data.errors) {
      const i = {};
      for (const a of Object.keys(n.headers))
        i[a] = n.headers[a];
      throw new Ff(
        s,
        i,
        n.data
      );
    }
    return n.data.data;
  });
}
function Ui(e, A) {
  const t = e.defaults(A);
  return Object.assign((s, o) => Gf(t, s, o), {
    defaults: Ui.bind(null, t),
    endpoint: t.endpoint
  });
}
Ui(ii, {
  headers: {
    "user-agent": `octokit-graphql.js/${Tf} ${to()}`
  },
  method: "POST",
  url: "/graphql"
});
function _f(e) {
  return Ui(e, {
    method: "POST",
    url: "/graphql"
  });
}
var Nf = /^v1\./, vf = /^ghs_/, Lf = /^ghu_/;
async function Mf(e) {
  const A = e.split(/\./).length === 3, t = Nf.test(e) || vf.test(e), r = Lf.test(e);
  return {
    type: "token",
    token: e,
    tokenType: A ? "app" : t ? "installation" : r ? "user-to-server" : "oauth"
  };
}
function Of(e) {
  return e.split(/\./).length === 3 ? `bearer ${e}` : `token ${e}`;
}
async function Pf(e, A, t, r) {
  const s = A.endpoint.merge(
    t,
    r
  );
  return s.headers.authorization = Of(e), A(s);
}
var Yf = function(A) {
  if (!A)
    throw new Error("[@octokit/auth-token] No token passed to createTokenAuth");
  if (typeof A != "string")
    throw new Error(
      "[@octokit/auth-token] Token passed to createTokenAuth is not a string"
    );
  return A = A.replace(/^(token|bearer) +/i, ""), Object.assign(Mf.bind(null, A), {
    hook: Pf.bind(null, A)
  });
}, ru = "5.2.0", lg = () => {
}, xf = console.warn.bind(console), Jf = console.error.bind(console), Eg = `octokit-core.js/${ru} ${to()}`, Hf = class {
  static {
    this.VERSION = ru;
  }
  static defaults(A) {
    return class extends this {
      constructor(...r) {
        const s = r[0] || {};
        if (typeof A == "function") {
          super(A(s));
          return;
        }
        super(
          Object.assign(
            {},
            A,
            s,
            s.userAgent && A.userAgent ? {
              userAgent: `${s.userAgent} ${A.userAgent}`
            } : null
          )
        );
      }
    };
  }
  static {
    this.plugins = [];
  }
  /**
   * Attach a plugin (or many) to your Octokit instance.
   *
   * @example
   * const API = Octokit.plugin(plugin1, plugin2, plugin3, ...)
   */
  static plugin(...A) {
    const t = this.plugins;
    return class extends this {
      static {
        this.plugins = t.concat(
          A.filter((s) => !t.includes(s))
        );
      }
    };
  }
  constructor(A = {}) {
    const t = new sf(), r = {
      baseUrl: ii.endpoint.DEFAULTS.baseUrl,
      headers: {},
      request: Object.assign({}, A.request, {
        // @ts-ignore internal usage only, no need to type
        hook: t.bind(null, "request")
      }),
      mediaType: {
        previews: [],
        format: ""
      }
    };
    if (r.headers["user-agent"] = A.userAgent ? `${A.userAgent} ${Eg}` : Eg, A.baseUrl && (r.baseUrl = A.baseUrl), A.previews && (r.mediaType.previews = A.previews), A.timeZone && (r.headers["time-zone"] = A.timeZone), this.request = ii.defaults(r), this.graphql = _f(this.request).defaults(r), this.log = Object.assign(
      {
        debug: lg,
        info: lg,
        warn: xf,
        error: Jf
      },
      A.log
    ), this.hook = t, A.authStrategy) {
      const { authStrategy: o, ...n } = A, i = o(
        Object.assign(
          {
            request: this.request,
            log: this.log,
            // we pass the current octokit instance as well as its constructor options
            // to allow for authentication strategies that return a new octokit instance
            // that shares the same internal state as the current one. The original
            // requirement for this was the "event-octokit" authentication strategy
            // of https://github.com/probot/octokit-auth-probot.
            octokit: this,
            octokitOptions: n
          },
          A.auth
        )
      );
      t.wrap("request", i.hook), this.auth = i;
    } else if (!A.auth)
      this.auth = async () => ({
        type: "unauthenticated"
      });
    else {
      const o = Yf(A.auth);
      t.wrap("request", o.hook), this.auth = o;
    }
    const s = this.constructor;
    for (let o = 0; o < s.plugins.length; ++o)
      Object.assign(this, s.plugins[o](this, A));
  }
};
const Vf = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  Octokit: Hf
}, Symbol.toStringTag, { value: "Module" })), qf = /* @__PURE__ */ ui(Vf);
var su = "10.4.1", Wf = {
  actions: {
    addCustomLabelsToSelfHostedRunnerForOrg: [
      "POST /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    addCustomLabelsToSelfHostedRunnerForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgVariable: [
      "PUT /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
    ],
    approveWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve"
    ],
    cancelWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel"
    ],
    createEnvironmentVariable: [
      "POST /repositories/{repository_id}/environments/{environment_name}/variables"
    ],
    createOrUpdateEnvironmentSecret: [
      "PUT /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}"
    ],
    createOrUpdateOrgSecret: ["PUT /orgs/{org}/actions/secrets/{secret_name}"],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}"
    ],
    createOrgVariable: ["POST /orgs/{org}/actions/variables"],
    createRegistrationTokenForOrg: [
      "POST /orgs/{org}/actions/runners/registration-token"
    ],
    createRegistrationTokenForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/registration-token"
    ],
    createRemoveTokenForOrg: ["POST /orgs/{org}/actions/runners/remove-token"],
    createRemoveTokenForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/remove-token"
    ],
    createRepoVariable: ["POST /repos/{owner}/{repo}/actions/variables"],
    createWorkflowDispatch: [
      "POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
    ],
    deleteActionsCacheById: [
      "DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}"
    ],
    deleteActionsCacheByKey: [
      "DELETE /repos/{owner}/{repo}/actions/caches{?key,ref}"
    ],
    deleteArtifact: [
      "DELETE /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"
    ],
    deleteEnvironmentSecret: [
      "DELETE /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}"
    ],
    deleteEnvironmentVariable: [
      "DELETE /repositories/{repository_id}/environments/{environment_name}/variables/{name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/actions/secrets/{secret_name}"],
    deleteOrgVariable: ["DELETE /orgs/{org}/actions/variables/{name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}"
    ],
    deleteRepoVariable: [
      "DELETE /repos/{owner}/{repo}/actions/variables/{name}"
    ],
    deleteSelfHostedRunnerFromOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}"
    ],
    deleteSelfHostedRunnerFromRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}"
    ],
    deleteWorkflowRun: ["DELETE /repos/{owner}/{repo}/actions/runs/{run_id}"],
    deleteWorkflowRunLogs: [
      "DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    ],
    disableSelectedRepositoryGithubActionsOrganization: [
      "DELETE /orgs/{org}/actions/permissions/repositories/{repository_id}"
    ],
    disableWorkflow: [
      "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable"
    ],
    downloadArtifact: [
      "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}"
    ],
    downloadJobLogsForWorkflowRun: [
      "GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
    ],
    downloadWorkflowRunAttemptLogs: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs"
    ],
    downloadWorkflowRunLogs: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    ],
    enableSelectedRepositoryGithubActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/repositories/{repository_id}"
    ],
    enableWorkflow: [
      "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable"
    ],
    forceCancelWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/force-cancel"
    ],
    generateRunnerJitconfigForOrg: [
      "POST /orgs/{org}/actions/runners/generate-jitconfig"
    ],
    generateRunnerJitconfigForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig"
    ],
    getActionsCacheList: ["GET /repos/{owner}/{repo}/actions/caches"],
    getActionsCacheUsage: ["GET /repos/{owner}/{repo}/actions/cache/usage"],
    getActionsCacheUsageByRepoForOrg: [
      "GET /orgs/{org}/actions/cache/usage-by-repository"
    ],
    getActionsCacheUsageForOrg: ["GET /orgs/{org}/actions/cache/usage"],
    getAllowedActionsOrganization: [
      "GET /orgs/{org}/actions/permissions/selected-actions"
    ],
    getAllowedActionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/selected-actions"
    ],
    getArtifact: ["GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"],
    getCustomOidcSubClaimForRepo: [
      "GET /repos/{owner}/{repo}/actions/oidc/customization/sub"
    ],
    getEnvironmentPublicKey: [
      "GET /repositories/{repository_id}/environments/{environment_name}/secrets/public-key"
    ],
    getEnvironmentSecret: [
      "GET /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}"
    ],
    getEnvironmentVariable: [
      "GET /repositories/{repository_id}/environments/{environment_name}/variables/{name}"
    ],
    getGithubActionsDefaultWorkflowPermissionsOrganization: [
      "GET /orgs/{org}/actions/permissions/workflow"
    ],
    getGithubActionsDefaultWorkflowPermissionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/workflow"
    ],
    getGithubActionsPermissionsOrganization: [
      "GET /orgs/{org}/actions/permissions"
    ],
    getGithubActionsPermissionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions"
    ],
    getJobForWorkflowRun: ["GET /repos/{owner}/{repo}/actions/jobs/{job_id}"],
    getOrgPublicKey: ["GET /orgs/{org}/actions/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/actions/secrets/{secret_name}"],
    getOrgVariable: ["GET /orgs/{org}/actions/variables/{name}"],
    getPendingDeploymentsForRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
    ],
    getRepoPermissions: [
      "GET /repos/{owner}/{repo}/actions/permissions",
      {},
      { renamed: ["actions", "getGithubActionsPermissionsRepository"] }
    ],
    getRepoPublicKey: ["GET /repos/{owner}/{repo}/actions/secrets/public-key"],
    getRepoSecret: ["GET /repos/{owner}/{repo}/actions/secrets/{secret_name}"],
    getRepoVariable: ["GET /repos/{owner}/{repo}/actions/variables/{name}"],
    getReviewsForRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals"
    ],
    getSelfHostedRunnerForOrg: ["GET /orgs/{org}/actions/runners/{runner_id}"],
    getSelfHostedRunnerForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/{runner_id}"
    ],
    getWorkflow: ["GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}"],
    getWorkflowAccessToRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/access"
    ],
    getWorkflowRun: ["GET /repos/{owner}/{repo}/actions/runs/{run_id}"],
    getWorkflowRunAttempt: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}"
    ],
    getWorkflowRunUsage: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/timing"
    ],
    getWorkflowUsage: [
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/timing"
    ],
    listArtifactsForRepo: ["GET /repos/{owner}/{repo}/actions/artifacts"],
    listEnvironmentSecrets: [
      "GET /repositories/{repository_id}/environments/{environment_name}/secrets"
    ],
    listEnvironmentVariables: [
      "GET /repositories/{repository_id}/environments/{environment_name}/variables"
    ],
    listJobsForWorkflowRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
    ],
    listJobsForWorkflowRunAttempt: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs"
    ],
    listLabelsForSelfHostedRunnerForOrg: [
      "GET /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    listLabelsForSelfHostedRunnerForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    listOrgSecrets: ["GET /orgs/{org}/actions/secrets"],
    listOrgVariables: ["GET /orgs/{org}/actions/variables"],
    listRepoOrganizationSecrets: [
      "GET /repos/{owner}/{repo}/actions/organization-secrets"
    ],
    listRepoOrganizationVariables: [
      "GET /repos/{owner}/{repo}/actions/organization-variables"
    ],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/actions/secrets"],
    listRepoVariables: ["GET /repos/{owner}/{repo}/actions/variables"],
    listRepoWorkflows: ["GET /repos/{owner}/{repo}/actions/workflows"],
    listRunnerApplicationsForOrg: ["GET /orgs/{org}/actions/runners/downloads"],
    listRunnerApplicationsForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/downloads"
    ],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/actions/secrets/{secret_name}/repositories"
    ],
    listSelectedReposForOrgVariable: [
      "GET /orgs/{org}/actions/variables/{name}/repositories"
    ],
    listSelectedRepositoriesEnabledGithubActionsOrganization: [
      "GET /orgs/{org}/actions/permissions/repositories"
    ],
    listSelfHostedRunnersForOrg: ["GET /orgs/{org}/actions/runners"],
    listSelfHostedRunnersForRepo: ["GET /repos/{owner}/{repo}/actions/runners"],
    listWorkflowRunArtifacts: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    ],
    listWorkflowRuns: [
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
    ],
    listWorkflowRunsForRepo: ["GET /repos/{owner}/{repo}/actions/runs"],
    reRunJobForWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/jobs/{job_id}/rerun"
    ],
    reRunWorkflow: ["POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun"],
    reRunWorkflowFailedJobs: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs"
    ],
    removeAllCustomLabelsFromSelfHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    removeAllCustomLabelsFromSelfHostedRunnerForRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    removeCustomLabelFromSelfHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}/labels/{name}"
    ],
    removeCustomLabelFromSelfHostedRunnerForRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels/{name}"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
    ],
    removeSelectedRepoFromOrgVariable: [
      "DELETE /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
    ],
    reviewCustomGatesForRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule"
    ],
    reviewPendingDeploymentsForRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
    ],
    setAllowedActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/selected-actions"
    ],
    setAllowedActionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/selected-actions"
    ],
    setCustomLabelsForSelfHostedRunnerForOrg: [
      "PUT /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    setCustomLabelsForSelfHostedRunnerForRepo: [
      "PUT /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    setCustomOidcSubClaimForRepo: [
      "PUT /repos/{owner}/{repo}/actions/oidc/customization/sub"
    ],
    setGithubActionsDefaultWorkflowPermissionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/workflow"
    ],
    setGithubActionsDefaultWorkflowPermissionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/workflow"
    ],
    setGithubActionsPermissionsOrganization: [
      "PUT /orgs/{org}/actions/permissions"
    ],
    setGithubActionsPermissionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories"
    ],
    setSelectedReposForOrgVariable: [
      "PUT /orgs/{org}/actions/variables/{name}/repositories"
    ],
    setSelectedRepositoriesEnabledGithubActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/repositories"
    ],
    setWorkflowAccessToRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/access"
    ],
    updateEnvironmentVariable: [
      "PATCH /repositories/{repository_id}/environments/{environment_name}/variables/{name}"
    ],
    updateOrgVariable: ["PATCH /orgs/{org}/actions/variables/{name}"],
    updateRepoVariable: [
      "PATCH /repos/{owner}/{repo}/actions/variables/{name}"
    ]
  },
  activity: {
    checkRepoIsStarredByAuthenticatedUser: ["GET /user/starred/{owner}/{repo}"],
    deleteRepoSubscription: ["DELETE /repos/{owner}/{repo}/subscription"],
    deleteThreadSubscription: [
      "DELETE /notifications/threads/{thread_id}/subscription"
    ],
    getFeeds: ["GET /feeds"],
    getRepoSubscription: ["GET /repos/{owner}/{repo}/subscription"],
    getThread: ["GET /notifications/threads/{thread_id}"],
    getThreadSubscriptionForAuthenticatedUser: [
      "GET /notifications/threads/{thread_id}/subscription"
    ],
    listEventsForAuthenticatedUser: ["GET /users/{username}/events"],
    listNotificationsForAuthenticatedUser: ["GET /notifications"],
    listOrgEventsForAuthenticatedUser: [
      "GET /users/{username}/events/orgs/{org}"
    ],
    listPublicEvents: ["GET /events"],
    listPublicEventsForRepoNetwork: ["GET /networks/{owner}/{repo}/events"],
    listPublicEventsForUser: ["GET /users/{username}/events/public"],
    listPublicOrgEvents: ["GET /orgs/{org}/events"],
    listReceivedEventsForUser: ["GET /users/{username}/received_events"],
    listReceivedPublicEventsForUser: [
      "GET /users/{username}/received_events/public"
    ],
    listRepoEvents: ["GET /repos/{owner}/{repo}/events"],
    listRepoNotificationsForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/notifications"
    ],
    listReposStarredByAuthenticatedUser: ["GET /user/starred"],
    listReposStarredByUser: ["GET /users/{username}/starred"],
    listReposWatchedByUser: ["GET /users/{username}/subscriptions"],
    listStargazersForRepo: ["GET /repos/{owner}/{repo}/stargazers"],
    listWatchedReposForAuthenticatedUser: ["GET /user/subscriptions"],
    listWatchersForRepo: ["GET /repos/{owner}/{repo}/subscribers"],
    markNotificationsAsRead: ["PUT /notifications"],
    markRepoNotificationsAsRead: ["PUT /repos/{owner}/{repo}/notifications"],
    markThreadAsDone: ["DELETE /notifications/threads/{thread_id}"],
    markThreadAsRead: ["PATCH /notifications/threads/{thread_id}"],
    setRepoSubscription: ["PUT /repos/{owner}/{repo}/subscription"],
    setThreadSubscription: [
      "PUT /notifications/threads/{thread_id}/subscription"
    ],
    starRepoForAuthenticatedUser: ["PUT /user/starred/{owner}/{repo}"],
    unstarRepoForAuthenticatedUser: ["DELETE /user/starred/{owner}/{repo}"]
  },
  apps: {
    addRepoToInstallation: [
      "PUT /user/installations/{installation_id}/repositories/{repository_id}",
      {},
      { renamed: ["apps", "addRepoToInstallationForAuthenticatedUser"] }
    ],
    addRepoToInstallationForAuthenticatedUser: [
      "PUT /user/installations/{installation_id}/repositories/{repository_id}"
    ],
    checkToken: ["POST /applications/{client_id}/token"],
    createFromManifest: ["POST /app-manifests/{code}/conversions"],
    createInstallationAccessToken: [
      "POST /app/installations/{installation_id}/access_tokens"
    ],
    deleteAuthorization: ["DELETE /applications/{client_id}/grant"],
    deleteInstallation: ["DELETE /app/installations/{installation_id}"],
    deleteToken: ["DELETE /applications/{client_id}/token"],
    getAuthenticated: ["GET /app"],
    getBySlug: ["GET /apps/{app_slug}"],
    getInstallation: ["GET /app/installations/{installation_id}"],
    getOrgInstallation: ["GET /orgs/{org}/installation"],
    getRepoInstallation: ["GET /repos/{owner}/{repo}/installation"],
    getSubscriptionPlanForAccount: [
      "GET /marketplace_listing/accounts/{account_id}"
    ],
    getSubscriptionPlanForAccountStubbed: [
      "GET /marketplace_listing/stubbed/accounts/{account_id}"
    ],
    getUserInstallation: ["GET /users/{username}/installation"],
    getWebhookConfigForApp: ["GET /app/hook/config"],
    getWebhookDelivery: ["GET /app/hook/deliveries/{delivery_id}"],
    listAccountsForPlan: ["GET /marketplace_listing/plans/{plan_id}/accounts"],
    listAccountsForPlanStubbed: [
      "GET /marketplace_listing/stubbed/plans/{plan_id}/accounts"
    ],
    listInstallationReposForAuthenticatedUser: [
      "GET /user/installations/{installation_id}/repositories"
    ],
    listInstallationRequestsForAuthenticatedApp: [
      "GET /app/installation-requests"
    ],
    listInstallations: ["GET /app/installations"],
    listInstallationsForAuthenticatedUser: ["GET /user/installations"],
    listPlans: ["GET /marketplace_listing/plans"],
    listPlansStubbed: ["GET /marketplace_listing/stubbed/plans"],
    listReposAccessibleToInstallation: ["GET /installation/repositories"],
    listSubscriptionsForAuthenticatedUser: ["GET /user/marketplace_purchases"],
    listSubscriptionsForAuthenticatedUserStubbed: [
      "GET /user/marketplace_purchases/stubbed"
    ],
    listWebhookDeliveries: ["GET /app/hook/deliveries"],
    redeliverWebhookDelivery: [
      "POST /app/hook/deliveries/{delivery_id}/attempts"
    ],
    removeRepoFromInstallation: [
      "DELETE /user/installations/{installation_id}/repositories/{repository_id}",
      {},
      { renamed: ["apps", "removeRepoFromInstallationForAuthenticatedUser"] }
    ],
    removeRepoFromInstallationForAuthenticatedUser: [
      "DELETE /user/installations/{installation_id}/repositories/{repository_id}"
    ],
    resetToken: ["PATCH /applications/{client_id}/token"],
    revokeInstallationAccessToken: ["DELETE /installation/token"],
    scopeToken: ["POST /applications/{client_id}/token/scoped"],
    suspendInstallation: ["PUT /app/installations/{installation_id}/suspended"],
    unsuspendInstallation: [
      "DELETE /app/installations/{installation_id}/suspended"
    ],
    updateWebhookConfigForApp: ["PATCH /app/hook/config"]
  },
  billing: {
    getGithubActionsBillingOrg: ["GET /orgs/{org}/settings/billing/actions"],
    getGithubActionsBillingUser: [
      "GET /users/{username}/settings/billing/actions"
    ],
    getGithubPackagesBillingOrg: ["GET /orgs/{org}/settings/billing/packages"],
    getGithubPackagesBillingUser: [
      "GET /users/{username}/settings/billing/packages"
    ],
    getSharedStorageBillingOrg: [
      "GET /orgs/{org}/settings/billing/shared-storage"
    ],
    getSharedStorageBillingUser: [
      "GET /users/{username}/settings/billing/shared-storage"
    ]
  },
  checks: {
    create: ["POST /repos/{owner}/{repo}/check-runs"],
    createSuite: ["POST /repos/{owner}/{repo}/check-suites"],
    get: ["GET /repos/{owner}/{repo}/check-runs/{check_run_id}"],
    getSuite: ["GET /repos/{owner}/{repo}/check-suites/{check_suite_id}"],
    listAnnotations: [
      "GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations"
    ],
    listForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-runs"],
    listForSuite: [
      "GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs"
    ],
    listSuitesForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-suites"],
    rerequestRun: [
      "POST /repos/{owner}/{repo}/check-runs/{check_run_id}/rerequest"
    ],
    rerequestSuite: [
      "POST /repos/{owner}/{repo}/check-suites/{check_suite_id}/rerequest"
    ],
    setSuitesPreferences: [
      "PATCH /repos/{owner}/{repo}/check-suites/preferences"
    ],
    update: ["PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}"]
  },
  codeScanning: {
    deleteAnalysis: [
      "DELETE /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}{?confirm_delete}"
    ],
    getAlert: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
      {},
      { renamedParameters: { alert_id: "alert_number" } }
    ],
    getAnalysis: [
      "GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}"
    ],
    getCodeqlDatabase: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
    ],
    getDefaultSetup: ["GET /repos/{owner}/{repo}/code-scanning/default-setup"],
    getSarif: ["GET /repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}"],
    listAlertInstances: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/code-scanning/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/code-scanning/alerts"],
    listAlertsInstances: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
      {},
      { renamed: ["codeScanning", "listAlertInstances"] }
    ],
    listCodeqlDatabases: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/databases"
    ],
    listRecentAnalyses: ["GET /repos/{owner}/{repo}/code-scanning/analyses"],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    ],
    updateDefaultSetup: [
      "PATCH /repos/{owner}/{repo}/code-scanning/default-setup"
    ],
    uploadSarif: ["POST /repos/{owner}/{repo}/code-scanning/sarifs"]
  },
  codesOfConduct: {
    getAllCodesOfConduct: ["GET /codes_of_conduct"],
    getConductCode: ["GET /codes_of_conduct/{key}"]
  },
  codespaces: {
    addRepositoryForSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    checkPermissionsForDevcontainer: [
      "GET /repos/{owner}/{repo}/codespaces/permissions_check"
    ],
    codespaceMachinesForAuthenticatedUser: [
      "GET /user/codespaces/{codespace_name}/machines"
    ],
    createForAuthenticatedUser: ["POST /user/codespaces"],
    createOrUpdateOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}"
    ],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    createOrUpdateSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}"
    ],
    createWithPrForAuthenticatedUser: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/codespaces"
    ],
    createWithRepoForAuthenticatedUser: [
      "POST /repos/{owner}/{repo}/codespaces"
    ],
    deleteForAuthenticatedUser: ["DELETE /user/codespaces/{codespace_name}"],
    deleteFromOrganization: [
      "DELETE /orgs/{org}/members/{username}/codespaces/{codespace_name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/codespaces/secrets/{secret_name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    deleteSecretForAuthenticatedUser: [
      "DELETE /user/codespaces/secrets/{secret_name}"
    ],
    exportForAuthenticatedUser: [
      "POST /user/codespaces/{codespace_name}/exports"
    ],
    getCodespacesForUserInOrg: [
      "GET /orgs/{org}/members/{username}/codespaces"
    ],
    getExportDetailsForAuthenticatedUser: [
      "GET /user/codespaces/{codespace_name}/exports/{export_id}"
    ],
    getForAuthenticatedUser: ["GET /user/codespaces/{codespace_name}"],
    getOrgPublicKey: ["GET /orgs/{org}/codespaces/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/codespaces/secrets/{secret_name}"],
    getPublicKeyForAuthenticatedUser: [
      "GET /user/codespaces/secrets/public-key"
    ],
    getRepoPublicKey: [
      "GET /repos/{owner}/{repo}/codespaces/secrets/public-key"
    ],
    getRepoSecret: [
      "GET /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    getSecretForAuthenticatedUser: [
      "GET /user/codespaces/secrets/{secret_name}"
    ],
    listDevcontainersInRepositoryForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/devcontainers"
    ],
    listForAuthenticatedUser: ["GET /user/codespaces"],
    listInOrganization: [
      "GET /orgs/{org}/codespaces",
      {},
      { renamedParameters: { org_id: "org" } }
    ],
    listInRepositoryForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces"
    ],
    listOrgSecrets: ["GET /orgs/{org}/codespaces/secrets"],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/codespaces/secrets"],
    listRepositoriesForSecretForAuthenticatedUser: [
      "GET /user/codespaces/secrets/{secret_name}/repositories"
    ],
    listSecretsForAuthenticatedUser: ["GET /user/codespaces/secrets"],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
    ],
    preFlightWithRepoForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/new"
    ],
    publishForAuthenticatedUser: [
      "POST /user/codespaces/{codespace_name}/publish"
    ],
    removeRepositoryForSecretForAuthenticatedUser: [
      "DELETE /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    repoMachinesForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/machines"
    ],
    setRepositoriesForSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}/repositories"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
    ],
    startForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/start"],
    stopForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/stop"],
    stopInOrganization: [
      "POST /orgs/{org}/members/{username}/codespaces/{codespace_name}/stop"
    ],
    updateForAuthenticatedUser: ["PATCH /user/codespaces/{codespace_name}"]
  },
  copilot: {
    addCopilotSeatsForTeams: [
      "POST /orgs/{org}/copilot/billing/selected_teams"
    ],
    addCopilotSeatsForUsers: [
      "POST /orgs/{org}/copilot/billing/selected_users"
    ],
    cancelCopilotSeatAssignmentForTeams: [
      "DELETE /orgs/{org}/copilot/billing/selected_teams"
    ],
    cancelCopilotSeatAssignmentForUsers: [
      "DELETE /orgs/{org}/copilot/billing/selected_users"
    ],
    getCopilotOrganizationDetails: ["GET /orgs/{org}/copilot/billing"],
    getCopilotSeatDetailsForUser: [
      "GET /orgs/{org}/members/{username}/copilot"
    ],
    listCopilotSeats: ["GET /orgs/{org}/copilot/billing/seats"]
  },
  dependabot: {
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
    ],
    createOrUpdateOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}"
    ],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/dependabot/secrets/{secret_name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    getAlert: ["GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"],
    getOrgPublicKey: ["GET /orgs/{org}/dependabot/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/dependabot/secrets/{secret_name}"],
    getRepoPublicKey: [
      "GET /repos/{owner}/{repo}/dependabot/secrets/public-key"
    ],
    getRepoSecret: [
      "GET /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    listAlertsForEnterprise: [
      "GET /enterprises/{enterprise}/dependabot/alerts"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/dependabot/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/dependabot/alerts"],
    listOrgSecrets: ["GET /orgs/{org}/dependabot/secrets"],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/dependabot/secrets"],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
    ],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"
    ]
  },
  dependencyGraph: {
    createRepositorySnapshot: [
      "POST /repos/{owner}/{repo}/dependency-graph/snapshots"
    ],
    diffRange: [
      "GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}"
    ],
    exportSbom: ["GET /repos/{owner}/{repo}/dependency-graph/sbom"]
  },
  emojis: { get: ["GET /emojis"] },
  gists: {
    checkIsStarred: ["GET /gists/{gist_id}/star"],
    create: ["POST /gists"],
    createComment: ["POST /gists/{gist_id}/comments"],
    delete: ["DELETE /gists/{gist_id}"],
    deleteComment: ["DELETE /gists/{gist_id}/comments/{comment_id}"],
    fork: ["POST /gists/{gist_id}/forks"],
    get: ["GET /gists/{gist_id}"],
    getComment: ["GET /gists/{gist_id}/comments/{comment_id}"],
    getRevision: ["GET /gists/{gist_id}/{sha}"],
    list: ["GET /gists"],
    listComments: ["GET /gists/{gist_id}/comments"],
    listCommits: ["GET /gists/{gist_id}/commits"],
    listForUser: ["GET /users/{username}/gists"],
    listForks: ["GET /gists/{gist_id}/forks"],
    listPublic: ["GET /gists/public"],
    listStarred: ["GET /gists/starred"],
    star: ["PUT /gists/{gist_id}/star"],
    unstar: ["DELETE /gists/{gist_id}/star"],
    update: ["PATCH /gists/{gist_id}"],
    updateComment: ["PATCH /gists/{gist_id}/comments/{comment_id}"]
  },
  git: {
    createBlob: ["POST /repos/{owner}/{repo}/git/blobs"],
    createCommit: ["POST /repos/{owner}/{repo}/git/commits"],
    createRef: ["POST /repos/{owner}/{repo}/git/refs"],
    createTag: ["POST /repos/{owner}/{repo}/git/tags"],
    createTree: ["POST /repos/{owner}/{repo}/git/trees"],
    deleteRef: ["DELETE /repos/{owner}/{repo}/git/refs/{ref}"],
    getBlob: ["GET /repos/{owner}/{repo}/git/blobs/{file_sha}"],
    getCommit: ["GET /repos/{owner}/{repo}/git/commits/{commit_sha}"],
    getRef: ["GET /repos/{owner}/{repo}/git/ref/{ref}"],
    getTag: ["GET /repos/{owner}/{repo}/git/tags/{tag_sha}"],
    getTree: ["GET /repos/{owner}/{repo}/git/trees/{tree_sha}"],
    listMatchingRefs: ["GET /repos/{owner}/{repo}/git/matching-refs/{ref}"],
    updateRef: ["PATCH /repos/{owner}/{repo}/git/refs/{ref}"]
  },
  gitignore: {
    getAllTemplates: ["GET /gitignore/templates"],
    getTemplate: ["GET /gitignore/templates/{name}"]
  },
  interactions: {
    getRestrictionsForAuthenticatedUser: ["GET /user/interaction-limits"],
    getRestrictionsForOrg: ["GET /orgs/{org}/interaction-limits"],
    getRestrictionsForRepo: ["GET /repos/{owner}/{repo}/interaction-limits"],
    getRestrictionsForYourPublicRepos: [
      "GET /user/interaction-limits",
      {},
      { renamed: ["interactions", "getRestrictionsForAuthenticatedUser"] }
    ],
    removeRestrictionsForAuthenticatedUser: ["DELETE /user/interaction-limits"],
    removeRestrictionsForOrg: ["DELETE /orgs/{org}/interaction-limits"],
    removeRestrictionsForRepo: [
      "DELETE /repos/{owner}/{repo}/interaction-limits"
    ],
    removeRestrictionsForYourPublicRepos: [
      "DELETE /user/interaction-limits",
      {},
      { renamed: ["interactions", "removeRestrictionsForAuthenticatedUser"] }
    ],
    setRestrictionsForAuthenticatedUser: ["PUT /user/interaction-limits"],
    setRestrictionsForOrg: ["PUT /orgs/{org}/interaction-limits"],
    setRestrictionsForRepo: ["PUT /repos/{owner}/{repo}/interaction-limits"],
    setRestrictionsForYourPublicRepos: [
      "PUT /user/interaction-limits",
      {},
      { renamed: ["interactions", "setRestrictionsForAuthenticatedUser"] }
    ]
  },
  issues: {
    addAssignees: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/assignees"
    ],
    addLabels: ["POST /repos/{owner}/{repo}/issues/{issue_number}/labels"],
    checkUserCanBeAssigned: ["GET /repos/{owner}/{repo}/assignees/{assignee}"],
    checkUserCanBeAssignedToIssue: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/assignees/{assignee}"
    ],
    create: ["POST /repos/{owner}/{repo}/issues"],
    createComment: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments"
    ],
    createLabel: ["POST /repos/{owner}/{repo}/labels"],
    createMilestone: ["POST /repos/{owner}/{repo}/milestones"],
    deleteComment: [
      "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}"
    ],
    deleteLabel: ["DELETE /repos/{owner}/{repo}/labels/{name}"],
    deleteMilestone: [
      "DELETE /repos/{owner}/{repo}/milestones/{milestone_number}"
    ],
    get: ["GET /repos/{owner}/{repo}/issues/{issue_number}"],
    getComment: ["GET /repos/{owner}/{repo}/issues/comments/{comment_id}"],
    getEvent: ["GET /repos/{owner}/{repo}/issues/events/{event_id}"],
    getLabel: ["GET /repos/{owner}/{repo}/labels/{name}"],
    getMilestone: ["GET /repos/{owner}/{repo}/milestones/{milestone_number}"],
    list: ["GET /issues"],
    listAssignees: ["GET /repos/{owner}/{repo}/assignees"],
    listComments: ["GET /repos/{owner}/{repo}/issues/{issue_number}/comments"],
    listCommentsForRepo: ["GET /repos/{owner}/{repo}/issues/comments"],
    listEvents: ["GET /repos/{owner}/{repo}/issues/{issue_number}/events"],
    listEventsForRepo: ["GET /repos/{owner}/{repo}/issues/events"],
    listEventsForTimeline: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/timeline"
    ],
    listForAuthenticatedUser: ["GET /user/issues"],
    listForOrg: ["GET /orgs/{org}/issues"],
    listForRepo: ["GET /repos/{owner}/{repo}/issues"],
    listLabelsForMilestone: [
      "GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels"
    ],
    listLabelsForRepo: ["GET /repos/{owner}/{repo}/labels"],
    listLabelsOnIssue: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/labels"
    ],
    listMilestones: ["GET /repos/{owner}/{repo}/milestones"],
    lock: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/lock"],
    removeAllLabels: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels"
    ],
    removeAssignees: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/assignees"
    ],
    removeLabel: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}"
    ],
    setLabels: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/labels"],
    unlock: ["DELETE /repos/{owner}/{repo}/issues/{issue_number}/lock"],
    update: ["PATCH /repos/{owner}/{repo}/issues/{issue_number}"],
    updateComment: ["PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}"],
    updateLabel: ["PATCH /repos/{owner}/{repo}/labels/{name}"],
    updateMilestone: [
      "PATCH /repos/{owner}/{repo}/milestones/{milestone_number}"
    ]
  },
  licenses: {
    get: ["GET /licenses/{license}"],
    getAllCommonlyUsed: ["GET /licenses"],
    getForRepo: ["GET /repos/{owner}/{repo}/license"]
  },
  markdown: {
    render: ["POST /markdown"],
    renderRaw: [
      "POST /markdown/raw",
      { headers: { "content-type": "text/plain; charset=utf-8" } }
    ]
  },
  meta: {
    get: ["GET /meta"],
    getAllVersions: ["GET /versions"],
    getOctocat: ["GET /octocat"],
    getZen: ["GET /zen"],
    root: ["GET /"]
  },
  migrations: {
    cancelImport: [
      "DELETE /repos/{owner}/{repo}/import",
      {},
      {
        deprecated: "octokit.rest.migrations.cancelImport() is deprecated, see https://docs.github.com/rest/migrations/source-imports#cancel-an-import"
      }
    ],
    deleteArchiveForAuthenticatedUser: [
      "DELETE /user/migrations/{migration_id}/archive"
    ],
    deleteArchiveForOrg: [
      "DELETE /orgs/{org}/migrations/{migration_id}/archive"
    ],
    downloadArchiveForOrg: [
      "GET /orgs/{org}/migrations/{migration_id}/archive"
    ],
    getArchiveForAuthenticatedUser: [
      "GET /user/migrations/{migration_id}/archive"
    ],
    getCommitAuthors: [
      "GET /repos/{owner}/{repo}/import/authors",
      {},
      {
        deprecated: "octokit.rest.migrations.getCommitAuthors() is deprecated, see https://docs.github.com/rest/migrations/source-imports#get-commit-authors"
      }
    ],
    getImportStatus: [
      "GET /repos/{owner}/{repo}/import",
      {},
      {
        deprecated: "octokit.rest.migrations.getImportStatus() is deprecated, see https://docs.github.com/rest/migrations/source-imports#get-an-import-status"
      }
    ],
    getLargeFiles: [
      "GET /repos/{owner}/{repo}/import/large_files",
      {},
      {
        deprecated: "octokit.rest.migrations.getLargeFiles() is deprecated, see https://docs.github.com/rest/migrations/source-imports#get-large-files"
      }
    ],
    getStatusForAuthenticatedUser: ["GET /user/migrations/{migration_id}"],
    getStatusForOrg: ["GET /orgs/{org}/migrations/{migration_id}"],
    listForAuthenticatedUser: ["GET /user/migrations"],
    listForOrg: ["GET /orgs/{org}/migrations"],
    listReposForAuthenticatedUser: [
      "GET /user/migrations/{migration_id}/repositories"
    ],
    listReposForOrg: ["GET /orgs/{org}/migrations/{migration_id}/repositories"],
    listReposForUser: [
      "GET /user/migrations/{migration_id}/repositories",
      {},
      { renamed: ["migrations", "listReposForAuthenticatedUser"] }
    ],
    mapCommitAuthor: [
      "PATCH /repos/{owner}/{repo}/import/authors/{author_id}",
      {},
      {
        deprecated: "octokit.rest.migrations.mapCommitAuthor() is deprecated, see https://docs.github.com/rest/migrations/source-imports#map-a-commit-author"
      }
    ],
    setLfsPreference: [
      "PATCH /repos/{owner}/{repo}/import/lfs",
      {},
      {
        deprecated: "octokit.rest.migrations.setLfsPreference() is deprecated, see https://docs.github.com/rest/migrations/source-imports#update-git-lfs-preference"
      }
    ],
    startForAuthenticatedUser: ["POST /user/migrations"],
    startForOrg: ["POST /orgs/{org}/migrations"],
    startImport: [
      "PUT /repos/{owner}/{repo}/import",
      {},
      {
        deprecated: "octokit.rest.migrations.startImport() is deprecated, see https://docs.github.com/rest/migrations/source-imports#start-an-import"
      }
    ],
    unlockRepoForAuthenticatedUser: [
      "DELETE /user/migrations/{migration_id}/repos/{repo_name}/lock"
    ],
    unlockRepoForOrg: [
      "DELETE /orgs/{org}/migrations/{migration_id}/repos/{repo_name}/lock"
    ],
    updateImport: [
      "PATCH /repos/{owner}/{repo}/import",
      {},
      {
        deprecated: "octokit.rest.migrations.updateImport() is deprecated, see https://docs.github.com/rest/migrations/source-imports#update-an-import"
      }
    ]
  },
  oidc: {
    getOidcCustomSubTemplateForOrg: [
      "GET /orgs/{org}/actions/oidc/customization/sub"
    ],
    updateOidcCustomSubTemplateForOrg: [
      "PUT /orgs/{org}/actions/oidc/customization/sub"
    ]
  },
  orgs: {
    addSecurityManagerTeam: [
      "PUT /orgs/{org}/security-managers/teams/{team_slug}"
    ],
    assignTeamToOrgRole: [
      "PUT /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}"
    ],
    assignUserToOrgRole: [
      "PUT /orgs/{org}/organization-roles/users/{username}/{role_id}"
    ],
    blockUser: ["PUT /orgs/{org}/blocks/{username}"],
    cancelInvitation: ["DELETE /orgs/{org}/invitations/{invitation_id}"],
    checkBlockedUser: ["GET /orgs/{org}/blocks/{username}"],
    checkMembershipForUser: ["GET /orgs/{org}/members/{username}"],
    checkPublicMembershipForUser: ["GET /orgs/{org}/public_members/{username}"],
    convertMemberToOutsideCollaborator: [
      "PUT /orgs/{org}/outside_collaborators/{username}"
    ],
    createCustomOrganizationRole: ["POST /orgs/{org}/organization-roles"],
    createInvitation: ["POST /orgs/{org}/invitations"],
    createOrUpdateCustomProperties: ["PATCH /orgs/{org}/properties/schema"],
    createOrUpdateCustomPropertiesValuesForRepos: [
      "PATCH /orgs/{org}/properties/values"
    ],
    createOrUpdateCustomProperty: [
      "PUT /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    createWebhook: ["POST /orgs/{org}/hooks"],
    delete: ["DELETE /orgs/{org}"],
    deleteCustomOrganizationRole: [
      "DELETE /orgs/{org}/organization-roles/{role_id}"
    ],
    deleteWebhook: ["DELETE /orgs/{org}/hooks/{hook_id}"],
    enableOrDisableSecurityProductOnAllOrgRepos: [
      "POST /orgs/{org}/{security_product}/{enablement}"
    ],
    get: ["GET /orgs/{org}"],
    getAllCustomProperties: ["GET /orgs/{org}/properties/schema"],
    getCustomProperty: [
      "GET /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    getMembershipForAuthenticatedUser: ["GET /user/memberships/orgs/{org}"],
    getMembershipForUser: ["GET /orgs/{org}/memberships/{username}"],
    getOrgRole: ["GET /orgs/{org}/organization-roles/{role_id}"],
    getWebhook: ["GET /orgs/{org}/hooks/{hook_id}"],
    getWebhookConfigForOrg: ["GET /orgs/{org}/hooks/{hook_id}/config"],
    getWebhookDelivery: [
      "GET /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}"
    ],
    list: ["GET /organizations"],
    listAppInstallations: ["GET /orgs/{org}/installations"],
    listBlockedUsers: ["GET /orgs/{org}/blocks"],
    listCustomPropertiesValuesForRepos: ["GET /orgs/{org}/properties/values"],
    listFailedInvitations: ["GET /orgs/{org}/failed_invitations"],
    listForAuthenticatedUser: ["GET /user/orgs"],
    listForUser: ["GET /users/{username}/orgs"],
    listInvitationTeams: ["GET /orgs/{org}/invitations/{invitation_id}/teams"],
    listMembers: ["GET /orgs/{org}/members"],
    listMembershipsForAuthenticatedUser: ["GET /user/memberships/orgs"],
    listOrgRoleTeams: ["GET /orgs/{org}/organization-roles/{role_id}/teams"],
    listOrgRoleUsers: ["GET /orgs/{org}/organization-roles/{role_id}/users"],
    listOrgRoles: ["GET /orgs/{org}/organization-roles"],
    listOrganizationFineGrainedPermissions: [
      "GET /orgs/{org}/organization-fine-grained-permissions"
    ],
    listOutsideCollaborators: ["GET /orgs/{org}/outside_collaborators"],
    listPatGrantRepositories: [
      "GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories"
    ],
    listPatGrantRequestRepositories: [
      "GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories"
    ],
    listPatGrantRequests: ["GET /orgs/{org}/personal-access-token-requests"],
    listPatGrants: ["GET /orgs/{org}/personal-access-tokens"],
    listPendingInvitations: ["GET /orgs/{org}/invitations"],
    listPublicMembers: ["GET /orgs/{org}/public_members"],
    listSecurityManagerTeams: ["GET /orgs/{org}/security-managers"],
    listWebhookDeliveries: ["GET /orgs/{org}/hooks/{hook_id}/deliveries"],
    listWebhooks: ["GET /orgs/{org}/hooks"],
    patchCustomOrganizationRole: [
      "PATCH /orgs/{org}/organization-roles/{role_id}"
    ],
    pingWebhook: ["POST /orgs/{org}/hooks/{hook_id}/pings"],
    redeliverWebhookDelivery: [
      "POST /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
    ],
    removeCustomProperty: [
      "DELETE /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    removeMember: ["DELETE /orgs/{org}/members/{username}"],
    removeMembershipForUser: ["DELETE /orgs/{org}/memberships/{username}"],
    removeOutsideCollaborator: [
      "DELETE /orgs/{org}/outside_collaborators/{username}"
    ],
    removePublicMembershipForAuthenticatedUser: [
      "DELETE /orgs/{org}/public_members/{username}"
    ],
    removeSecurityManagerTeam: [
      "DELETE /orgs/{org}/security-managers/teams/{team_slug}"
    ],
    reviewPatGrantRequest: [
      "POST /orgs/{org}/personal-access-token-requests/{pat_request_id}"
    ],
    reviewPatGrantRequestsInBulk: [
      "POST /orgs/{org}/personal-access-token-requests"
    ],
    revokeAllOrgRolesTeam: [
      "DELETE /orgs/{org}/organization-roles/teams/{team_slug}"
    ],
    revokeAllOrgRolesUser: [
      "DELETE /orgs/{org}/organization-roles/users/{username}"
    ],
    revokeOrgRoleTeam: [
      "DELETE /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}"
    ],
    revokeOrgRoleUser: [
      "DELETE /orgs/{org}/organization-roles/users/{username}/{role_id}"
    ],
    setMembershipForUser: ["PUT /orgs/{org}/memberships/{username}"],
    setPublicMembershipForAuthenticatedUser: [
      "PUT /orgs/{org}/public_members/{username}"
    ],
    unblockUser: ["DELETE /orgs/{org}/blocks/{username}"],
    update: ["PATCH /orgs/{org}"],
    updateMembershipForAuthenticatedUser: [
      "PATCH /user/memberships/orgs/{org}"
    ],
    updatePatAccess: ["POST /orgs/{org}/personal-access-tokens/{pat_id}"],
    updatePatAccesses: ["POST /orgs/{org}/personal-access-tokens"],
    updateWebhook: ["PATCH /orgs/{org}/hooks/{hook_id}"],
    updateWebhookConfigForOrg: ["PATCH /orgs/{org}/hooks/{hook_id}/config"]
  },
  packages: {
    deletePackageForAuthenticatedUser: [
      "DELETE /user/packages/{package_type}/{package_name}"
    ],
    deletePackageForOrg: [
      "DELETE /orgs/{org}/packages/{package_type}/{package_name}"
    ],
    deletePackageForUser: [
      "DELETE /users/{username}/packages/{package_type}/{package_name}"
    ],
    deletePackageVersionForAuthenticatedUser: [
      "DELETE /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    deletePackageVersionForOrg: [
      "DELETE /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    deletePackageVersionForUser: [
      "DELETE /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getAllPackageVersionsForAPackageOwnedByAnOrg: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions",
      {},
      { renamed: ["packages", "getAllPackageVersionsForPackageOwnedByOrg"] }
    ],
    getAllPackageVersionsForAPackageOwnedByTheAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions",
      {},
      {
        renamed: [
          "packages",
          "getAllPackageVersionsForPackageOwnedByAuthenticatedUser"
        ]
      }
    ],
    getAllPackageVersionsForPackageOwnedByAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions"
    ],
    getAllPackageVersionsForPackageOwnedByOrg: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions"
    ],
    getAllPackageVersionsForPackageOwnedByUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}/versions"
    ],
    getPackageForAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}"
    ],
    getPackageForOrganization: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}"
    ],
    getPackageForUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}"
    ],
    getPackageVersionForAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getPackageVersionForOrganization: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getPackageVersionForUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    listDockerMigrationConflictingPackagesForAuthenticatedUser: [
      "GET /user/docker/conflicts"
    ],
    listDockerMigrationConflictingPackagesForOrganization: [
      "GET /orgs/{org}/docker/conflicts"
    ],
    listDockerMigrationConflictingPackagesForUser: [
      "GET /users/{username}/docker/conflicts"
    ],
    listPackagesForAuthenticatedUser: ["GET /user/packages"],
    listPackagesForOrganization: ["GET /orgs/{org}/packages"],
    listPackagesForUser: ["GET /users/{username}/packages"],
    restorePackageForAuthenticatedUser: [
      "POST /user/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageForOrg: [
      "POST /orgs/{org}/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageForUser: [
      "POST /users/{username}/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageVersionForAuthenticatedUser: [
      "POST /user/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ],
    restorePackageVersionForOrg: [
      "POST /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ],
    restorePackageVersionForUser: [
      "POST /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ]
  },
  projects: {
    addCollaborator: ["PUT /projects/{project_id}/collaborators/{username}"],
    createCard: ["POST /projects/columns/{column_id}/cards"],
    createColumn: ["POST /projects/{project_id}/columns"],
    createForAuthenticatedUser: ["POST /user/projects"],
    createForOrg: ["POST /orgs/{org}/projects"],
    createForRepo: ["POST /repos/{owner}/{repo}/projects"],
    delete: ["DELETE /projects/{project_id}"],
    deleteCard: ["DELETE /projects/columns/cards/{card_id}"],
    deleteColumn: ["DELETE /projects/columns/{column_id}"],
    get: ["GET /projects/{project_id}"],
    getCard: ["GET /projects/columns/cards/{card_id}"],
    getColumn: ["GET /projects/columns/{column_id}"],
    getPermissionForUser: [
      "GET /projects/{project_id}/collaborators/{username}/permission"
    ],
    listCards: ["GET /projects/columns/{column_id}/cards"],
    listCollaborators: ["GET /projects/{project_id}/collaborators"],
    listColumns: ["GET /projects/{project_id}/columns"],
    listForOrg: ["GET /orgs/{org}/projects"],
    listForRepo: ["GET /repos/{owner}/{repo}/projects"],
    listForUser: ["GET /users/{username}/projects"],
    moveCard: ["POST /projects/columns/cards/{card_id}/moves"],
    moveColumn: ["POST /projects/columns/{column_id}/moves"],
    removeCollaborator: [
      "DELETE /projects/{project_id}/collaborators/{username}"
    ],
    update: ["PATCH /projects/{project_id}"],
    updateCard: ["PATCH /projects/columns/cards/{card_id}"],
    updateColumn: ["PATCH /projects/columns/{column_id}"]
  },
  pulls: {
    checkIfMerged: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
    create: ["POST /repos/{owner}/{repo}/pulls"],
    createReplyForReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies"
    ],
    createReview: ["POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
    createReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments"
    ],
    deletePendingReview: [
      "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    deleteReviewComment: [
      "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}"
    ],
    dismissReview: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/dismissals"
    ],
    get: ["GET /repos/{owner}/{repo}/pulls/{pull_number}"],
    getReview: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    getReviewComment: ["GET /repos/{owner}/{repo}/pulls/comments/{comment_id}"],
    list: ["GET /repos/{owner}/{repo}/pulls"],
    listCommentsForReview: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments"
    ],
    listCommits: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/commits"],
    listFiles: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/files"],
    listRequestedReviewers: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    listReviewComments: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments"
    ],
    listReviewCommentsForRepo: ["GET /repos/{owner}/{repo}/pulls/comments"],
    listReviews: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
    merge: ["PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
    removeRequestedReviewers: [
      "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    requestReviewers: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    submitReview: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/events"
    ],
    update: ["PATCH /repos/{owner}/{repo}/pulls/{pull_number}"],
    updateBranch: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/update-branch"
    ],
    updateReview: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    updateReviewComment: [
      "PATCH /repos/{owner}/{repo}/pulls/comments/{comment_id}"
    ]
  },
  rateLimit: { get: ["GET /rate_limit"] },
  reactions: {
    createForCommitComment: [
      "POST /repos/{owner}/{repo}/comments/{comment_id}/reactions"
    ],
    createForIssue: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/reactions"
    ],
    createForIssueComment: [
      "POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    ],
    createForPullRequestReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
    ],
    createForRelease: [
      "POST /repos/{owner}/{repo}/releases/{release_id}/reactions"
    ],
    createForTeamDiscussionCommentInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
    ],
    createForTeamDiscussionInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
    ],
    deleteForCommitComment: [
      "DELETE /repos/{owner}/{repo}/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForIssue: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/reactions/{reaction_id}"
    ],
    deleteForIssueComment: [
      "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForPullRequestComment: [
      "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForRelease: [
      "DELETE /repos/{owner}/{repo}/releases/{release_id}/reactions/{reaction_id}"
    ],
    deleteForTeamDiscussion: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions/{reaction_id}"
    ],
    deleteForTeamDiscussionComment: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions/{reaction_id}"
    ],
    listForCommitComment: [
      "GET /repos/{owner}/{repo}/comments/{comment_id}/reactions"
    ],
    listForIssue: ["GET /repos/{owner}/{repo}/issues/{issue_number}/reactions"],
    listForIssueComment: [
      "GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    ],
    listForPullRequestReviewComment: [
      "GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
    ],
    listForRelease: [
      "GET /repos/{owner}/{repo}/releases/{release_id}/reactions"
    ],
    listForTeamDiscussionCommentInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
    ],
    listForTeamDiscussionInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
    ]
  },
  repos: {
    acceptInvitation: [
      "PATCH /user/repository_invitations/{invitation_id}",
      {},
      { renamed: ["repos", "acceptInvitationForAuthenticatedUser"] }
    ],
    acceptInvitationForAuthenticatedUser: [
      "PATCH /user/repository_invitations/{invitation_id}"
    ],
    addAppAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    addCollaborator: ["PUT /repos/{owner}/{repo}/collaborators/{username}"],
    addStatusCheckContexts: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    addTeamAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    addUserAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    cancelPagesDeployment: [
      "POST /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}/cancel"
    ],
    checkAutomatedSecurityFixes: [
      "GET /repos/{owner}/{repo}/automated-security-fixes"
    ],
    checkCollaborator: ["GET /repos/{owner}/{repo}/collaborators/{username}"],
    checkVulnerabilityAlerts: [
      "GET /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    codeownersErrors: ["GET /repos/{owner}/{repo}/codeowners/errors"],
    compareCommits: ["GET /repos/{owner}/{repo}/compare/{base}...{head}"],
    compareCommitsWithBasehead: [
      "GET /repos/{owner}/{repo}/compare/{basehead}"
    ],
    createAutolink: ["POST /repos/{owner}/{repo}/autolinks"],
    createCommitComment: [
      "POST /repos/{owner}/{repo}/commits/{commit_sha}/comments"
    ],
    createCommitSignatureProtection: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    createCommitStatus: ["POST /repos/{owner}/{repo}/statuses/{sha}"],
    createDeployKey: ["POST /repos/{owner}/{repo}/keys"],
    createDeployment: ["POST /repos/{owner}/{repo}/deployments"],
    createDeploymentBranchPolicy: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
    ],
    createDeploymentProtectionRule: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
    ],
    createDeploymentStatus: [
      "POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
    ],
    createDispatchEvent: ["POST /repos/{owner}/{repo}/dispatches"],
    createForAuthenticatedUser: ["POST /user/repos"],
    createFork: ["POST /repos/{owner}/{repo}/forks"],
    createInOrg: ["POST /orgs/{org}/repos"],
    createOrUpdateCustomPropertiesValues: [
      "PATCH /repos/{owner}/{repo}/properties/values"
    ],
    createOrUpdateEnvironment: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    createOrUpdateFileContents: ["PUT /repos/{owner}/{repo}/contents/{path}"],
    createOrgRuleset: ["POST /orgs/{org}/rulesets"],
    createPagesDeployment: ["POST /repos/{owner}/{repo}/pages/deployments"],
    createPagesSite: ["POST /repos/{owner}/{repo}/pages"],
    createRelease: ["POST /repos/{owner}/{repo}/releases"],
    createRepoRuleset: ["POST /repos/{owner}/{repo}/rulesets"],
    createTagProtection: ["POST /repos/{owner}/{repo}/tags/protection"],
    createUsingTemplate: [
      "POST /repos/{template_owner}/{template_repo}/generate"
    ],
    createWebhook: ["POST /repos/{owner}/{repo}/hooks"],
    declineInvitation: [
      "DELETE /user/repository_invitations/{invitation_id}",
      {},
      { renamed: ["repos", "declineInvitationForAuthenticatedUser"] }
    ],
    declineInvitationForAuthenticatedUser: [
      "DELETE /user/repository_invitations/{invitation_id}"
    ],
    delete: ["DELETE /repos/{owner}/{repo}"],
    deleteAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
    ],
    deleteAdminBranchProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    deleteAnEnvironment: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    deleteAutolink: ["DELETE /repos/{owner}/{repo}/autolinks/{autolink_id}"],
    deleteBranchProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    deleteCommitComment: ["DELETE /repos/{owner}/{repo}/comments/{comment_id}"],
    deleteCommitSignatureProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    deleteDeployKey: ["DELETE /repos/{owner}/{repo}/keys/{key_id}"],
    deleteDeployment: [
      "DELETE /repos/{owner}/{repo}/deployments/{deployment_id}"
    ],
    deleteDeploymentBranchPolicy: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    deleteFile: ["DELETE /repos/{owner}/{repo}/contents/{path}"],
    deleteInvitation: [
      "DELETE /repos/{owner}/{repo}/invitations/{invitation_id}"
    ],
    deleteOrgRuleset: ["DELETE /orgs/{org}/rulesets/{ruleset_id}"],
    deletePagesSite: ["DELETE /repos/{owner}/{repo}/pages"],
    deletePullRequestReviewProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    deleteRelease: ["DELETE /repos/{owner}/{repo}/releases/{release_id}"],
    deleteReleaseAsset: [
      "DELETE /repos/{owner}/{repo}/releases/assets/{asset_id}"
    ],
    deleteRepoRuleset: ["DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    deleteTagProtection: [
      "DELETE /repos/{owner}/{repo}/tags/protection/{tag_protection_id}"
    ],
    deleteWebhook: ["DELETE /repos/{owner}/{repo}/hooks/{hook_id}"],
    disableAutomatedSecurityFixes: [
      "DELETE /repos/{owner}/{repo}/automated-security-fixes"
    ],
    disableDeploymentProtectionRule: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
    ],
    disablePrivateVulnerabilityReporting: [
      "DELETE /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    disableVulnerabilityAlerts: [
      "DELETE /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    downloadArchive: [
      "GET /repos/{owner}/{repo}/zipball/{ref}",
      {},
      { renamed: ["repos", "downloadZipballArchive"] }
    ],
    downloadTarballArchive: ["GET /repos/{owner}/{repo}/tarball/{ref}"],
    downloadZipballArchive: ["GET /repos/{owner}/{repo}/zipball/{ref}"],
    enableAutomatedSecurityFixes: [
      "PUT /repos/{owner}/{repo}/automated-security-fixes"
    ],
    enablePrivateVulnerabilityReporting: [
      "PUT /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    enableVulnerabilityAlerts: [
      "PUT /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    generateReleaseNotes: [
      "POST /repos/{owner}/{repo}/releases/generate-notes"
    ],
    get: ["GET /repos/{owner}/{repo}"],
    getAccessRestrictions: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
    ],
    getAdminBranchProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    getAllDeploymentProtectionRules: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
    ],
    getAllEnvironments: ["GET /repos/{owner}/{repo}/environments"],
    getAllStatusCheckContexts: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts"
    ],
    getAllTopics: ["GET /repos/{owner}/{repo}/topics"],
    getAppsWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps"
    ],
    getAutolink: ["GET /repos/{owner}/{repo}/autolinks/{autolink_id}"],
    getBranch: ["GET /repos/{owner}/{repo}/branches/{branch}"],
    getBranchProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    getBranchRules: ["GET /repos/{owner}/{repo}/rules/branches/{branch}"],
    getClones: ["GET /repos/{owner}/{repo}/traffic/clones"],
    getCodeFrequencyStats: ["GET /repos/{owner}/{repo}/stats/code_frequency"],
    getCollaboratorPermissionLevel: [
      "GET /repos/{owner}/{repo}/collaborators/{username}/permission"
    ],
    getCombinedStatusForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/status"],
    getCommit: ["GET /repos/{owner}/{repo}/commits/{ref}"],
    getCommitActivityStats: ["GET /repos/{owner}/{repo}/stats/commit_activity"],
    getCommitComment: ["GET /repos/{owner}/{repo}/comments/{comment_id}"],
    getCommitSignatureProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    getCommunityProfileMetrics: ["GET /repos/{owner}/{repo}/community/profile"],
    getContent: ["GET /repos/{owner}/{repo}/contents/{path}"],
    getContributorsStats: ["GET /repos/{owner}/{repo}/stats/contributors"],
    getCustomDeploymentProtectionRule: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
    ],
    getCustomPropertiesValues: ["GET /repos/{owner}/{repo}/properties/values"],
    getDeployKey: ["GET /repos/{owner}/{repo}/keys/{key_id}"],
    getDeployment: ["GET /repos/{owner}/{repo}/deployments/{deployment_id}"],
    getDeploymentBranchPolicy: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    getDeploymentStatus: [
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses/{status_id}"
    ],
    getEnvironment: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    getLatestPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/latest"],
    getLatestRelease: ["GET /repos/{owner}/{repo}/releases/latest"],
    getOrgRuleSuite: ["GET /orgs/{org}/rulesets/rule-suites/{rule_suite_id}"],
    getOrgRuleSuites: ["GET /orgs/{org}/rulesets/rule-suites"],
    getOrgRuleset: ["GET /orgs/{org}/rulesets/{ruleset_id}"],
    getOrgRulesets: ["GET /orgs/{org}/rulesets"],
    getPages: ["GET /repos/{owner}/{repo}/pages"],
    getPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/{build_id}"],
    getPagesDeployment: [
      "GET /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}"
    ],
    getPagesHealthCheck: ["GET /repos/{owner}/{repo}/pages/health"],
    getParticipationStats: ["GET /repos/{owner}/{repo}/stats/participation"],
    getPullRequestReviewProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    getPunchCardStats: ["GET /repos/{owner}/{repo}/stats/punch_card"],
    getReadme: ["GET /repos/{owner}/{repo}/readme"],
    getReadmeInDirectory: ["GET /repos/{owner}/{repo}/readme/{dir}"],
    getRelease: ["GET /repos/{owner}/{repo}/releases/{release_id}"],
    getReleaseAsset: ["GET /repos/{owner}/{repo}/releases/assets/{asset_id}"],
    getReleaseByTag: ["GET /repos/{owner}/{repo}/releases/tags/{tag}"],
    getRepoRuleSuite: [
      "GET /repos/{owner}/{repo}/rulesets/rule-suites/{rule_suite_id}"
    ],
    getRepoRuleSuites: ["GET /repos/{owner}/{repo}/rulesets/rule-suites"],
    getRepoRuleset: ["GET /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    getRepoRulesets: ["GET /repos/{owner}/{repo}/rulesets"],
    getStatusChecksProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    getTeamsWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams"
    ],
    getTopPaths: ["GET /repos/{owner}/{repo}/traffic/popular/paths"],
    getTopReferrers: ["GET /repos/{owner}/{repo}/traffic/popular/referrers"],
    getUsersWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users"
    ],
    getViews: ["GET /repos/{owner}/{repo}/traffic/views"],
    getWebhook: ["GET /repos/{owner}/{repo}/hooks/{hook_id}"],
    getWebhookConfigForRepo: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/config"
    ],
    getWebhookDelivery: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}"
    ],
    listActivities: ["GET /repos/{owner}/{repo}/activity"],
    listAutolinks: ["GET /repos/{owner}/{repo}/autolinks"],
    listBranches: ["GET /repos/{owner}/{repo}/branches"],
    listBranchesForHeadCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/branches-where-head"
    ],
    listCollaborators: ["GET /repos/{owner}/{repo}/collaborators"],
    listCommentsForCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/comments"
    ],
    listCommitCommentsForRepo: ["GET /repos/{owner}/{repo}/comments"],
    listCommitStatusesForRef: [
      "GET /repos/{owner}/{repo}/commits/{ref}/statuses"
    ],
    listCommits: ["GET /repos/{owner}/{repo}/commits"],
    listContributors: ["GET /repos/{owner}/{repo}/contributors"],
    listCustomDeploymentRuleIntegrations: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps"
    ],
    listDeployKeys: ["GET /repos/{owner}/{repo}/keys"],
    listDeploymentBranchPolicies: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
    ],
    listDeploymentStatuses: [
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
    ],
    listDeployments: ["GET /repos/{owner}/{repo}/deployments"],
    listForAuthenticatedUser: ["GET /user/repos"],
    listForOrg: ["GET /orgs/{org}/repos"],
    listForUser: ["GET /users/{username}/repos"],
    listForks: ["GET /repos/{owner}/{repo}/forks"],
    listInvitations: ["GET /repos/{owner}/{repo}/invitations"],
    listInvitationsForAuthenticatedUser: ["GET /user/repository_invitations"],
    listLanguages: ["GET /repos/{owner}/{repo}/languages"],
    listPagesBuilds: ["GET /repos/{owner}/{repo}/pages/builds"],
    listPublic: ["GET /repositories"],
    listPullRequestsAssociatedWithCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls"
    ],
    listReleaseAssets: [
      "GET /repos/{owner}/{repo}/releases/{release_id}/assets"
    ],
    listReleases: ["GET /repos/{owner}/{repo}/releases"],
    listTagProtection: ["GET /repos/{owner}/{repo}/tags/protection"],
    listTags: ["GET /repos/{owner}/{repo}/tags"],
    listTeams: ["GET /repos/{owner}/{repo}/teams"],
    listWebhookDeliveries: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries"
    ],
    listWebhooks: ["GET /repos/{owner}/{repo}/hooks"],
    merge: ["POST /repos/{owner}/{repo}/merges"],
    mergeUpstream: ["POST /repos/{owner}/{repo}/merge-upstream"],
    pingWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/pings"],
    redeliverWebhookDelivery: [
      "POST /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
    ],
    removeAppAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    removeCollaborator: [
      "DELETE /repos/{owner}/{repo}/collaborators/{username}"
    ],
    removeStatusCheckContexts: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    removeStatusCheckProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    removeTeamAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    removeUserAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    renameBranch: ["POST /repos/{owner}/{repo}/branches/{branch}/rename"],
    replaceAllTopics: ["PUT /repos/{owner}/{repo}/topics"],
    requestPagesBuild: ["POST /repos/{owner}/{repo}/pages/builds"],
    setAdminBranchProtection: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    setAppAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    setStatusCheckContexts: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    setTeamAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    setUserAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    testPushWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/tests"],
    transfer: ["POST /repos/{owner}/{repo}/transfer"],
    update: ["PATCH /repos/{owner}/{repo}"],
    updateBranchProtection: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    updateCommitComment: ["PATCH /repos/{owner}/{repo}/comments/{comment_id}"],
    updateDeploymentBranchPolicy: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    updateInformationAboutPagesSite: ["PUT /repos/{owner}/{repo}/pages"],
    updateInvitation: [
      "PATCH /repos/{owner}/{repo}/invitations/{invitation_id}"
    ],
    updateOrgRuleset: ["PUT /orgs/{org}/rulesets/{ruleset_id}"],
    updatePullRequestReviewProtection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    updateRelease: ["PATCH /repos/{owner}/{repo}/releases/{release_id}"],
    updateReleaseAsset: [
      "PATCH /repos/{owner}/{repo}/releases/assets/{asset_id}"
    ],
    updateRepoRuleset: ["PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    updateStatusCheckPotection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks",
      {},
      { renamed: ["repos", "updateStatusCheckProtection"] }
    ],
    updateStatusCheckProtection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    updateWebhook: ["PATCH /repos/{owner}/{repo}/hooks/{hook_id}"],
    updateWebhookConfigForRepo: [
      "PATCH /repos/{owner}/{repo}/hooks/{hook_id}/config"
    ],
    uploadReleaseAsset: [
      "POST /repos/{owner}/{repo}/releases/{release_id}/assets{?name,label}",
      { baseUrl: "https://uploads.github.com" }
    ]
  },
  search: {
    code: ["GET /search/code"],
    commits: ["GET /search/commits"],
    issuesAndPullRequests: ["GET /search/issues"],
    labels: ["GET /search/labels"],
    repos: ["GET /search/repositories"],
    topics: ["GET /search/topics"],
    users: ["GET /search/users"]
  },
  secretScanning: {
    getAlert: [
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
    ],
    listAlertsForEnterprise: [
      "GET /enterprises/{enterprise}/secret-scanning/alerts"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/secret-scanning/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/secret-scanning/alerts"],
    listLocationsForAlert: [
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations"
    ],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
    ]
  },
  securityAdvisories: {
    createFork: [
      "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/forks"
    ],
    createPrivateVulnerabilityReport: [
      "POST /repos/{owner}/{repo}/security-advisories/reports"
    ],
    createRepositoryAdvisory: [
      "POST /repos/{owner}/{repo}/security-advisories"
    ],
    createRepositoryAdvisoryCveRequest: [
      "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve"
    ],
    getGlobalAdvisory: ["GET /advisories/{ghsa_id}"],
    getRepositoryAdvisory: [
      "GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    ],
    listGlobalAdvisories: ["GET /advisories"],
    listOrgRepositoryAdvisories: ["GET /orgs/{org}/security-advisories"],
    listRepositoryAdvisories: ["GET /repos/{owner}/{repo}/security-advisories"],
    updateRepositoryAdvisory: [
      "PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    ]
  },
  teams: {
    addOrUpdateMembershipForUserInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    addOrUpdateProjectPermissionsInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/projects/{project_id}"
    ],
    addOrUpdateRepoPermissionsInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    checkPermissionsForProjectInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/projects/{project_id}"
    ],
    checkPermissionsForRepoInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    create: ["POST /orgs/{org}/teams"],
    createDiscussionCommentInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
    ],
    createDiscussionInOrg: ["POST /orgs/{org}/teams/{team_slug}/discussions"],
    deleteDiscussionCommentInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    deleteDiscussionInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    deleteInOrg: ["DELETE /orgs/{org}/teams/{team_slug}"],
    getByName: ["GET /orgs/{org}/teams/{team_slug}"],
    getDiscussionCommentInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    getDiscussionInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    getMembershipForUserInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    list: ["GET /orgs/{org}/teams"],
    listChildInOrg: ["GET /orgs/{org}/teams/{team_slug}/teams"],
    listDiscussionCommentsInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
    ],
    listDiscussionsInOrg: ["GET /orgs/{org}/teams/{team_slug}/discussions"],
    listForAuthenticatedUser: ["GET /user/teams"],
    listMembersInOrg: ["GET /orgs/{org}/teams/{team_slug}/members"],
    listPendingInvitationsInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/invitations"
    ],
    listProjectsInOrg: ["GET /orgs/{org}/teams/{team_slug}/projects"],
    listReposInOrg: ["GET /orgs/{org}/teams/{team_slug}/repos"],
    removeMembershipForUserInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    removeProjectInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/projects/{project_id}"
    ],
    removeRepoInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    updateDiscussionCommentInOrg: [
      "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    updateDiscussionInOrg: [
      "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    updateInOrg: ["PATCH /orgs/{org}/teams/{team_slug}"]
  },
  users: {
    addEmailForAuthenticated: [
      "POST /user/emails",
      {},
      { renamed: ["users", "addEmailForAuthenticatedUser"] }
    ],
    addEmailForAuthenticatedUser: ["POST /user/emails"],
    addSocialAccountForAuthenticatedUser: ["POST /user/social_accounts"],
    block: ["PUT /user/blocks/{username}"],
    checkBlocked: ["GET /user/blocks/{username}"],
    checkFollowingForUser: ["GET /users/{username}/following/{target_user}"],
    checkPersonIsFollowedByAuthenticated: ["GET /user/following/{username}"],
    createGpgKeyForAuthenticated: [
      "POST /user/gpg_keys",
      {},
      { renamed: ["users", "createGpgKeyForAuthenticatedUser"] }
    ],
    createGpgKeyForAuthenticatedUser: ["POST /user/gpg_keys"],
    createPublicSshKeyForAuthenticated: [
      "POST /user/keys",
      {},
      { renamed: ["users", "createPublicSshKeyForAuthenticatedUser"] }
    ],
    createPublicSshKeyForAuthenticatedUser: ["POST /user/keys"],
    createSshSigningKeyForAuthenticatedUser: ["POST /user/ssh_signing_keys"],
    deleteEmailForAuthenticated: [
      "DELETE /user/emails",
      {},
      { renamed: ["users", "deleteEmailForAuthenticatedUser"] }
    ],
    deleteEmailForAuthenticatedUser: ["DELETE /user/emails"],
    deleteGpgKeyForAuthenticated: [
      "DELETE /user/gpg_keys/{gpg_key_id}",
      {},
      { renamed: ["users", "deleteGpgKeyForAuthenticatedUser"] }
    ],
    deleteGpgKeyForAuthenticatedUser: ["DELETE /user/gpg_keys/{gpg_key_id}"],
    deletePublicSshKeyForAuthenticated: [
      "DELETE /user/keys/{key_id}",
      {},
      { renamed: ["users", "deletePublicSshKeyForAuthenticatedUser"] }
    ],
    deletePublicSshKeyForAuthenticatedUser: ["DELETE /user/keys/{key_id}"],
    deleteSocialAccountForAuthenticatedUser: ["DELETE /user/social_accounts"],
    deleteSshSigningKeyForAuthenticatedUser: [
      "DELETE /user/ssh_signing_keys/{ssh_signing_key_id}"
    ],
    follow: ["PUT /user/following/{username}"],
    getAuthenticated: ["GET /user"],
    getByUsername: ["GET /users/{username}"],
    getContextForUser: ["GET /users/{username}/hovercard"],
    getGpgKeyForAuthenticated: [
      "GET /user/gpg_keys/{gpg_key_id}",
      {},
      { renamed: ["users", "getGpgKeyForAuthenticatedUser"] }
    ],
    getGpgKeyForAuthenticatedUser: ["GET /user/gpg_keys/{gpg_key_id}"],
    getPublicSshKeyForAuthenticated: [
      "GET /user/keys/{key_id}",
      {},
      { renamed: ["users", "getPublicSshKeyForAuthenticatedUser"] }
    ],
    getPublicSshKeyForAuthenticatedUser: ["GET /user/keys/{key_id}"],
    getSshSigningKeyForAuthenticatedUser: [
      "GET /user/ssh_signing_keys/{ssh_signing_key_id}"
    ],
    list: ["GET /users"],
    listBlockedByAuthenticated: [
      "GET /user/blocks",
      {},
      { renamed: ["users", "listBlockedByAuthenticatedUser"] }
    ],
    listBlockedByAuthenticatedUser: ["GET /user/blocks"],
    listEmailsForAuthenticated: [
      "GET /user/emails",
      {},
      { renamed: ["users", "listEmailsForAuthenticatedUser"] }
    ],
    listEmailsForAuthenticatedUser: ["GET /user/emails"],
    listFollowedByAuthenticated: [
      "GET /user/following",
      {},
      { renamed: ["users", "listFollowedByAuthenticatedUser"] }
    ],
    listFollowedByAuthenticatedUser: ["GET /user/following"],
    listFollowersForAuthenticatedUser: ["GET /user/followers"],
    listFollowersForUser: ["GET /users/{username}/followers"],
    listFollowingForUser: ["GET /users/{username}/following"],
    listGpgKeysForAuthenticated: [
      "GET /user/gpg_keys",
      {},
      { renamed: ["users", "listGpgKeysForAuthenticatedUser"] }
    ],
    listGpgKeysForAuthenticatedUser: ["GET /user/gpg_keys"],
    listGpgKeysForUser: ["GET /users/{username}/gpg_keys"],
    listPublicEmailsForAuthenticated: [
      "GET /user/public_emails",
      {},
      { renamed: ["users", "listPublicEmailsForAuthenticatedUser"] }
    ],
    listPublicEmailsForAuthenticatedUser: ["GET /user/public_emails"],
    listPublicKeysForUser: ["GET /users/{username}/keys"],
    listPublicSshKeysForAuthenticated: [
      "GET /user/keys",
      {},
      { renamed: ["users", "listPublicSshKeysForAuthenticatedUser"] }
    ],
    listPublicSshKeysForAuthenticatedUser: ["GET /user/keys"],
    listSocialAccountsForAuthenticatedUser: ["GET /user/social_accounts"],
    listSocialAccountsForUser: ["GET /users/{username}/social_accounts"],
    listSshSigningKeysForAuthenticatedUser: ["GET /user/ssh_signing_keys"],
    listSshSigningKeysForUser: ["GET /users/{username}/ssh_signing_keys"],
    setPrimaryEmailVisibilityForAuthenticated: [
      "PATCH /user/email/visibility",
      {},
      { renamed: ["users", "setPrimaryEmailVisibilityForAuthenticatedUser"] }
    ],
    setPrimaryEmailVisibilityForAuthenticatedUser: [
      "PATCH /user/email/visibility"
    ],
    unblock: ["DELETE /user/blocks/{username}"],
    unfollow: ["DELETE /user/following/{username}"],
    updateAuthenticated: ["PATCH /user"]
  }
}, jf = Wf, Tt = /* @__PURE__ */ new Map();
for (const [e, A] of Object.entries(jf))
  for (const [t, r] of Object.entries(A)) {
    const [s, o, n] = r, [i, a] = s.split(/ /), g = Object.assign(
      {
        method: i,
        url: a
      },
      o
    );
    Tt.has(e) || Tt.set(e, /* @__PURE__ */ new Map()), Tt.get(e).set(t, {
      scope: e,
      methodName: t,
      endpointDefaults: g,
      decorations: n
    });
  }
var $f = {
  has({ scope: e }, A) {
    return Tt.get(e).has(A);
  },
  getOwnPropertyDescriptor(e, A) {
    return {
      value: this.get(e, A),
      // ensures method is in the cache
      configurable: !0,
      writable: !0,
      enumerable: !0
    };
  },
  defineProperty(e, A, t) {
    return Object.defineProperty(e.cache, A, t), !0;
  },
  deleteProperty(e, A) {
    return delete e.cache[A], !0;
  },
  ownKeys({ scope: e }) {
    return [...Tt.get(e).keys()];
  },
  set(e, A, t) {
    return e.cache[A] = t;
  },
  get({ octokit: e, scope: A, cache: t }, r) {
    if (t[r])
      return t[r];
    const s = Tt.get(A).get(r);
    if (!s)
      return;
    const { endpointDefaults: o, decorations: n } = s;
    return n ? t[r] = Kf(
      e,
      A,
      r,
      o,
      n
    ) : t[r] = e.request.defaults(o), t[r];
  }
};
function ou(e) {
  const A = {};
  for (const t of Tt.keys())
    A[t] = new Proxy({ octokit: e, scope: t, cache: {} }, $f);
  return A;
}
function Kf(e, A, t, r, s) {
  const o = e.request.defaults(r);
  function n(...i) {
    let a = o.endpoint.merge(...i);
    if (s.mapToData)
      return a = Object.assign({}, a, {
        data: a[s.mapToData],
        [s.mapToData]: void 0
      }), o(a);
    if (s.renamed) {
      const [g, c] = s.renamed;
      e.log.warn(
        `octokit.${A}.${t}() has been renamed to octokit.${g}.${c}()`
      );
    }
    if (s.deprecated && e.log.warn(s.deprecated), s.renamedParameters) {
      const g = o.endpoint.merge(...i);
      for (const [c, E] of Object.entries(
        s.renamedParameters
      ))
        c in g && (e.log.warn(
          `"${c}" parameter is deprecated for "octokit.${A}.${t}()". Use "${E}" instead`
        ), E in g || (g[E] = g[c]), delete g[c]);
      return o(g);
    }
    return o(...i);
  }
  return Object.assign(n, o);
}
function nu(e) {
  return {
    rest: ou(e)
  };
}
nu.VERSION = su;
function iu(e) {
  const A = ou(e);
  return {
    ...A,
    rest: A
  };
}
iu.VERSION = su;
const zf = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  legacyRestEndpointMethods: iu,
  restEndpointMethods: nu
}, Symbol.toStringTag, { value: "Module" })), Zf = /* @__PURE__ */ ui(zf);
var Xf = "9.2.1";
function em(e) {
  if (!e.data)
    return {
      ...e,
      data: []
    };
  if (!("total_count" in e.data && !("url" in e.data)))
    return e;
  const t = e.data.incomplete_results, r = e.data.repository_selection, s = e.data.total_count;
  delete e.data.incomplete_results, delete e.data.repository_selection, delete e.data.total_count;
  const o = Object.keys(e.data)[0], n = e.data[o];
  return e.data = n, typeof t < "u" && (e.data.incomplete_results = t), typeof r < "u" && (e.data.repository_selection = r), e.data.total_count = s, e;
}
function Gi(e, A, t) {
  const r = typeof A == "function" ? A.endpoint(t) : e.request.endpoint(A, t), s = typeof A == "function" ? A : e.request, o = r.method, n = r.headers;
  let i = r.url;
  return {
    [Symbol.asyncIterator]: () => ({
      async next() {
        if (!i)
          return { done: !0 };
        try {
          const a = await s({ method: o, url: i, headers: n }), g = em(a);
          return i = ((g.headers.link || "").match(
            /<([^>]+)>;\s*rel="next"/
          ) || [])[1], { value: g };
        } catch (a) {
          if (a.status !== 409)
            throw a;
          return i = "", {
            value: {
              status: 200,
              headers: {},
              data: []
            }
          };
        }
      }
    })
  };
}
function au(e, A, t, r) {
  return typeof t == "function" && (r = t, t = void 0), cu(
    e,
    [],
    Gi(e, A, t)[Symbol.asyncIterator](),
    r
  );
}
function cu(e, A, t, r) {
  return t.next().then((s) => {
    if (s.done)
      return A;
    let o = !1;
    function n() {
      o = !0;
    }
    return A = A.concat(
      r ? r(s.value, n) : s.value.data
    ), o ? A : cu(e, A, t, r);
  });
}
var Am = Object.assign(au, {
  iterator: Gi
}), gu = [
  "GET /advisories",
  "GET /app/hook/deliveries",
  "GET /app/installation-requests",
  "GET /app/installations",
  "GET /assignments/{assignment_id}/accepted_assignments",
  "GET /classrooms",
  "GET /classrooms/{classroom_id}/assignments",
  "GET /enterprises/{enterprise}/dependabot/alerts",
  "GET /enterprises/{enterprise}/secret-scanning/alerts",
  "GET /events",
  "GET /gists",
  "GET /gists/public",
  "GET /gists/starred",
  "GET /gists/{gist_id}/comments",
  "GET /gists/{gist_id}/commits",
  "GET /gists/{gist_id}/forks",
  "GET /installation/repositories",
  "GET /issues",
  "GET /licenses",
  "GET /marketplace_listing/plans",
  "GET /marketplace_listing/plans/{plan_id}/accounts",
  "GET /marketplace_listing/stubbed/plans",
  "GET /marketplace_listing/stubbed/plans/{plan_id}/accounts",
  "GET /networks/{owner}/{repo}/events",
  "GET /notifications",
  "GET /organizations",
  "GET /orgs/{org}/actions/cache/usage-by-repository",
  "GET /orgs/{org}/actions/permissions/repositories",
  "GET /orgs/{org}/actions/runners",
  "GET /orgs/{org}/actions/secrets",
  "GET /orgs/{org}/actions/secrets/{secret_name}/repositories",
  "GET /orgs/{org}/actions/variables",
  "GET /orgs/{org}/actions/variables/{name}/repositories",
  "GET /orgs/{org}/blocks",
  "GET /orgs/{org}/code-scanning/alerts",
  "GET /orgs/{org}/codespaces",
  "GET /orgs/{org}/codespaces/secrets",
  "GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories",
  "GET /orgs/{org}/copilot/billing/seats",
  "GET /orgs/{org}/dependabot/alerts",
  "GET /orgs/{org}/dependabot/secrets",
  "GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories",
  "GET /orgs/{org}/events",
  "GET /orgs/{org}/failed_invitations",
  "GET /orgs/{org}/hooks",
  "GET /orgs/{org}/hooks/{hook_id}/deliveries",
  "GET /orgs/{org}/installations",
  "GET /orgs/{org}/invitations",
  "GET /orgs/{org}/invitations/{invitation_id}/teams",
  "GET /orgs/{org}/issues",
  "GET /orgs/{org}/members",
  "GET /orgs/{org}/members/{username}/codespaces",
  "GET /orgs/{org}/migrations",
  "GET /orgs/{org}/migrations/{migration_id}/repositories",
  "GET /orgs/{org}/organization-roles/{role_id}/teams",
  "GET /orgs/{org}/organization-roles/{role_id}/users",
  "GET /orgs/{org}/outside_collaborators",
  "GET /orgs/{org}/packages",
  "GET /orgs/{org}/packages/{package_type}/{package_name}/versions",
  "GET /orgs/{org}/personal-access-token-requests",
  "GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories",
  "GET /orgs/{org}/personal-access-tokens",
  "GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories",
  "GET /orgs/{org}/projects",
  "GET /orgs/{org}/properties/values",
  "GET /orgs/{org}/public_members",
  "GET /orgs/{org}/repos",
  "GET /orgs/{org}/rulesets",
  "GET /orgs/{org}/rulesets/rule-suites",
  "GET /orgs/{org}/secret-scanning/alerts",
  "GET /orgs/{org}/security-advisories",
  "GET /orgs/{org}/teams",
  "GET /orgs/{org}/teams/{team_slug}/discussions",
  "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments",
  "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions",
  "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions",
  "GET /orgs/{org}/teams/{team_slug}/invitations",
  "GET /orgs/{org}/teams/{team_slug}/members",
  "GET /orgs/{org}/teams/{team_slug}/projects",
  "GET /orgs/{org}/teams/{team_slug}/repos",
  "GET /orgs/{org}/teams/{team_slug}/teams",
  "GET /projects/columns/{column_id}/cards",
  "GET /projects/{project_id}/collaborators",
  "GET /projects/{project_id}/columns",
  "GET /repos/{owner}/{repo}/actions/artifacts",
  "GET /repos/{owner}/{repo}/actions/caches",
  "GET /repos/{owner}/{repo}/actions/organization-secrets",
  "GET /repos/{owner}/{repo}/actions/organization-variables",
  "GET /repos/{owner}/{repo}/actions/runners",
  "GET /repos/{owner}/{repo}/actions/runs",
  "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
  "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs",
  "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs",
  "GET /repos/{owner}/{repo}/actions/secrets",
  "GET /repos/{owner}/{repo}/actions/variables",
  "GET /repos/{owner}/{repo}/actions/workflows",
  "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs",
  "GET /repos/{owner}/{repo}/activity",
  "GET /repos/{owner}/{repo}/assignees",
  "GET /repos/{owner}/{repo}/branches",
  "GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations",
  "GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs",
  "GET /repos/{owner}/{repo}/code-scanning/alerts",
  "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
  "GET /repos/{owner}/{repo}/code-scanning/analyses",
  "GET /repos/{owner}/{repo}/codespaces",
  "GET /repos/{owner}/{repo}/codespaces/devcontainers",
  "GET /repos/{owner}/{repo}/codespaces/secrets",
  "GET /repos/{owner}/{repo}/collaborators",
  "GET /repos/{owner}/{repo}/comments",
  "GET /repos/{owner}/{repo}/comments/{comment_id}/reactions",
  "GET /repos/{owner}/{repo}/commits",
  "GET /repos/{owner}/{repo}/commits/{commit_sha}/comments",
  "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls",
  "GET /repos/{owner}/{repo}/commits/{ref}/check-runs",
  "GET /repos/{owner}/{repo}/commits/{ref}/check-suites",
  "GET /repos/{owner}/{repo}/commits/{ref}/status",
  "GET /repos/{owner}/{repo}/commits/{ref}/statuses",
  "GET /repos/{owner}/{repo}/contributors",
  "GET /repos/{owner}/{repo}/dependabot/alerts",
  "GET /repos/{owner}/{repo}/dependabot/secrets",
  "GET /repos/{owner}/{repo}/deployments",
  "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses",
  "GET /repos/{owner}/{repo}/environments",
  "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies",
  "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps",
  "GET /repos/{owner}/{repo}/events",
  "GET /repos/{owner}/{repo}/forks",
  "GET /repos/{owner}/{repo}/hooks",
  "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries",
  "GET /repos/{owner}/{repo}/invitations",
  "GET /repos/{owner}/{repo}/issues",
  "GET /repos/{owner}/{repo}/issues/comments",
  "GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions",
  "GET /repos/{owner}/{repo}/issues/events",
  "GET /repos/{owner}/{repo}/issues/{issue_number}/comments",
  "GET /repos/{owner}/{repo}/issues/{issue_number}/events",
  "GET /repos/{owner}/{repo}/issues/{issue_number}/labels",
  "GET /repos/{owner}/{repo}/issues/{issue_number}/reactions",
  "GET /repos/{owner}/{repo}/issues/{issue_number}/timeline",
  "GET /repos/{owner}/{repo}/keys",
  "GET /repos/{owner}/{repo}/labels",
  "GET /repos/{owner}/{repo}/milestones",
  "GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels",
  "GET /repos/{owner}/{repo}/notifications",
  "GET /repos/{owner}/{repo}/pages/builds",
  "GET /repos/{owner}/{repo}/projects",
  "GET /repos/{owner}/{repo}/pulls",
  "GET /repos/{owner}/{repo}/pulls/comments",
  "GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions",
  "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments",
  "GET /repos/{owner}/{repo}/pulls/{pull_number}/commits",
  "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
  "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
  "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments",
  "GET /repos/{owner}/{repo}/releases",
  "GET /repos/{owner}/{repo}/releases/{release_id}/assets",
  "GET /repos/{owner}/{repo}/releases/{release_id}/reactions",
  "GET /repos/{owner}/{repo}/rules/branches/{branch}",
  "GET /repos/{owner}/{repo}/rulesets",
  "GET /repos/{owner}/{repo}/rulesets/rule-suites",
  "GET /repos/{owner}/{repo}/secret-scanning/alerts",
  "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations",
  "GET /repos/{owner}/{repo}/security-advisories",
  "GET /repos/{owner}/{repo}/stargazers",
  "GET /repos/{owner}/{repo}/subscribers",
  "GET /repos/{owner}/{repo}/tags",
  "GET /repos/{owner}/{repo}/teams",
  "GET /repos/{owner}/{repo}/topics",
  "GET /repositories",
  "GET /repositories/{repository_id}/environments/{environment_name}/secrets",
  "GET /repositories/{repository_id}/environments/{environment_name}/variables",
  "GET /search/code",
  "GET /search/commits",
  "GET /search/issues",
  "GET /search/labels",
  "GET /search/repositories",
  "GET /search/topics",
  "GET /search/users",
  "GET /teams/{team_id}/discussions",
  "GET /teams/{team_id}/discussions/{discussion_number}/comments",
  "GET /teams/{team_id}/discussions/{discussion_number}/comments/{comment_number}/reactions",
  "GET /teams/{team_id}/discussions/{discussion_number}/reactions",
  "GET /teams/{team_id}/invitations",
  "GET /teams/{team_id}/members",
  "GET /teams/{team_id}/projects",
  "GET /teams/{team_id}/repos",
  "GET /teams/{team_id}/teams",
  "GET /user/blocks",
  "GET /user/codespaces",
  "GET /user/codespaces/secrets",
  "GET /user/emails",
  "GET /user/followers",
  "GET /user/following",
  "GET /user/gpg_keys",
  "GET /user/installations",
  "GET /user/installations/{installation_id}/repositories",
  "GET /user/issues",
  "GET /user/keys",
  "GET /user/marketplace_purchases",
  "GET /user/marketplace_purchases/stubbed",
  "GET /user/memberships/orgs",
  "GET /user/migrations",
  "GET /user/migrations/{migration_id}/repositories",
  "GET /user/orgs",
  "GET /user/packages",
  "GET /user/packages/{package_type}/{package_name}/versions",
  "GET /user/public_emails",
  "GET /user/repos",
  "GET /user/repository_invitations",
  "GET /user/social_accounts",
  "GET /user/ssh_signing_keys",
  "GET /user/starred",
  "GET /user/subscriptions",
  "GET /user/teams",
  "GET /users",
  "GET /users/{username}/events",
  "GET /users/{username}/events/orgs/{org}",
  "GET /users/{username}/events/public",
  "GET /users/{username}/followers",
  "GET /users/{username}/following",
  "GET /users/{username}/gists",
  "GET /users/{username}/gpg_keys",
  "GET /users/{username}/keys",
  "GET /users/{username}/orgs",
  "GET /users/{username}/packages",
  "GET /users/{username}/projects",
  "GET /users/{username}/received_events",
  "GET /users/{username}/received_events/public",
  "GET /users/{username}/repos",
  "GET /users/{username}/social_accounts",
  "GET /users/{username}/ssh_signing_keys",
  "GET /users/{username}/starred",
  "GET /users/{username}/subscriptions"
];
function tm(e) {
  return typeof e == "string" ? gu.includes(e) : !1;
}
function lu(e) {
  return {
    paginate: Object.assign(au.bind(null, e), {
      iterator: Gi.bind(null, e)
    })
  };
}
lu.VERSION = Xf;
const rm = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  composePaginateRest: Am,
  isPaginatingEndpoint: tm,
  paginateRest: lu,
  paginatingEndpoints: gu
}, Symbol.toStringTag, { value: "Module" })), sm = /* @__PURE__ */ ui(rm);
(function(e) {
  var A = O && O.__createBinding || (Object.create ? function(E, l, Q, I) {
    I === void 0 && (I = Q);
    var d = Object.getOwnPropertyDescriptor(l, Q);
    (!d || ("get" in d ? !l.__esModule : d.writable || d.configurable)) && (d = { enumerable: !0, get: function() {
      return l[Q];
    } }), Object.defineProperty(E, I, d);
  } : function(E, l, Q, I) {
    I === void 0 && (I = Q), E[I] = l[Q];
  }), t = O && O.__setModuleDefault || (Object.create ? function(E, l) {
    Object.defineProperty(E, "default", { enumerable: !0, value: l });
  } : function(E, l) {
    E.default = l;
  }), r = O && O.__importStar || function(E) {
    if (E && E.__esModule) return E;
    var l = {};
    if (E != null) for (var Q in E) Q !== "default" && Object.prototype.hasOwnProperty.call(E, Q) && A(l, E, Q);
    return t(l, E), l;
  };
  Object.defineProperty(e, "__esModule", { value: !0 }), e.getOctokitOptions = e.GitHub = e.defaults = e.context = void 0;
  const s = r(Wr), o = r(mA), n = qf, i = Zf, a = sm;
  e.context = new s.Context();
  const g = o.getApiBaseUrl();
  e.defaults = {
    baseUrl: g,
    request: {
      agent: o.getProxyAgent(g),
      fetch: o.getProxyFetch(g)
    }
  }, e.GitHub = n.Octokit.plugin(i.restEndpointMethods, a.paginateRest).defaults(e.defaults);
  function c(E, l) {
    const Q = Object.assign({}, l || {}), I = o.getAuthString(E, Q);
    return I && (Q.auth = I), Q;
  }
  e.getOctokitOptions = c;
})(Al);
var om = O && O.__createBinding || (Object.create ? function(e, A, t, r) {
  r === void 0 && (r = t);
  var s = Object.getOwnPropertyDescriptor(A, t);
  (!s || ("get" in s ? !A.__esModule : s.writable || s.configurable)) && (s = { enumerable: !0, get: function() {
    return A[t];
  } }), Object.defineProperty(e, r, s);
} : function(e, A, t, r) {
  r === void 0 && (r = t), e[r] = A[t];
}), nm = O && O.__setModuleDefault || (Object.create ? function(e, A) {
  Object.defineProperty(e, "default", { enumerable: !0, value: A });
} : function(e, A) {
  e.default = A;
}), im = O && O.__importStar || function(e) {
  if (e && e.__esModule) return e;
  var A = {};
  if (e != null) for (var t in e) t !== "default" && Object.prototype.hasOwnProperty.call(e, t) && om(A, e, t);
  return nm(A, e), A;
};
Object.defineProperty(Or, "__esModule", { value: !0 });
var Eu = Or.getOctokit = _i = Or.context = void 0;
const am = im(Wr), ug = Al;
var _i = Or.context = new am.Context();
function cm(e, A, ...t) {
  const r = ug.GitHub.plugin(...t);
  return new r((0, ug.getOctokitOptions)(e, A));
}
Eu = Or.getOctokit = cm;
function so() {
  return typeof navigator == "object" && "userAgent" in navigator ? navigator.userAgent : typeof process == "object" && process.version !== void 0 ? `Node.js/${process.version.substr(1)} (${process.platform}; ${process.arch})` : "<environment undetectable>";
}
function uu(e, A, t, r) {
  if (typeof t != "function")
    throw new Error("method for before hook must be a function");
  return r || (r = {}), Array.isArray(A) ? A.reverse().reduce((s, o) => uu.bind(null, e, o, s, r), t)() : Promise.resolve().then(() => e.registry[A] ? e.registry[A].reduce((s, o) => o.hook.bind(null, s, r), t)() : t(r));
}
function gm(e, A, t, r) {
  const s = r;
  e.registry[t] || (e.registry[t] = []), A === "before" && (r = (o, n) => Promise.resolve().then(s.bind(null, n)).then(o.bind(null, n))), A === "after" && (r = (o, n) => {
    let i;
    return Promise.resolve().then(o.bind(null, n)).then((a) => (i = a, s(i, n))).then(() => i);
  }), A === "error" && (r = (o, n) => Promise.resolve().then(o.bind(null, n)).catch((i) => s(i, n))), e.registry[t].push({
    hook: r,
    orig: s
  });
}
function lm(e, A, t) {
  if (!e.registry[A])
    return;
  const r = e.registry[A].map((s) => s.orig).indexOf(t);
  r !== -1 && e.registry[A].splice(r, 1);
}
const hg = Function.bind, dg = hg.bind(hg);
function Em(e, A, t) {
  const r = dg(lm, null).apply(
    null,
    [A]
  );
  e.api = { remove: r }, e.remove = r, ["before", "error", "after", "wrap"].forEach((s) => {
    const o = [A, s];
    e[s] = e.api[s] = dg(gm, null).apply(null, o);
  });
}
function um() {
  const e = {
    registry: {}
  }, A = uu.bind(null, e);
  return Em(A, e), A;
}
const hm = { Collection: um };
var dm = "0.0.0-development", Qm = `octokit-endpoint.js/${dm} ${so()}`, Cm = {
  method: "GET",
  baseUrl: "https://api.github.com",
  headers: {
    accept: "application/vnd.github.v3+json",
    "user-agent": Qm
  },
  mediaType: {
    format: ""
  }
};
function Bm(e) {
  return e ? Object.keys(e).reduce((A, t) => (A[t.toLowerCase()] = e[t], A), {}) : {};
}
function Im(e) {
  if (typeof e != "object" || e === null || Object.prototype.toString.call(e) !== "[object Object]") return !1;
  const A = Object.getPrototypeOf(e);
  if (A === null) return !0;
  const t = Object.prototype.hasOwnProperty.call(A, "constructor") && A.constructor;
  return typeof t == "function" && t instanceof t && Function.prototype.call(t) === Function.prototype.call(e);
}
function hu(e, A) {
  const t = Object.assign({}, e);
  return Object.keys(A).forEach((r) => {
    Im(A[r]) ? r in e ? t[r] = hu(e[r], A[r]) : Object.assign(t, { [r]: A[r] }) : Object.assign(t, { [r]: A[r] });
  }), t;
}
function Qg(e) {
  for (const A in e)
    e[A] === void 0 && delete e[A];
  return e;
}
function ai(e, A, t) {
  if (typeof A == "string") {
    let [s, o] = A.split(" ");
    t = Object.assign(o ? { method: s, url: o } : { url: s }, t);
  } else
    t = Object.assign({}, A);
  t.headers = Bm(t.headers), Qg(t), Qg(t.headers);
  const r = hu(e || {}, t);
  return t.url === "/graphql" && (e && e.mediaType.previews?.length && (r.mediaType.previews = e.mediaType.previews.filter(
    (s) => !r.mediaType.previews.includes(s)
  ).concat(r.mediaType.previews)), r.mediaType.previews = (r.mediaType.previews || []).map((s) => s.replace(/-preview/, ""))), r;
}
function pm(e, A) {
  const t = /\?/.test(e) ? "&" : "?", r = Object.keys(A);
  return r.length === 0 ? e : e + t + r.map((s) => s === "q" ? "q=" + A.q.split("+").map(encodeURIComponent).join("+") : `${s}=${encodeURIComponent(A[s])}`).join("&");
}
var fm = /\{[^{}}]+\}/g;
function mm(e) {
  return e.replace(/(?:^\W+)|(?:(?<!\W)\W+$)/g, "").split(/,/);
}
function wm(e) {
  const A = e.match(fm);
  return A ? A.map(mm).reduce((t, r) => t.concat(r), []) : [];
}
function Cg(e, A) {
  const t = { __proto__: null };
  for (const r of Object.keys(e))
    A.indexOf(r) === -1 && (t[r] = e[r]);
  return t;
}
function du(e) {
  return e.split(/(%[0-9A-Fa-f]{2})/g).map(function(A) {
    return /%[0-9A-Fa-f]/.test(A) || (A = encodeURI(A).replace(/%5B/g, "[").replace(/%5D/g, "]")), A;
  }).join("");
}
function Wt(e) {
  return encodeURIComponent(e).replace(/[!'()*]/g, function(A) {
    return "%" + A.charCodeAt(0).toString(16).toUpperCase();
  });
}
function Tr(e, A, t) {
  return A = e === "+" || e === "#" ? du(A) : Wt(A), t ? Wt(t) + "=" + A : A;
}
function Ht(e) {
  return e != null;
}
function Ln(e) {
  return e === ";" || e === "&" || e === "?";
}
function ym(e, A, t, r) {
  var s = e[t], o = [];
  if (Ht(s) && s !== "")
    if (typeof s == "string" || typeof s == "number" || typeof s == "boolean")
      s = s.toString(), r && r !== "*" && (s = s.substring(0, parseInt(r, 10))), o.push(
        Tr(A, s, Ln(A) ? t : "")
      );
    else if (r === "*")
      Array.isArray(s) ? s.filter(Ht).forEach(function(n) {
        o.push(
          Tr(A, n, Ln(A) ? t : "")
        );
      }) : Object.keys(s).forEach(function(n) {
        Ht(s[n]) && o.push(Tr(A, s[n], n));
      });
    else {
      const n = [];
      Array.isArray(s) ? s.filter(Ht).forEach(function(i) {
        n.push(Tr(A, i));
      }) : Object.keys(s).forEach(function(i) {
        Ht(s[i]) && (n.push(Wt(i)), n.push(Tr(A, s[i].toString())));
      }), Ln(A) ? o.push(Wt(t) + "=" + n.join(",")) : n.length !== 0 && o.push(n.join(","));
    }
  else
    A === ";" ? Ht(s) && o.push(Wt(t)) : s === "" && (A === "&" || A === "?") ? o.push(Wt(t) + "=") : s === "" && o.push("");
  return o;
}
function bm(e) {
  return {
    expand: Rm.bind(null, e)
  };
}
function Rm(e, A) {
  var t = ["+", "#", ".", "/", ";", "?", "&"];
  return e = e.replace(
    /\{([^\{\}]+)\}|([^\{\}]+)/g,
    function(r, s, o) {
      if (s) {
        let i = "";
        const a = [];
        if (t.indexOf(s.charAt(0)) !== -1 && (i = s.charAt(0), s = s.substr(1)), s.split(/,/g).forEach(function(g) {
          var c = /([^:\*]*)(?::(\d+)|(\*))?/.exec(g);
          a.push(ym(A, i, c[1], c[2] || c[3]));
        }), i && i !== "+") {
          var n = ",";
          return i === "?" ? n = "&" : i !== "#" && (n = i), (a.length !== 0 ? i : "") + a.join(n);
        } else
          return a.join(",");
      } else
        return du(o);
    }
  ), e === "/" ? e : e.replace(/\/$/, "");
}
function Qu(e) {
  let A = e.method.toUpperCase(), t = (e.url || "/").replace(/:([a-z]\w+)/g, "{$1}"), r = Object.assign({}, e.headers), s, o = Cg(e, [
    "method",
    "baseUrl",
    "url",
    "headers",
    "request",
    "mediaType"
  ]);
  const n = wm(t);
  t = bm(t).expand(o), /^http/.test(t) || (t = e.baseUrl + t);
  const i = Object.keys(e).filter((c) => n.includes(c)).concat("baseUrl"), a = Cg(o, i);
  if (!/application\/octet-stream/i.test(r.accept) && (e.mediaType.format && (r.accept = r.accept.split(/,/).map(
    (c) => c.replace(
      /application\/vnd(\.\w+)(\.v3)?(\.\w+)?(\+json)?$/,
      `application/vnd$1$2.${e.mediaType.format}`
    )
  ).join(",")), t.endsWith("/graphql") && e.mediaType.previews?.length)) {
    const c = r.accept.match(/(?<![\w-])[\w-]+(?=-preview)/g) || [];
    r.accept = c.concat(e.mediaType.previews).map((E) => {
      const l = e.mediaType.format ? `.${e.mediaType.format}` : "+json";
      return `application/vnd.github.${E}-preview${l}`;
    }).join(",");
  }
  return ["GET", "HEAD"].includes(A) ? t = pm(t, a) : "data" in a ? s = a.data : Object.keys(a).length && (s = a), !r["content-type"] && typeof s < "u" && (r["content-type"] = "application/json; charset=utf-8"), ["PATCH", "PUT"].includes(A) && typeof s > "u" && (s = ""), Object.assign(
    { method: A, url: t, headers: r },
    typeof s < "u" ? { body: s } : null,
    e.request ? { request: e.request } : null
  );
}
function Dm(e, A, t) {
  return Qu(ai(e, A, t));
}
function Cu(e, A) {
  const t = ai(e, A), r = Dm.bind(null, t);
  return Object.assign(r, {
    DEFAULTS: t,
    defaults: Cu.bind(null, t),
    merge: ai.bind(null, t),
    parse: Qu
  });
}
var Tm = Cu(null, Cm);
const Ni = function() {
};
Ni.prototype = /* @__PURE__ */ Object.create(null);
const Bg = /; *([!#$%&'*+.^\w`|~-]+)=("(?:[\v\u0020\u0021\u0023-\u005b\u005d-\u007e\u0080-\u00ff]|\\[\v\u0020-\u00ff])*"|[!#$%&'*+.^\w`|~-]+) */gu, Ig = /\\([\v\u0020-\u00ff])/gu, km = /^[!#$%&'*+.^\w|~-]+\/[!#$%&'*+.^\w|~-]+$/u, jt = { type: "", parameters: new Ni() };
Object.freeze(jt.parameters);
Object.freeze(jt);
function Fm(e) {
  if (typeof e != "string")
    return jt;
  let A = e.indexOf(";");
  const t = A !== -1 ? e.slice(0, A).trim() : e.trim();
  if (km.test(t) === !1)
    return jt;
  const r = {
    type: t.toLowerCase(),
    parameters: new Ni()
  };
  if (A === -1)
    return r;
  let s, o, n;
  for (Bg.lastIndex = A; o = Bg.exec(e); ) {
    if (o.index !== A)
      return jt;
    A += o[0].length, s = o[1].toLowerCase(), n = o[2], n[0] === '"' && (n = n.slice(1, n.length - 1), Ig.test(n) && (n = n.replace(Ig, "$1"))), r.parameters[s] = n;
  }
  return A !== e.length ? jt : r;
}
var Sm = Fm;
class Gr extends Error {
  name;
  /**
   * http status code
   */
  status;
  /**
   * Request options that lead to the error.
   */
  request;
  /**
   * Response object if a response was received
   */
  response;
  constructor(A, t, r) {
    super(A), this.name = "HttpError", this.status = Number.parseInt(t), Number.isNaN(this.status) && (this.status = 0), "response" in r && (this.response = r.response);
    const s = Object.assign({}, r.request);
    r.request.headers.authorization && (s.headers = Object.assign({}, r.request.headers, {
      authorization: r.request.headers.authorization.replace(
        /(?<! ) .*$/,
        " [REDACTED]"
      )
    })), s.url = s.url.replace(/\bclient_secret=\w+/g, "client_secret=[REDACTED]").replace(/\baccess_token=\w+/g, "access_token=[REDACTED]"), this.request = s;
  }
}
var Um = "0.0.0-development", Gm = {
  headers: {
    "user-agent": `octokit-request.js/${Um} ${so()}`
  }
};
function _m(e) {
  if (typeof e != "object" || e === null || Object.prototype.toString.call(e) !== "[object Object]") return !1;
  const A = Object.getPrototypeOf(e);
  if (A === null) return !0;
  const t = Object.prototype.hasOwnProperty.call(A, "constructor") && A.constructor;
  return typeof t == "function" && t instanceof t && Function.prototype.call(t) === Function.prototype.call(e);
}
async function pg(e) {
  const A = e.request?.fetch || globalThis.fetch;
  if (!A)
    throw new Error(
      "fetch is not set. Please pass a fetch implementation as new Octokit({ request: { fetch }}). Learn more at https://github.com/octokit/octokit.js/#fetch-missing"
    );
  const t = e.request?.log || console, r = e.request?.parseSuccessResponseBody !== !1, s = _m(e.body) || Array.isArray(e.body) ? JSON.stringify(e.body) : e.body, o = Object.fromEntries(
    Object.entries(e.headers).map(([E, l]) => [
      E,
      String(l)
    ])
  );
  let n;
  try {
    n = await A(e.url, {
      method: e.method,
      body: s,
      redirect: e.request?.redirect,
      headers: o,
      signal: e.request?.signal,
      // duplex must be set if request.body is ReadableStream or Async Iterables.
      // See https://fetch.spec.whatwg.org/#dom-requestinit-duplex.
      ...e.body && { duplex: "half" }
    });
  } catch (E) {
    let l = "Unknown Error";
    if (E instanceof Error) {
      if (E.name === "AbortError")
        throw E.status = 500, E;
      l = E.message, E.name === "TypeError" && "cause" in E && (E.cause instanceof Error ? l = E.cause.message : typeof E.cause == "string" && (l = E.cause));
    }
    const Q = new Gr(l, 500, {
      request: e
    });
    throw Q.cause = E, Q;
  }
  const i = n.status, a = n.url, g = {};
  for (const [E, l] of n.headers)
    g[E] = l;
  const c = {
    url: a,
    status: i,
    headers: g,
    data: ""
  };
  if ("deprecation" in g) {
    const E = g.link && g.link.match(/<([^<>]+)>; rel="deprecation"/), l = E && E.pop();
    t.warn(
      `[@octokit/request] "${e.method} ${e.url}" is deprecated. It is scheduled to be removed on ${g.sunset}${l ? `. See ${l}` : ""}`
    );
  }
  if (i === 204 || i === 205)
    return c;
  if (e.method === "HEAD") {
    if (i < 400)
      return c;
    throw new Gr(n.statusText, i, {
      response: c,
      request: e
    });
  }
  if (i === 304)
    throw c.data = await Mn(n), new Gr("Not modified", i, {
      response: c,
      request: e
    });
  if (i >= 400)
    throw c.data = await Mn(n), new Gr(vm(c.data), i, {
      response: c,
      request: e
    });
  return c.data = r ? await Mn(n) : n.body, c;
}
async function Mn(e) {
  const A = e.headers.get("content-type");
  if (!A)
    return e.text().catch(() => "");
  const t = Sm(A);
  if (Nm(t)) {
    let r = "";
    try {
      return r = await e.text(), JSON.parse(r);
    } catch {
      return r;
    }
  } else return t.type.startsWith("text/") || t.parameters.charset?.toLowerCase() === "utf-8" ? e.text().catch(() => "") : e.arrayBuffer().catch(() => new ArrayBuffer(0));
}
function Nm(e) {
  return e.type === "application/json" || e.type === "application/scim+json";
}
function vm(e) {
  if (typeof e == "string")
    return e;
  if (e instanceof ArrayBuffer)
    return "Unknown error";
  if ("message" in e) {
    const A = "documentation_url" in e ? ` - ${e.documentation_url}` : "";
    return Array.isArray(e.errors) ? `${e.message}: ${e.errors.map((t) => JSON.stringify(t)).join(", ")}${A}` : `${e.message}${A}`;
  }
  return `Unknown error: ${JSON.stringify(e)}`;
}
function ci(e, A) {
  const t = e.defaults(A);
  return Object.assign(function(s, o) {
    const n = t.merge(s, o);
    if (!n.request || !n.request.hook)
      return pg(t.parse(n));
    const i = (a, g) => pg(
      t.parse(t.merge(a, g))
    );
    return Object.assign(i, {
      endpoint: t,
      defaults: ci.bind(null, t)
    }), n.request.hook(i, n);
  }, {
    endpoint: t,
    defaults: ci.bind(null, t)
  });
}
var gi = ci(Tm, Gm), Lm = "0.0.0-development";
function Mm(e) {
  return `Request failed due to following response errors:
` + e.errors.map((A) => ` - ${A.message}`).join(`
`);
}
var Om = class extends Error {
  constructor(e, A, t) {
    super(Mm(t)), this.request = e, this.headers = A, this.response = t, this.errors = t.errors, this.data = t.data, Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
  }
  name = "GraphqlResponseError";
  errors;
  data;
}, Pm = [
  "method",
  "baseUrl",
  "url",
  "headers",
  "request",
  "query",
  "mediaType",
  "operationName"
], Ym = ["query", "method", "url"], fg = /\/api\/v3\/?$/;
function xm(e, A, t) {
  if (t) {
    if (typeof A == "string" && "query" in t)
      return Promise.reject(
        new Error('[@octokit/graphql] "query" cannot be used as variable name')
      );
    for (const n in t)
      if (Ym.includes(n))
        return Promise.reject(
          new Error(
            `[@octokit/graphql] "${n}" cannot be used as variable name`
          )
        );
  }
  const r = typeof A == "string" ? Object.assign({ query: A }, t) : A, s = Object.keys(
    r
  ).reduce((n, i) => Pm.includes(i) ? (n[i] = r[i], n) : (n.variables || (n.variables = {}), n.variables[i] = r[i], n), {}), o = r.baseUrl || e.endpoint.DEFAULTS.baseUrl;
  return fg.test(o) && (s.url = o.replace(fg, "/api/graphql")), e(s).then((n) => {
    if (n.data.errors) {
      const i = {};
      for (const a of Object.keys(n.headers))
        i[a] = n.headers[a];
      throw new Om(
        s,
        i,
        n.data
      );
    }
    return n.data.data;
  });
}
function vi(e, A) {
  const t = e.defaults(A);
  return Object.assign((s, o) => xm(t, s, o), {
    defaults: vi.bind(null, t),
    endpoint: t.endpoint
  });
}
vi(gi, {
  headers: {
    "user-agent": `octokit-graphql.js/${Lm} ${so()}`
  },
  method: "POST",
  url: "/graphql"
});
function Jm(e) {
  return vi(e, {
    method: "POST",
    url: "/graphql"
  });
}
var On = "(?:[a-zA-Z0-9_-]+)", mg = "\\.", wg = new RegExp(`^${On}${mg}${On}${mg}${On}$`), Hm = wg.test.bind(wg);
async function Vm(e) {
  const A = Hm(e), t = e.startsWith("v1.") || e.startsWith("ghs_"), r = e.startsWith("ghu_");
  return {
    type: "token",
    token: e,
    tokenType: A ? "app" : t ? "installation" : r ? "user-to-server" : "oauth"
  };
}
function qm(e) {
  return e.split(/\./).length === 3 ? `bearer ${e}` : `token ${e}`;
}
async function Wm(e, A, t, r) {
  const s = A.endpoint.merge(
    t,
    r
  );
  return s.headers.authorization = qm(e), A(s);
}
var jm = function(A) {
  if (!A)
    throw new Error("[@octokit/auth-token] No token passed to createTokenAuth");
  if (typeof A != "string")
    throw new Error(
      "[@octokit/auth-token] Token passed to createTokenAuth is not a string"
    );
  return A = A.replace(/^(token|bearer) +/i, ""), Object.assign(Vm.bind(null, A), {
    hook: Wm.bind(null, A)
  });
};
const Bu = "6.1.4", yg = () => {
}, $m = console.warn.bind(console), Km = console.error.bind(console), bg = `octokit-core.js/${Bu} ${so()}`;
let zm = class {
  static VERSION = Bu;
  static defaults(A) {
    return class extends this {
      constructor(...r) {
        const s = r[0] || {};
        if (typeof A == "function") {
          super(A(s));
          return;
        }
        super(
          Object.assign(
            {},
            A,
            s,
            s.userAgent && A.userAgent ? {
              userAgent: `${s.userAgent} ${A.userAgent}`
            } : null
          )
        );
      }
    };
  }
  static plugins = [];
  /**
   * Attach a plugin (or many) to your Octokit instance.
   *
   * @example
   * const API = Octokit.plugin(plugin1, plugin2, plugin3, ...)
   */
  static plugin(...A) {
    const t = this.plugins;
    return class extends this {
      static plugins = t.concat(
        A.filter((s) => !t.includes(s))
      );
    };
  }
  constructor(A = {}) {
    const t = new hm.Collection(), r = {
      baseUrl: gi.endpoint.DEFAULTS.baseUrl,
      headers: {},
      request: Object.assign({}, A.request, {
        // @ts-ignore internal usage only, no need to type
        hook: t.bind(null, "request")
      }),
      mediaType: {
        previews: [],
        format: ""
      }
    };
    if (r.headers["user-agent"] = A.userAgent ? `${A.userAgent} ${bg}` : bg, A.baseUrl && (r.baseUrl = A.baseUrl), A.previews && (r.mediaType.previews = A.previews), A.timeZone && (r.headers["time-zone"] = A.timeZone), this.request = gi.defaults(r), this.graphql = Jm(this.request).defaults(r), this.log = Object.assign(
      {
        debug: yg,
        info: yg,
        warn: $m,
        error: Km
      },
      A.log
    ), this.hook = t, A.authStrategy) {
      const { authStrategy: o, ...n } = A, i = o(
        Object.assign(
          {
            request: this.request,
            log: this.log,
            // we pass the current octokit instance as well as its constructor options
            // to allow for authentication strategies that return a new octokit instance
            // that shares the same internal state as the current one. The original
            // requirement for this was the "event-octokit" authentication strategy
            // of https://github.com/probot/octokit-auth-probot.
            octokit: this,
            octokitOptions: n
          },
          A.auth
        )
      );
      t.wrap("request", i.hook), this.auth = i;
    } else if (!A.auth)
      this.auth = async () => ({
        type: "unauthenticated"
      });
    else {
      const o = jm(A.auth);
      t.wrap("request", o.hook), this.auth = o;
    }
    const s = this.constructor;
    for (let o = 0; o < s.plugins.length; ++o)
      Object.assign(this, s.plugins[o](this, A));
  }
  // assigned during constructor
  request;
  graphql;
  log;
  hook;
  // TODO: type `octokit.auth` based on passed options.authStrategy
  auth;
};
var Zm = "0.0.0-development";
function Xm(e) {
  if (!e.data)
    return {
      ...e,
      data: []
    };
  if (!("total_count" in e.data && !("url" in e.data))) return e;
  const t = e.data.incomplete_results, r = e.data.repository_selection, s = e.data.total_count;
  delete e.data.incomplete_results, delete e.data.repository_selection, delete e.data.total_count;
  const o = Object.keys(e.data)[0], n = e.data[o];
  return e.data = n, typeof t < "u" && (e.data.incomplete_results = t), typeof r < "u" && (e.data.repository_selection = r), e.data.total_count = s, e;
}
function Li(e, A, t) {
  const r = typeof A == "function" ? A.endpoint(t) : e.request.endpoint(A, t), s = typeof A == "function" ? A : e.request, o = r.method, n = r.headers;
  let i = r.url;
  return {
    [Symbol.asyncIterator]: () => ({
      async next() {
        if (!i) return { done: !0 };
        try {
          const a = await s({ method: o, url: i, headers: n }), g = Xm(a);
          return i = ((g.headers.link || "").match(
            /<([^<>]+)>;\s*rel="next"/
          ) || [])[1], { value: g };
        } catch (a) {
          if (a.status !== 409) throw a;
          return i = "", {
            value: {
              status: 200,
              headers: {},
              data: []
            }
          };
        }
      }
    })
  };
}
function Iu(e, A, t, r) {
  return typeof t == "function" && (r = t, t = void 0), pu(
    e,
    [],
    Li(e, A, t)[Symbol.asyncIterator](),
    r
  );
}
function pu(e, A, t, r) {
  return t.next().then((s) => {
    if (s.done)
      return A;
    let o = !1;
    function n() {
      o = !0;
    }
    return A = A.concat(
      r ? r(s.value, n) : s.value.data
    ), o ? A : pu(e, A, t, r);
  });
}
Object.assign(Iu, {
  iterator: Li
});
function fu(e) {
  return {
    paginate: Object.assign(Iu.bind(null, e), {
      iterator: Li.bind(null, e)
    })
  };
}
fu.VERSION = Zm;
var ew = (e, A) => `The cursor at "${e.join(
  ","
)}" did not change its value "${A}" after a page transition. Please make sure your that your query is set up correctly.`, Aw = class extends Error {
  constructor(e, A) {
    super(ew(e.pathInQuery, A)), this.pageInfo = e, this.cursorValue = A, Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
  }
  name = "MissingCursorChangeError";
}, tw = class extends Error {
  constructor(e) {
    super(
      `No pageInfo property found in response. Please make sure to specify the pageInfo in your query. Response-Data: ${JSON.stringify(
        e,
        null,
        2
      )}`
    ), this.response = e, Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
  }
  name = "MissingPageInfo";
}, rw = (e) => Object.prototype.toString.call(e) === "[object Object]";
function mu(e) {
  const A = wu(
    e,
    "pageInfo"
  );
  if (A.length === 0)
    throw new tw(e);
  return A;
}
var wu = (e, A, t = []) => {
  for (const r of Object.keys(e)) {
    const s = [...t, r], o = e[r];
    if (rw(o)) {
      if (o.hasOwnProperty(A))
        return s;
      const n = wu(
        o,
        A,
        s
      );
      if (n.length > 0)
        return n;
    }
  }
  return [];
}, Lr = (e, A) => A.reduce((t, r) => t[r], e), Pn = (e, A, t) => {
  const r = A[A.length - 1], s = [...A].slice(0, -1), o = Lr(e, s);
  typeof t == "function" ? o[r] = t(o[r]) : o[r] = t;
}, sw = (e) => {
  const A = mu(e);
  return {
    pathInQuery: A,
    pageInfo: Lr(e, [...A, "pageInfo"])
  };
}, yu = (e) => e.hasOwnProperty("hasNextPage"), ow = (e) => yu(e) ? e.endCursor : e.startCursor, nw = (e) => yu(e) ? e.hasNextPage : e.hasPreviousPage, bu = (e) => (A, t = {}) => {
  let r = !0, s = { ...t };
  return {
    [Symbol.asyncIterator]: () => ({
      async next() {
        if (!r) return { done: !0, value: {} };
        const o = await e.graphql(
          A,
          s
        ), n = sw(o), i = ow(n.pageInfo);
        if (r = nw(n.pageInfo), r && i === s.cursor)
          throw new Aw(n, i);
        return s = {
          ...s,
          cursor: i
        }, { done: !1, value: o };
      }
    })
  };
}, iw = (e, A) => {
  if (Object.keys(e).length === 0)
    return Object.assign(e, A);
  const t = mu(e), r = [...t, "nodes"], s = Lr(A, r);
  s && Pn(e, r, (a) => [...a, ...s]);
  const o = [...t, "edges"], n = Lr(A, o);
  n && Pn(e, o, (a) => [...a, ...n]);
  const i = [...t, "pageInfo"];
  return Pn(e, i, Lr(A, i)), e;
}, aw = (e) => {
  const A = bu(e);
  return async (t, r = {}) => {
    let s = {};
    for await (const o of A(
      t,
      r
    ))
      s = iw(s, o);
    return s;
  };
};
function cw(e) {
  return {
    graphql: Object.assign(e.graphql, {
      paginate: Object.assign(aw(e), {
        iterator: bu(e)
      })
    })
  };
}
const gw = "13.3.1", lw = {
  actions: {
    addCustomLabelsToSelfHostedRunnerForOrg: [
      "POST /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    addCustomLabelsToSelfHostedRunnerForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    addRepoAccessToSelfHostedRunnerGroupInOrg: [
      "PUT /orgs/{org}/actions/runner-groups/{runner_group_id}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgVariable: [
      "PUT /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
    ],
    approveWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve"
    ],
    cancelWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel"
    ],
    createEnvironmentVariable: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/variables"
    ],
    createOrUpdateEnvironmentSecret: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}"
    ],
    createOrUpdateOrgSecret: ["PUT /orgs/{org}/actions/secrets/{secret_name}"],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}"
    ],
    createOrgVariable: ["POST /orgs/{org}/actions/variables"],
    createRegistrationTokenForOrg: [
      "POST /orgs/{org}/actions/runners/registration-token"
    ],
    createRegistrationTokenForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/registration-token"
    ],
    createRemoveTokenForOrg: ["POST /orgs/{org}/actions/runners/remove-token"],
    createRemoveTokenForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/remove-token"
    ],
    createRepoVariable: ["POST /repos/{owner}/{repo}/actions/variables"],
    createWorkflowDispatch: [
      "POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
    ],
    deleteActionsCacheById: [
      "DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}"
    ],
    deleteActionsCacheByKey: [
      "DELETE /repos/{owner}/{repo}/actions/caches{?key,ref}"
    ],
    deleteArtifact: [
      "DELETE /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"
    ],
    deleteEnvironmentSecret: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}"
    ],
    deleteEnvironmentVariable: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/actions/secrets/{secret_name}"],
    deleteOrgVariable: ["DELETE /orgs/{org}/actions/variables/{name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}"
    ],
    deleteRepoVariable: [
      "DELETE /repos/{owner}/{repo}/actions/variables/{name}"
    ],
    deleteSelfHostedRunnerFromOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}"
    ],
    deleteSelfHostedRunnerFromRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}"
    ],
    deleteWorkflowRun: ["DELETE /repos/{owner}/{repo}/actions/runs/{run_id}"],
    deleteWorkflowRunLogs: [
      "DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    ],
    disableSelectedRepositoryGithubActionsOrganization: [
      "DELETE /orgs/{org}/actions/permissions/repositories/{repository_id}"
    ],
    disableWorkflow: [
      "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable"
    ],
    downloadArtifact: [
      "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}"
    ],
    downloadJobLogsForWorkflowRun: [
      "GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
    ],
    downloadWorkflowRunAttemptLogs: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs"
    ],
    downloadWorkflowRunLogs: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    ],
    enableSelectedRepositoryGithubActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/repositories/{repository_id}"
    ],
    enableWorkflow: [
      "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable"
    ],
    forceCancelWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/force-cancel"
    ],
    generateRunnerJitconfigForOrg: [
      "POST /orgs/{org}/actions/runners/generate-jitconfig"
    ],
    generateRunnerJitconfigForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig"
    ],
    getActionsCacheList: ["GET /repos/{owner}/{repo}/actions/caches"],
    getActionsCacheUsage: ["GET /repos/{owner}/{repo}/actions/cache/usage"],
    getActionsCacheUsageByRepoForOrg: [
      "GET /orgs/{org}/actions/cache/usage-by-repository"
    ],
    getActionsCacheUsageForOrg: ["GET /orgs/{org}/actions/cache/usage"],
    getAllowedActionsOrganization: [
      "GET /orgs/{org}/actions/permissions/selected-actions"
    ],
    getAllowedActionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/selected-actions"
    ],
    getArtifact: ["GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"],
    getCustomOidcSubClaimForRepo: [
      "GET /repos/{owner}/{repo}/actions/oidc/customization/sub"
    ],
    getEnvironmentPublicKey: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/public-key"
    ],
    getEnvironmentSecret: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}"
    ],
    getEnvironmentVariable: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}"
    ],
    getGithubActionsDefaultWorkflowPermissionsOrganization: [
      "GET /orgs/{org}/actions/permissions/workflow"
    ],
    getGithubActionsDefaultWorkflowPermissionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/workflow"
    ],
    getGithubActionsPermissionsOrganization: [
      "GET /orgs/{org}/actions/permissions"
    ],
    getGithubActionsPermissionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions"
    ],
    getJobForWorkflowRun: ["GET /repos/{owner}/{repo}/actions/jobs/{job_id}"],
    getOrgPublicKey: ["GET /orgs/{org}/actions/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/actions/secrets/{secret_name}"],
    getOrgVariable: ["GET /orgs/{org}/actions/variables/{name}"],
    getPendingDeploymentsForRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
    ],
    getRepoPermissions: [
      "GET /repos/{owner}/{repo}/actions/permissions",
      {},
      { renamed: ["actions", "getGithubActionsPermissionsRepository"] }
    ],
    getRepoPublicKey: ["GET /repos/{owner}/{repo}/actions/secrets/public-key"],
    getRepoSecret: ["GET /repos/{owner}/{repo}/actions/secrets/{secret_name}"],
    getRepoVariable: ["GET /repos/{owner}/{repo}/actions/variables/{name}"],
    getReviewsForRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals"
    ],
    getSelfHostedRunnerForOrg: ["GET /orgs/{org}/actions/runners/{runner_id}"],
    getSelfHostedRunnerForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/{runner_id}"
    ],
    getWorkflow: ["GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}"],
    getWorkflowAccessToRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/access"
    ],
    getWorkflowRun: ["GET /repos/{owner}/{repo}/actions/runs/{run_id}"],
    getWorkflowRunAttempt: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}"
    ],
    getWorkflowRunUsage: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/timing"
    ],
    getWorkflowUsage: [
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/timing"
    ],
    listArtifactsForRepo: ["GET /repos/{owner}/{repo}/actions/artifacts"],
    listEnvironmentSecrets: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets"
    ],
    listEnvironmentVariables: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/variables"
    ],
    listJobsForWorkflowRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
    ],
    listJobsForWorkflowRunAttempt: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs"
    ],
    listLabelsForSelfHostedRunnerForOrg: [
      "GET /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    listLabelsForSelfHostedRunnerForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    listOrgSecrets: ["GET /orgs/{org}/actions/secrets"],
    listOrgVariables: ["GET /orgs/{org}/actions/variables"],
    listRepoOrganizationSecrets: [
      "GET /repos/{owner}/{repo}/actions/organization-secrets"
    ],
    listRepoOrganizationVariables: [
      "GET /repos/{owner}/{repo}/actions/organization-variables"
    ],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/actions/secrets"],
    listRepoVariables: ["GET /repos/{owner}/{repo}/actions/variables"],
    listRepoWorkflows: ["GET /repos/{owner}/{repo}/actions/workflows"],
    listRunnerApplicationsForOrg: ["GET /orgs/{org}/actions/runners/downloads"],
    listRunnerApplicationsForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/downloads"
    ],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/actions/secrets/{secret_name}/repositories"
    ],
    listSelectedReposForOrgVariable: [
      "GET /orgs/{org}/actions/variables/{name}/repositories"
    ],
    listSelectedRepositoriesEnabledGithubActionsOrganization: [
      "GET /orgs/{org}/actions/permissions/repositories"
    ],
    listSelfHostedRunnersForOrg: ["GET /orgs/{org}/actions/runners"],
    listSelfHostedRunnersForRepo: ["GET /repos/{owner}/{repo}/actions/runners"],
    listWorkflowRunArtifacts: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    ],
    listWorkflowRuns: [
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
    ],
    listWorkflowRunsForRepo: ["GET /repos/{owner}/{repo}/actions/runs"],
    reRunJobForWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/jobs/{job_id}/rerun"
    ],
    reRunWorkflow: ["POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun"],
    reRunWorkflowFailedJobs: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs"
    ],
    removeAllCustomLabelsFromSelfHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    removeAllCustomLabelsFromSelfHostedRunnerForRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    removeCustomLabelFromSelfHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}/labels/{name}"
    ],
    removeCustomLabelFromSelfHostedRunnerForRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels/{name}"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
    ],
    removeSelectedRepoFromOrgVariable: [
      "DELETE /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
    ],
    reviewCustomGatesForRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule"
    ],
    reviewPendingDeploymentsForRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
    ],
    setAllowedActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/selected-actions"
    ],
    setAllowedActionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/selected-actions"
    ],
    setCustomLabelsForSelfHostedRunnerForOrg: [
      "PUT /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    setCustomLabelsForSelfHostedRunnerForRepo: [
      "PUT /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    setCustomOidcSubClaimForRepo: [
      "PUT /repos/{owner}/{repo}/actions/oidc/customization/sub"
    ],
    setGithubActionsDefaultWorkflowPermissionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/workflow"
    ],
    setGithubActionsDefaultWorkflowPermissionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/workflow"
    ],
    setGithubActionsPermissionsOrganization: [
      "PUT /orgs/{org}/actions/permissions"
    ],
    setGithubActionsPermissionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories"
    ],
    setSelectedReposForOrgVariable: [
      "PUT /orgs/{org}/actions/variables/{name}/repositories"
    ],
    setSelectedRepositoriesEnabledGithubActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/repositories"
    ],
    setWorkflowAccessToRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/access"
    ],
    updateEnvironmentVariable: [
      "PATCH /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}"
    ],
    updateOrgVariable: ["PATCH /orgs/{org}/actions/variables/{name}"],
    updateRepoVariable: [
      "PATCH /repos/{owner}/{repo}/actions/variables/{name}"
    ]
  },
  activity: {
    checkRepoIsStarredByAuthenticatedUser: ["GET /user/starred/{owner}/{repo}"],
    deleteRepoSubscription: ["DELETE /repos/{owner}/{repo}/subscription"],
    deleteThreadSubscription: [
      "DELETE /notifications/threads/{thread_id}/subscription"
    ],
    getFeeds: ["GET /feeds"],
    getRepoSubscription: ["GET /repos/{owner}/{repo}/subscription"],
    getThread: ["GET /notifications/threads/{thread_id}"],
    getThreadSubscriptionForAuthenticatedUser: [
      "GET /notifications/threads/{thread_id}/subscription"
    ],
    listEventsForAuthenticatedUser: ["GET /users/{username}/events"],
    listNotificationsForAuthenticatedUser: ["GET /notifications"],
    listOrgEventsForAuthenticatedUser: [
      "GET /users/{username}/events/orgs/{org}"
    ],
    listPublicEvents: ["GET /events"],
    listPublicEventsForRepoNetwork: ["GET /networks/{owner}/{repo}/events"],
    listPublicEventsForUser: ["GET /users/{username}/events/public"],
    listPublicOrgEvents: ["GET /orgs/{org}/events"],
    listReceivedEventsForUser: ["GET /users/{username}/received_events"],
    listReceivedPublicEventsForUser: [
      "GET /users/{username}/received_events/public"
    ],
    listRepoEvents: ["GET /repos/{owner}/{repo}/events"],
    listRepoNotificationsForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/notifications"
    ],
    listReposStarredByAuthenticatedUser: ["GET /user/starred"],
    listReposStarredByUser: ["GET /users/{username}/starred"],
    listReposWatchedByUser: ["GET /users/{username}/subscriptions"],
    listStargazersForRepo: ["GET /repos/{owner}/{repo}/stargazers"],
    listWatchedReposForAuthenticatedUser: ["GET /user/subscriptions"],
    listWatchersForRepo: ["GET /repos/{owner}/{repo}/subscribers"],
    markNotificationsAsRead: ["PUT /notifications"],
    markRepoNotificationsAsRead: ["PUT /repos/{owner}/{repo}/notifications"],
    markThreadAsDone: ["DELETE /notifications/threads/{thread_id}"],
    markThreadAsRead: ["PATCH /notifications/threads/{thread_id}"],
    setRepoSubscription: ["PUT /repos/{owner}/{repo}/subscription"],
    setThreadSubscription: [
      "PUT /notifications/threads/{thread_id}/subscription"
    ],
    starRepoForAuthenticatedUser: ["PUT /user/starred/{owner}/{repo}"],
    unstarRepoForAuthenticatedUser: ["DELETE /user/starred/{owner}/{repo}"]
  },
  apps: {
    addRepoToInstallation: [
      "PUT /user/installations/{installation_id}/repositories/{repository_id}",
      {},
      { renamed: ["apps", "addRepoToInstallationForAuthenticatedUser"] }
    ],
    addRepoToInstallationForAuthenticatedUser: [
      "PUT /user/installations/{installation_id}/repositories/{repository_id}"
    ],
    checkToken: ["POST /applications/{client_id}/token"],
    createFromManifest: ["POST /app-manifests/{code}/conversions"],
    createInstallationAccessToken: [
      "POST /app/installations/{installation_id}/access_tokens"
    ],
    deleteAuthorization: ["DELETE /applications/{client_id}/grant"],
    deleteInstallation: ["DELETE /app/installations/{installation_id}"],
    deleteToken: ["DELETE /applications/{client_id}/token"],
    getAuthenticated: ["GET /app"],
    getBySlug: ["GET /apps/{app_slug}"],
    getInstallation: ["GET /app/installations/{installation_id}"],
    getOrgInstallation: ["GET /orgs/{org}/installation"],
    getRepoInstallation: ["GET /repos/{owner}/{repo}/installation"],
    getSubscriptionPlanForAccount: [
      "GET /marketplace_listing/accounts/{account_id}"
    ],
    getSubscriptionPlanForAccountStubbed: [
      "GET /marketplace_listing/stubbed/accounts/{account_id}"
    ],
    getUserInstallation: ["GET /users/{username}/installation"],
    getWebhookConfigForApp: ["GET /app/hook/config"],
    getWebhookDelivery: ["GET /app/hook/deliveries/{delivery_id}"],
    listAccountsForPlan: ["GET /marketplace_listing/plans/{plan_id}/accounts"],
    listAccountsForPlanStubbed: [
      "GET /marketplace_listing/stubbed/plans/{plan_id}/accounts"
    ],
    listInstallationReposForAuthenticatedUser: [
      "GET /user/installations/{installation_id}/repositories"
    ],
    listInstallationRequestsForAuthenticatedApp: [
      "GET /app/installation-requests"
    ],
    listInstallations: ["GET /app/installations"],
    listInstallationsForAuthenticatedUser: ["GET /user/installations"],
    listPlans: ["GET /marketplace_listing/plans"],
    listPlansStubbed: ["GET /marketplace_listing/stubbed/plans"],
    listReposAccessibleToInstallation: ["GET /installation/repositories"],
    listSubscriptionsForAuthenticatedUser: ["GET /user/marketplace_purchases"],
    listSubscriptionsForAuthenticatedUserStubbed: [
      "GET /user/marketplace_purchases/stubbed"
    ],
    listWebhookDeliveries: ["GET /app/hook/deliveries"],
    redeliverWebhookDelivery: [
      "POST /app/hook/deliveries/{delivery_id}/attempts"
    ],
    removeRepoFromInstallation: [
      "DELETE /user/installations/{installation_id}/repositories/{repository_id}",
      {},
      { renamed: ["apps", "removeRepoFromInstallationForAuthenticatedUser"] }
    ],
    removeRepoFromInstallationForAuthenticatedUser: [
      "DELETE /user/installations/{installation_id}/repositories/{repository_id}"
    ],
    resetToken: ["PATCH /applications/{client_id}/token"],
    revokeInstallationAccessToken: ["DELETE /installation/token"],
    scopeToken: ["POST /applications/{client_id}/token/scoped"],
    suspendInstallation: ["PUT /app/installations/{installation_id}/suspended"],
    unsuspendInstallation: [
      "DELETE /app/installations/{installation_id}/suspended"
    ],
    updateWebhookConfigForApp: ["PATCH /app/hook/config"]
  },
  billing: {
    getGithubActionsBillingOrg: ["GET /orgs/{org}/settings/billing/actions"],
    getGithubActionsBillingUser: [
      "GET /users/{username}/settings/billing/actions"
    ],
    getGithubBillingUsageReportOrg: [
      "GET /organizations/{org}/settings/billing/usage"
    ],
    getGithubPackagesBillingOrg: ["GET /orgs/{org}/settings/billing/packages"],
    getGithubPackagesBillingUser: [
      "GET /users/{username}/settings/billing/packages"
    ],
    getSharedStorageBillingOrg: [
      "GET /orgs/{org}/settings/billing/shared-storage"
    ],
    getSharedStorageBillingUser: [
      "GET /users/{username}/settings/billing/shared-storage"
    ]
  },
  checks: {
    create: ["POST /repos/{owner}/{repo}/check-runs"],
    createSuite: ["POST /repos/{owner}/{repo}/check-suites"],
    get: ["GET /repos/{owner}/{repo}/check-runs/{check_run_id}"],
    getSuite: ["GET /repos/{owner}/{repo}/check-suites/{check_suite_id}"],
    listAnnotations: [
      "GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations"
    ],
    listForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-runs"],
    listForSuite: [
      "GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs"
    ],
    listSuitesForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-suites"],
    rerequestRun: [
      "POST /repos/{owner}/{repo}/check-runs/{check_run_id}/rerequest"
    ],
    rerequestSuite: [
      "POST /repos/{owner}/{repo}/check-suites/{check_suite_id}/rerequest"
    ],
    setSuitesPreferences: [
      "PATCH /repos/{owner}/{repo}/check-suites/preferences"
    ],
    update: ["PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}"]
  },
  codeScanning: {
    commitAutofix: [
      "POST /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/autofix/commits"
    ],
    createAutofix: [
      "POST /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/autofix"
    ],
    createVariantAnalysis: [
      "POST /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses"
    ],
    deleteAnalysis: [
      "DELETE /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}{?confirm_delete}"
    ],
    deleteCodeqlDatabase: [
      "DELETE /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
    ],
    getAlert: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
      {},
      { renamedParameters: { alert_id: "alert_number" } }
    ],
    getAnalysis: [
      "GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}"
    ],
    getAutofix: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/autofix"
    ],
    getCodeqlDatabase: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
    ],
    getDefaultSetup: ["GET /repos/{owner}/{repo}/code-scanning/default-setup"],
    getSarif: ["GET /repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}"],
    getVariantAnalysis: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{codeql_variant_analysis_id}"
    ],
    getVariantAnalysisRepoTask: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{codeql_variant_analysis_id}/repos/{repo_owner}/{repo_name}"
    ],
    listAlertInstances: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/code-scanning/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/code-scanning/alerts"],
    listAlertsInstances: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
      {},
      { renamed: ["codeScanning", "listAlertInstances"] }
    ],
    listCodeqlDatabases: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/databases"
    ],
    listRecentAnalyses: ["GET /repos/{owner}/{repo}/code-scanning/analyses"],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    ],
    updateDefaultSetup: [
      "PATCH /repos/{owner}/{repo}/code-scanning/default-setup"
    ],
    uploadSarif: ["POST /repos/{owner}/{repo}/code-scanning/sarifs"]
  },
  codeSecurity: {
    attachConfiguration: [
      "POST /orgs/{org}/code-security/configurations/{configuration_id}/attach"
    ],
    attachEnterpriseConfiguration: [
      "POST /enterprises/{enterprise}/code-security/configurations/{configuration_id}/attach"
    ],
    createConfiguration: ["POST /orgs/{org}/code-security/configurations"],
    createConfigurationForEnterprise: [
      "POST /enterprises/{enterprise}/code-security/configurations"
    ],
    deleteConfiguration: [
      "DELETE /orgs/{org}/code-security/configurations/{configuration_id}"
    ],
    deleteConfigurationForEnterprise: [
      "DELETE /enterprises/{enterprise}/code-security/configurations/{configuration_id}"
    ],
    detachConfiguration: [
      "DELETE /orgs/{org}/code-security/configurations/detach"
    ],
    getConfiguration: [
      "GET /orgs/{org}/code-security/configurations/{configuration_id}"
    ],
    getConfigurationForRepository: [
      "GET /repos/{owner}/{repo}/code-security-configuration"
    ],
    getConfigurationsForEnterprise: [
      "GET /enterprises/{enterprise}/code-security/configurations"
    ],
    getConfigurationsForOrg: ["GET /orgs/{org}/code-security/configurations"],
    getDefaultConfigurations: [
      "GET /orgs/{org}/code-security/configurations/defaults"
    ],
    getDefaultConfigurationsForEnterprise: [
      "GET /enterprises/{enterprise}/code-security/configurations/defaults"
    ],
    getRepositoriesForConfiguration: [
      "GET /orgs/{org}/code-security/configurations/{configuration_id}/repositories"
    ],
    getRepositoriesForEnterpriseConfiguration: [
      "GET /enterprises/{enterprise}/code-security/configurations/{configuration_id}/repositories"
    ],
    getSingleConfigurationForEnterprise: [
      "GET /enterprises/{enterprise}/code-security/configurations/{configuration_id}"
    ],
    setConfigurationAsDefault: [
      "PUT /orgs/{org}/code-security/configurations/{configuration_id}/defaults"
    ],
    setConfigurationAsDefaultForEnterprise: [
      "PUT /enterprises/{enterprise}/code-security/configurations/{configuration_id}/defaults"
    ],
    updateConfiguration: [
      "PATCH /orgs/{org}/code-security/configurations/{configuration_id}"
    ],
    updateEnterpriseConfiguration: [
      "PATCH /enterprises/{enterprise}/code-security/configurations/{configuration_id}"
    ]
  },
  codesOfConduct: {
    getAllCodesOfConduct: ["GET /codes_of_conduct"],
    getConductCode: ["GET /codes_of_conduct/{key}"]
  },
  codespaces: {
    addRepositoryForSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    checkPermissionsForDevcontainer: [
      "GET /repos/{owner}/{repo}/codespaces/permissions_check"
    ],
    codespaceMachinesForAuthenticatedUser: [
      "GET /user/codespaces/{codespace_name}/machines"
    ],
    createForAuthenticatedUser: ["POST /user/codespaces"],
    createOrUpdateOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}"
    ],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    createOrUpdateSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}"
    ],
    createWithPrForAuthenticatedUser: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/codespaces"
    ],
    createWithRepoForAuthenticatedUser: [
      "POST /repos/{owner}/{repo}/codespaces"
    ],
    deleteForAuthenticatedUser: ["DELETE /user/codespaces/{codespace_name}"],
    deleteFromOrganization: [
      "DELETE /orgs/{org}/members/{username}/codespaces/{codespace_name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/codespaces/secrets/{secret_name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    deleteSecretForAuthenticatedUser: [
      "DELETE /user/codespaces/secrets/{secret_name}"
    ],
    exportForAuthenticatedUser: [
      "POST /user/codespaces/{codespace_name}/exports"
    ],
    getCodespacesForUserInOrg: [
      "GET /orgs/{org}/members/{username}/codespaces"
    ],
    getExportDetailsForAuthenticatedUser: [
      "GET /user/codespaces/{codespace_name}/exports/{export_id}"
    ],
    getForAuthenticatedUser: ["GET /user/codespaces/{codespace_name}"],
    getOrgPublicKey: ["GET /orgs/{org}/codespaces/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/codespaces/secrets/{secret_name}"],
    getPublicKeyForAuthenticatedUser: [
      "GET /user/codespaces/secrets/public-key"
    ],
    getRepoPublicKey: [
      "GET /repos/{owner}/{repo}/codespaces/secrets/public-key"
    ],
    getRepoSecret: [
      "GET /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    getSecretForAuthenticatedUser: [
      "GET /user/codespaces/secrets/{secret_name}"
    ],
    listDevcontainersInRepositoryForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/devcontainers"
    ],
    listForAuthenticatedUser: ["GET /user/codespaces"],
    listInOrganization: [
      "GET /orgs/{org}/codespaces",
      {},
      { renamedParameters: { org_id: "org" } }
    ],
    listInRepositoryForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces"
    ],
    listOrgSecrets: ["GET /orgs/{org}/codespaces/secrets"],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/codespaces/secrets"],
    listRepositoriesForSecretForAuthenticatedUser: [
      "GET /user/codespaces/secrets/{secret_name}/repositories"
    ],
    listSecretsForAuthenticatedUser: ["GET /user/codespaces/secrets"],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
    ],
    preFlightWithRepoForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/new"
    ],
    publishForAuthenticatedUser: [
      "POST /user/codespaces/{codespace_name}/publish"
    ],
    removeRepositoryForSecretForAuthenticatedUser: [
      "DELETE /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    repoMachinesForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/machines"
    ],
    setRepositoriesForSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}/repositories"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
    ],
    startForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/start"],
    stopForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/stop"],
    stopInOrganization: [
      "POST /orgs/{org}/members/{username}/codespaces/{codespace_name}/stop"
    ],
    updateForAuthenticatedUser: ["PATCH /user/codespaces/{codespace_name}"]
  },
  copilot: {
    addCopilotSeatsForTeams: [
      "POST /orgs/{org}/copilot/billing/selected_teams"
    ],
    addCopilotSeatsForUsers: [
      "POST /orgs/{org}/copilot/billing/selected_users"
    ],
    cancelCopilotSeatAssignmentForTeams: [
      "DELETE /orgs/{org}/copilot/billing/selected_teams"
    ],
    cancelCopilotSeatAssignmentForUsers: [
      "DELETE /orgs/{org}/copilot/billing/selected_users"
    ],
    copilotMetricsForOrganization: ["GET /orgs/{org}/copilot/metrics"],
    copilotMetricsForTeam: ["GET /orgs/{org}/team/{team_slug}/copilot/metrics"],
    getCopilotOrganizationDetails: ["GET /orgs/{org}/copilot/billing"],
    getCopilotSeatDetailsForUser: [
      "GET /orgs/{org}/members/{username}/copilot"
    ],
    listCopilotSeats: ["GET /orgs/{org}/copilot/billing/seats"],
    usageMetricsForOrg: ["GET /orgs/{org}/copilot/usage"],
    usageMetricsForTeam: ["GET /orgs/{org}/team/{team_slug}/copilot/usage"]
  },
  dependabot: {
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
    ],
    createOrUpdateOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}"
    ],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/dependabot/secrets/{secret_name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    getAlert: ["GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"],
    getOrgPublicKey: ["GET /orgs/{org}/dependabot/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/dependabot/secrets/{secret_name}"],
    getRepoPublicKey: [
      "GET /repos/{owner}/{repo}/dependabot/secrets/public-key"
    ],
    getRepoSecret: [
      "GET /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    listAlertsForEnterprise: [
      "GET /enterprises/{enterprise}/dependabot/alerts"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/dependabot/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/dependabot/alerts"],
    listOrgSecrets: ["GET /orgs/{org}/dependabot/secrets"],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/dependabot/secrets"],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
    ],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"
    ]
  },
  dependencyGraph: {
    createRepositorySnapshot: [
      "POST /repos/{owner}/{repo}/dependency-graph/snapshots"
    ],
    diffRange: [
      "GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}"
    ],
    exportSbom: ["GET /repos/{owner}/{repo}/dependency-graph/sbom"]
  },
  emojis: { get: ["GET /emojis"] },
  gists: {
    checkIsStarred: ["GET /gists/{gist_id}/star"],
    create: ["POST /gists"],
    createComment: ["POST /gists/{gist_id}/comments"],
    delete: ["DELETE /gists/{gist_id}"],
    deleteComment: ["DELETE /gists/{gist_id}/comments/{comment_id}"],
    fork: ["POST /gists/{gist_id}/forks"],
    get: ["GET /gists/{gist_id}"],
    getComment: ["GET /gists/{gist_id}/comments/{comment_id}"],
    getRevision: ["GET /gists/{gist_id}/{sha}"],
    list: ["GET /gists"],
    listComments: ["GET /gists/{gist_id}/comments"],
    listCommits: ["GET /gists/{gist_id}/commits"],
    listForUser: ["GET /users/{username}/gists"],
    listForks: ["GET /gists/{gist_id}/forks"],
    listPublic: ["GET /gists/public"],
    listStarred: ["GET /gists/starred"],
    star: ["PUT /gists/{gist_id}/star"],
    unstar: ["DELETE /gists/{gist_id}/star"],
    update: ["PATCH /gists/{gist_id}"],
    updateComment: ["PATCH /gists/{gist_id}/comments/{comment_id}"]
  },
  git: {
    createBlob: ["POST /repos/{owner}/{repo}/git/blobs"],
    createCommit: ["POST /repos/{owner}/{repo}/git/commits"],
    createRef: ["POST /repos/{owner}/{repo}/git/refs"],
    createTag: ["POST /repos/{owner}/{repo}/git/tags"],
    createTree: ["POST /repos/{owner}/{repo}/git/trees"],
    deleteRef: ["DELETE /repos/{owner}/{repo}/git/refs/{ref}"],
    getBlob: ["GET /repos/{owner}/{repo}/git/blobs/{file_sha}"],
    getCommit: ["GET /repos/{owner}/{repo}/git/commits/{commit_sha}"],
    getRef: ["GET /repos/{owner}/{repo}/git/ref/{ref}"],
    getTag: ["GET /repos/{owner}/{repo}/git/tags/{tag_sha}"],
    getTree: ["GET /repos/{owner}/{repo}/git/trees/{tree_sha}"],
    listMatchingRefs: ["GET /repos/{owner}/{repo}/git/matching-refs/{ref}"],
    updateRef: ["PATCH /repos/{owner}/{repo}/git/refs/{ref}"]
  },
  gitignore: {
    getAllTemplates: ["GET /gitignore/templates"],
    getTemplate: ["GET /gitignore/templates/{name}"]
  },
  interactions: {
    getRestrictionsForAuthenticatedUser: ["GET /user/interaction-limits"],
    getRestrictionsForOrg: ["GET /orgs/{org}/interaction-limits"],
    getRestrictionsForRepo: ["GET /repos/{owner}/{repo}/interaction-limits"],
    getRestrictionsForYourPublicRepos: [
      "GET /user/interaction-limits",
      {},
      { renamed: ["interactions", "getRestrictionsForAuthenticatedUser"] }
    ],
    removeRestrictionsForAuthenticatedUser: ["DELETE /user/interaction-limits"],
    removeRestrictionsForOrg: ["DELETE /orgs/{org}/interaction-limits"],
    removeRestrictionsForRepo: [
      "DELETE /repos/{owner}/{repo}/interaction-limits"
    ],
    removeRestrictionsForYourPublicRepos: [
      "DELETE /user/interaction-limits",
      {},
      { renamed: ["interactions", "removeRestrictionsForAuthenticatedUser"] }
    ],
    setRestrictionsForAuthenticatedUser: ["PUT /user/interaction-limits"],
    setRestrictionsForOrg: ["PUT /orgs/{org}/interaction-limits"],
    setRestrictionsForRepo: ["PUT /repos/{owner}/{repo}/interaction-limits"],
    setRestrictionsForYourPublicRepos: [
      "PUT /user/interaction-limits",
      {},
      { renamed: ["interactions", "setRestrictionsForAuthenticatedUser"] }
    ]
  },
  issues: {
    addAssignees: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/assignees"
    ],
    addLabels: ["POST /repos/{owner}/{repo}/issues/{issue_number}/labels"],
    addSubIssue: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/sub_issues"
    ],
    checkUserCanBeAssigned: ["GET /repos/{owner}/{repo}/assignees/{assignee}"],
    checkUserCanBeAssignedToIssue: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/assignees/{assignee}"
    ],
    create: ["POST /repos/{owner}/{repo}/issues"],
    createComment: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments"
    ],
    createLabel: ["POST /repos/{owner}/{repo}/labels"],
    createMilestone: ["POST /repos/{owner}/{repo}/milestones"],
    deleteComment: [
      "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}"
    ],
    deleteLabel: ["DELETE /repos/{owner}/{repo}/labels/{name}"],
    deleteMilestone: [
      "DELETE /repos/{owner}/{repo}/milestones/{milestone_number}"
    ],
    get: ["GET /repos/{owner}/{repo}/issues/{issue_number}"],
    getComment: ["GET /repos/{owner}/{repo}/issues/comments/{comment_id}"],
    getEvent: ["GET /repos/{owner}/{repo}/issues/events/{event_id}"],
    getLabel: ["GET /repos/{owner}/{repo}/labels/{name}"],
    getMilestone: ["GET /repos/{owner}/{repo}/milestones/{milestone_number}"],
    list: ["GET /issues"],
    listAssignees: ["GET /repos/{owner}/{repo}/assignees"],
    listComments: ["GET /repos/{owner}/{repo}/issues/{issue_number}/comments"],
    listCommentsForRepo: ["GET /repos/{owner}/{repo}/issues/comments"],
    listEvents: ["GET /repos/{owner}/{repo}/issues/{issue_number}/events"],
    listEventsForRepo: ["GET /repos/{owner}/{repo}/issues/events"],
    listEventsForTimeline: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/timeline"
    ],
    listForAuthenticatedUser: ["GET /user/issues"],
    listForOrg: ["GET /orgs/{org}/issues"],
    listForRepo: ["GET /repos/{owner}/{repo}/issues"],
    listLabelsForMilestone: [
      "GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels"
    ],
    listLabelsForRepo: ["GET /repos/{owner}/{repo}/labels"],
    listLabelsOnIssue: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/labels"
    ],
    listMilestones: ["GET /repos/{owner}/{repo}/milestones"],
    listSubIssues: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/sub_issues"
    ],
    lock: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/lock"],
    removeAllLabels: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels"
    ],
    removeAssignees: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/assignees"
    ],
    removeLabel: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}"
    ],
    removeSubIssue: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/sub_issue"
    ],
    reprioritizeSubIssue: [
      "PATCH /repos/{owner}/{repo}/issues/{issue_number}/sub_issues/priority"
    ],
    setLabels: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/labels"],
    unlock: ["DELETE /repos/{owner}/{repo}/issues/{issue_number}/lock"],
    update: ["PATCH /repos/{owner}/{repo}/issues/{issue_number}"],
    updateComment: ["PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}"],
    updateLabel: ["PATCH /repos/{owner}/{repo}/labels/{name}"],
    updateMilestone: [
      "PATCH /repos/{owner}/{repo}/milestones/{milestone_number}"
    ]
  },
  licenses: {
    get: ["GET /licenses/{license}"],
    getAllCommonlyUsed: ["GET /licenses"],
    getForRepo: ["GET /repos/{owner}/{repo}/license"]
  },
  markdown: {
    render: ["POST /markdown"],
    renderRaw: [
      "POST /markdown/raw",
      { headers: { "content-type": "text/plain; charset=utf-8" } }
    ]
  },
  meta: {
    get: ["GET /meta"],
    getAllVersions: ["GET /versions"],
    getOctocat: ["GET /octocat"],
    getZen: ["GET /zen"],
    root: ["GET /"]
  },
  migrations: {
    deleteArchiveForAuthenticatedUser: [
      "DELETE /user/migrations/{migration_id}/archive"
    ],
    deleteArchiveForOrg: [
      "DELETE /orgs/{org}/migrations/{migration_id}/archive"
    ],
    downloadArchiveForOrg: [
      "GET /orgs/{org}/migrations/{migration_id}/archive"
    ],
    getArchiveForAuthenticatedUser: [
      "GET /user/migrations/{migration_id}/archive"
    ],
    getStatusForAuthenticatedUser: ["GET /user/migrations/{migration_id}"],
    getStatusForOrg: ["GET /orgs/{org}/migrations/{migration_id}"],
    listForAuthenticatedUser: ["GET /user/migrations"],
    listForOrg: ["GET /orgs/{org}/migrations"],
    listReposForAuthenticatedUser: [
      "GET /user/migrations/{migration_id}/repositories"
    ],
    listReposForOrg: ["GET /orgs/{org}/migrations/{migration_id}/repositories"],
    listReposForUser: [
      "GET /user/migrations/{migration_id}/repositories",
      {},
      { renamed: ["migrations", "listReposForAuthenticatedUser"] }
    ],
    startForAuthenticatedUser: ["POST /user/migrations"],
    startForOrg: ["POST /orgs/{org}/migrations"],
    unlockRepoForAuthenticatedUser: [
      "DELETE /user/migrations/{migration_id}/repos/{repo_name}/lock"
    ],
    unlockRepoForOrg: [
      "DELETE /orgs/{org}/migrations/{migration_id}/repos/{repo_name}/lock"
    ]
  },
  oidc: {
    getOidcCustomSubTemplateForOrg: [
      "GET /orgs/{org}/actions/oidc/customization/sub"
    ],
    updateOidcCustomSubTemplateForOrg: [
      "PUT /orgs/{org}/actions/oidc/customization/sub"
    ]
  },
  orgs: {
    addSecurityManagerTeam: [
      "PUT /orgs/{org}/security-managers/teams/{team_slug}",
      {},
      {
        deprecated: "octokit.rest.orgs.addSecurityManagerTeam() is deprecated, see https://docs.github.com/rest/orgs/security-managers#add-a-security-manager-team"
      }
    ],
    assignTeamToOrgRole: [
      "PUT /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}"
    ],
    assignUserToOrgRole: [
      "PUT /orgs/{org}/organization-roles/users/{username}/{role_id}"
    ],
    blockUser: ["PUT /orgs/{org}/blocks/{username}"],
    cancelInvitation: ["DELETE /orgs/{org}/invitations/{invitation_id}"],
    checkBlockedUser: ["GET /orgs/{org}/blocks/{username}"],
    checkMembershipForUser: ["GET /orgs/{org}/members/{username}"],
    checkPublicMembershipForUser: ["GET /orgs/{org}/public_members/{username}"],
    convertMemberToOutsideCollaborator: [
      "PUT /orgs/{org}/outside_collaborators/{username}"
    ],
    createInvitation: ["POST /orgs/{org}/invitations"],
    createOrUpdateCustomProperties: ["PATCH /orgs/{org}/properties/schema"],
    createOrUpdateCustomPropertiesValuesForRepos: [
      "PATCH /orgs/{org}/properties/values"
    ],
    createOrUpdateCustomProperty: [
      "PUT /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    createWebhook: ["POST /orgs/{org}/hooks"],
    delete: ["DELETE /orgs/{org}"],
    deleteWebhook: ["DELETE /orgs/{org}/hooks/{hook_id}"],
    enableOrDisableSecurityProductOnAllOrgRepos: [
      "POST /orgs/{org}/{security_product}/{enablement}",
      {},
      {
        deprecated: "octokit.rest.orgs.enableOrDisableSecurityProductOnAllOrgRepos() is deprecated, see https://docs.github.com/rest/orgs/orgs#enable-or-disable-a-security-feature-for-an-organization"
      }
    ],
    get: ["GET /orgs/{org}"],
    getAllCustomProperties: ["GET /orgs/{org}/properties/schema"],
    getCustomProperty: [
      "GET /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    getMembershipForAuthenticatedUser: ["GET /user/memberships/orgs/{org}"],
    getMembershipForUser: ["GET /orgs/{org}/memberships/{username}"],
    getOrgRole: ["GET /orgs/{org}/organization-roles/{role_id}"],
    getWebhook: ["GET /orgs/{org}/hooks/{hook_id}"],
    getWebhookConfigForOrg: ["GET /orgs/{org}/hooks/{hook_id}/config"],
    getWebhookDelivery: [
      "GET /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}"
    ],
    list: ["GET /organizations"],
    listAppInstallations: ["GET /orgs/{org}/installations"],
    listAttestations: ["GET /orgs/{org}/attestations/{subject_digest}"],
    listBlockedUsers: ["GET /orgs/{org}/blocks"],
    listCustomPropertiesValuesForRepos: ["GET /orgs/{org}/properties/values"],
    listFailedInvitations: ["GET /orgs/{org}/failed_invitations"],
    listForAuthenticatedUser: ["GET /user/orgs"],
    listForUser: ["GET /users/{username}/orgs"],
    listInvitationTeams: ["GET /orgs/{org}/invitations/{invitation_id}/teams"],
    listMembers: ["GET /orgs/{org}/members"],
    listMembershipsForAuthenticatedUser: ["GET /user/memberships/orgs"],
    listOrgRoleTeams: ["GET /orgs/{org}/organization-roles/{role_id}/teams"],
    listOrgRoleUsers: ["GET /orgs/{org}/organization-roles/{role_id}/users"],
    listOrgRoles: ["GET /orgs/{org}/organization-roles"],
    listOrganizationFineGrainedPermissions: [
      "GET /orgs/{org}/organization-fine-grained-permissions"
    ],
    listOutsideCollaborators: ["GET /orgs/{org}/outside_collaborators"],
    listPatGrantRepositories: [
      "GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories"
    ],
    listPatGrantRequestRepositories: [
      "GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories"
    ],
    listPatGrantRequests: ["GET /orgs/{org}/personal-access-token-requests"],
    listPatGrants: ["GET /orgs/{org}/personal-access-tokens"],
    listPendingInvitations: ["GET /orgs/{org}/invitations"],
    listPublicMembers: ["GET /orgs/{org}/public_members"],
    listSecurityManagerTeams: [
      "GET /orgs/{org}/security-managers",
      {},
      {
        deprecated: "octokit.rest.orgs.listSecurityManagerTeams() is deprecated, see https://docs.github.com/rest/orgs/security-managers#list-security-manager-teams"
      }
    ],
    listWebhookDeliveries: ["GET /orgs/{org}/hooks/{hook_id}/deliveries"],
    listWebhooks: ["GET /orgs/{org}/hooks"],
    pingWebhook: ["POST /orgs/{org}/hooks/{hook_id}/pings"],
    redeliverWebhookDelivery: [
      "POST /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
    ],
    removeCustomProperty: [
      "DELETE /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    removeMember: ["DELETE /orgs/{org}/members/{username}"],
    removeMembershipForUser: ["DELETE /orgs/{org}/memberships/{username}"],
    removeOutsideCollaborator: [
      "DELETE /orgs/{org}/outside_collaborators/{username}"
    ],
    removePublicMembershipForAuthenticatedUser: [
      "DELETE /orgs/{org}/public_members/{username}"
    ],
    removeSecurityManagerTeam: [
      "DELETE /orgs/{org}/security-managers/teams/{team_slug}",
      {},
      {
        deprecated: "octokit.rest.orgs.removeSecurityManagerTeam() is deprecated, see https://docs.github.com/rest/orgs/security-managers#remove-a-security-manager-team"
      }
    ],
    reviewPatGrantRequest: [
      "POST /orgs/{org}/personal-access-token-requests/{pat_request_id}"
    ],
    reviewPatGrantRequestsInBulk: [
      "POST /orgs/{org}/personal-access-token-requests"
    ],
    revokeAllOrgRolesTeam: [
      "DELETE /orgs/{org}/organization-roles/teams/{team_slug}"
    ],
    revokeAllOrgRolesUser: [
      "DELETE /orgs/{org}/organization-roles/users/{username}"
    ],
    revokeOrgRoleTeam: [
      "DELETE /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}"
    ],
    revokeOrgRoleUser: [
      "DELETE /orgs/{org}/organization-roles/users/{username}/{role_id}"
    ],
    setMembershipForUser: ["PUT /orgs/{org}/memberships/{username}"],
    setPublicMembershipForAuthenticatedUser: [
      "PUT /orgs/{org}/public_members/{username}"
    ],
    unblockUser: ["DELETE /orgs/{org}/blocks/{username}"],
    update: ["PATCH /orgs/{org}"],
    updateMembershipForAuthenticatedUser: [
      "PATCH /user/memberships/orgs/{org}"
    ],
    updatePatAccess: ["POST /orgs/{org}/personal-access-tokens/{pat_id}"],
    updatePatAccesses: ["POST /orgs/{org}/personal-access-tokens"],
    updateWebhook: ["PATCH /orgs/{org}/hooks/{hook_id}"],
    updateWebhookConfigForOrg: ["PATCH /orgs/{org}/hooks/{hook_id}/config"]
  },
  packages: {
    deletePackageForAuthenticatedUser: [
      "DELETE /user/packages/{package_type}/{package_name}"
    ],
    deletePackageForOrg: [
      "DELETE /orgs/{org}/packages/{package_type}/{package_name}"
    ],
    deletePackageForUser: [
      "DELETE /users/{username}/packages/{package_type}/{package_name}"
    ],
    deletePackageVersionForAuthenticatedUser: [
      "DELETE /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    deletePackageVersionForOrg: [
      "DELETE /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    deletePackageVersionForUser: [
      "DELETE /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getAllPackageVersionsForAPackageOwnedByAnOrg: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions",
      {},
      { renamed: ["packages", "getAllPackageVersionsForPackageOwnedByOrg"] }
    ],
    getAllPackageVersionsForAPackageOwnedByTheAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions",
      {},
      {
        renamed: [
          "packages",
          "getAllPackageVersionsForPackageOwnedByAuthenticatedUser"
        ]
      }
    ],
    getAllPackageVersionsForPackageOwnedByAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions"
    ],
    getAllPackageVersionsForPackageOwnedByOrg: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions"
    ],
    getAllPackageVersionsForPackageOwnedByUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}/versions"
    ],
    getPackageForAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}"
    ],
    getPackageForOrganization: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}"
    ],
    getPackageForUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}"
    ],
    getPackageVersionForAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getPackageVersionForOrganization: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getPackageVersionForUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    listDockerMigrationConflictingPackagesForAuthenticatedUser: [
      "GET /user/docker/conflicts"
    ],
    listDockerMigrationConflictingPackagesForOrganization: [
      "GET /orgs/{org}/docker/conflicts"
    ],
    listDockerMigrationConflictingPackagesForUser: [
      "GET /users/{username}/docker/conflicts"
    ],
    listPackagesForAuthenticatedUser: ["GET /user/packages"],
    listPackagesForOrganization: ["GET /orgs/{org}/packages"],
    listPackagesForUser: ["GET /users/{username}/packages"],
    restorePackageForAuthenticatedUser: [
      "POST /user/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageForOrg: [
      "POST /orgs/{org}/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageForUser: [
      "POST /users/{username}/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageVersionForAuthenticatedUser: [
      "POST /user/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ],
    restorePackageVersionForOrg: [
      "POST /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ],
    restorePackageVersionForUser: [
      "POST /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ]
  },
  privateRegistries: {
    createOrgPrivateRegistry: ["POST /orgs/{org}/private-registries"],
    deleteOrgPrivateRegistry: [
      "DELETE /orgs/{org}/private-registries/{secret_name}"
    ],
    getOrgPrivateRegistry: ["GET /orgs/{org}/private-registries/{secret_name}"],
    getOrgPublicKey: ["GET /orgs/{org}/private-registries/public-key"],
    listOrgPrivateRegistries: ["GET /orgs/{org}/private-registries"],
    updateOrgPrivateRegistry: [
      "PATCH /orgs/{org}/private-registries/{secret_name}"
    ]
  },
  projects: {
    addCollaborator: ["PUT /projects/{project_id}/collaborators/{username}"],
    createCard: ["POST /projects/columns/{column_id}/cards"],
    createColumn: ["POST /projects/{project_id}/columns"],
    createForAuthenticatedUser: ["POST /user/projects"],
    createForOrg: ["POST /orgs/{org}/projects"],
    createForRepo: ["POST /repos/{owner}/{repo}/projects"],
    delete: ["DELETE /projects/{project_id}"],
    deleteCard: ["DELETE /projects/columns/cards/{card_id}"],
    deleteColumn: ["DELETE /projects/columns/{column_id}"],
    get: ["GET /projects/{project_id}"],
    getCard: ["GET /projects/columns/cards/{card_id}"],
    getColumn: ["GET /projects/columns/{column_id}"],
    getPermissionForUser: [
      "GET /projects/{project_id}/collaborators/{username}/permission"
    ],
    listCards: ["GET /projects/columns/{column_id}/cards"],
    listCollaborators: ["GET /projects/{project_id}/collaborators"],
    listColumns: ["GET /projects/{project_id}/columns"],
    listForOrg: ["GET /orgs/{org}/projects"],
    listForRepo: ["GET /repos/{owner}/{repo}/projects"],
    listForUser: ["GET /users/{username}/projects"],
    moveCard: ["POST /projects/columns/cards/{card_id}/moves"],
    moveColumn: ["POST /projects/columns/{column_id}/moves"],
    removeCollaborator: [
      "DELETE /projects/{project_id}/collaborators/{username}"
    ],
    update: ["PATCH /projects/{project_id}"],
    updateCard: ["PATCH /projects/columns/cards/{card_id}"],
    updateColumn: ["PATCH /projects/columns/{column_id}"]
  },
  pulls: {
    checkIfMerged: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
    create: ["POST /repos/{owner}/{repo}/pulls"],
    createReplyForReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies"
    ],
    createReview: ["POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
    createReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments"
    ],
    deletePendingReview: [
      "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    deleteReviewComment: [
      "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}"
    ],
    dismissReview: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/dismissals"
    ],
    get: ["GET /repos/{owner}/{repo}/pulls/{pull_number}"],
    getReview: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    getReviewComment: ["GET /repos/{owner}/{repo}/pulls/comments/{comment_id}"],
    list: ["GET /repos/{owner}/{repo}/pulls"],
    listCommentsForReview: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments"
    ],
    listCommits: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/commits"],
    listFiles: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/files"],
    listRequestedReviewers: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    listReviewComments: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments"
    ],
    listReviewCommentsForRepo: ["GET /repos/{owner}/{repo}/pulls/comments"],
    listReviews: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
    merge: ["PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
    removeRequestedReviewers: [
      "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    requestReviewers: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    submitReview: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/events"
    ],
    update: ["PATCH /repos/{owner}/{repo}/pulls/{pull_number}"],
    updateBranch: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/update-branch"
    ],
    updateReview: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    updateReviewComment: [
      "PATCH /repos/{owner}/{repo}/pulls/comments/{comment_id}"
    ]
  },
  rateLimit: { get: ["GET /rate_limit"] },
  reactions: {
    createForCommitComment: [
      "POST /repos/{owner}/{repo}/comments/{comment_id}/reactions"
    ],
    createForIssue: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/reactions"
    ],
    createForIssueComment: [
      "POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    ],
    createForPullRequestReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
    ],
    createForRelease: [
      "POST /repos/{owner}/{repo}/releases/{release_id}/reactions"
    ],
    createForTeamDiscussionCommentInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
    ],
    createForTeamDiscussionInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
    ],
    deleteForCommitComment: [
      "DELETE /repos/{owner}/{repo}/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForIssue: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/reactions/{reaction_id}"
    ],
    deleteForIssueComment: [
      "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForPullRequestComment: [
      "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForRelease: [
      "DELETE /repos/{owner}/{repo}/releases/{release_id}/reactions/{reaction_id}"
    ],
    deleteForTeamDiscussion: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions/{reaction_id}"
    ],
    deleteForTeamDiscussionComment: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions/{reaction_id}"
    ],
    listForCommitComment: [
      "GET /repos/{owner}/{repo}/comments/{comment_id}/reactions"
    ],
    listForIssue: ["GET /repos/{owner}/{repo}/issues/{issue_number}/reactions"],
    listForIssueComment: [
      "GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    ],
    listForPullRequestReviewComment: [
      "GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
    ],
    listForRelease: [
      "GET /repos/{owner}/{repo}/releases/{release_id}/reactions"
    ],
    listForTeamDiscussionCommentInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
    ],
    listForTeamDiscussionInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
    ]
  },
  repos: {
    acceptInvitation: [
      "PATCH /user/repository_invitations/{invitation_id}",
      {},
      { renamed: ["repos", "acceptInvitationForAuthenticatedUser"] }
    ],
    acceptInvitationForAuthenticatedUser: [
      "PATCH /user/repository_invitations/{invitation_id}"
    ],
    addAppAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    addCollaborator: ["PUT /repos/{owner}/{repo}/collaborators/{username}"],
    addStatusCheckContexts: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    addTeamAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    addUserAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    cancelPagesDeployment: [
      "POST /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}/cancel"
    ],
    checkAutomatedSecurityFixes: [
      "GET /repos/{owner}/{repo}/automated-security-fixes"
    ],
    checkCollaborator: ["GET /repos/{owner}/{repo}/collaborators/{username}"],
    checkPrivateVulnerabilityReporting: [
      "GET /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    checkVulnerabilityAlerts: [
      "GET /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    codeownersErrors: ["GET /repos/{owner}/{repo}/codeowners/errors"],
    compareCommits: ["GET /repos/{owner}/{repo}/compare/{base}...{head}"],
    compareCommitsWithBasehead: [
      "GET /repos/{owner}/{repo}/compare/{basehead}"
    ],
    createAttestation: ["POST /repos/{owner}/{repo}/attestations"],
    createAutolink: ["POST /repos/{owner}/{repo}/autolinks"],
    createCommitComment: [
      "POST /repos/{owner}/{repo}/commits/{commit_sha}/comments"
    ],
    createCommitSignatureProtection: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    createCommitStatus: ["POST /repos/{owner}/{repo}/statuses/{sha}"],
    createDeployKey: ["POST /repos/{owner}/{repo}/keys"],
    createDeployment: ["POST /repos/{owner}/{repo}/deployments"],
    createDeploymentBranchPolicy: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
    ],
    createDeploymentProtectionRule: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
    ],
    createDeploymentStatus: [
      "POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
    ],
    createDispatchEvent: ["POST /repos/{owner}/{repo}/dispatches"],
    createForAuthenticatedUser: ["POST /user/repos"],
    createFork: ["POST /repos/{owner}/{repo}/forks"],
    createInOrg: ["POST /orgs/{org}/repos"],
    createOrUpdateCustomPropertiesValues: [
      "PATCH /repos/{owner}/{repo}/properties/values"
    ],
    createOrUpdateEnvironment: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    createOrUpdateFileContents: ["PUT /repos/{owner}/{repo}/contents/{path}"],
    createOrgRuleset: ["POST /orgs/{org}/rulesets"],
    createPagesDeployment: ["POST /repos/{owner}/{repo}/pages/deployments"],
    createPagesSite: ["POST /repos/{owner}/{repo}/pages"],
    createRelease: ["POST /repos/{owner}/{repo}/releases"],
    createRepoRuleset: ["POST /repos/{owner}/{repo}/rulesets"],
    createUsingTemplate: [
      "POST /repos/{template_owner}/{template_repo}/generate"
    ],
    createWebhook: ["POST /repos/{owner}/{repo}/hooks"],
    declineInvitation: [
      "DELETE /user/repository_invitations/{invitation_id}",
      {},
      { renamed: ["repos", "declineInvitationForAuthenticatedUser"] }
    ],
    declineInvitationForAuthenticatedUser: [
      "DELETE /user/repository_invitations/{invitation_id}"
    ],
    delete: ["DELETE /repos/{owner}/{repo}"],
    deleteAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
    ],
    deleteAdminBranchProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    deleteAnEnvironment: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    deleteAutolink: ["DELETE /repos/{owner}/{repo}/autolinks/{autolink_id}"],
    deleteBranchProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    deleteCommitComment: ["DELETE /repos/{owner}/{repo}/comments/{comment_id}"],
    deleteCommitSignatureProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    deleteDeployKey: ["DELETE /repos/{owner}/{repo}/keys/{key_id}"],
    deleteDeployment: [
      "DELETE /repos/{owner}/{repo}/deployments/{deployment_id}"
    ],
    deleteDeploymentBranchPolicy: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    deleteFile: ["DELETE /repos/{owner}/{repo}/contents/{path}"],
    deleteInvitation: [
      "DELETE /repos/{owner}/{repo}/invitations/{invitation_id}"
    ],
    deleteOrgRuleset: ["DELETE /orgs/{org}/rulesets/{ruleset_id}"],
    deletePagesSite: ["DELETE /repos/{owner}/{repo}/pages"],
    deletePullRequestReviewProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    deleteRelease: ["DELETE /repos/{owner}/{repo}/releases/{release_id}"],
    deleteReleaseAsset: [
      "DELETE /repos/{owner}/{repo}/releases/assets/{asset_id}"
    ],
    deleteRepoRuleset: ["DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    deleteWebhook: ["DELETE /repos/{owner}/{repo}/hooks/{hook_id}"],
    disableAutomatedSecurityFixes: [
      "DELETE /repos/{owner}/{repo}/automated-security-fixes"
    ],
    disableDeploymentProtectionRule: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
    ],
    disablePrivateVulnerabilityReporting: [
      "DELETE /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    disableVulnerabilityAlerts: [
      "DELETE /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    downloadArchive: [
      "GET /repos/{owner}/{repo}/zipball/{ref}",
      {},
      { renamed: ["repos", "downloadZipballArchive"] }
    ],
    downloadTarballArchive: ["GET /repos/{owner}/{repo}/tarball/{ref}"],
    downloadZipballArchive: ["GET /repos/{owner}/{repo}/zipball/{ref}"],
    enableAutomatedSecurityFixes: [
      "PUT /repos/{owner}/{repo}/automated-security-fixes"
    ],
    enablePrivateVulnerabilityReporting: [
      "PUT /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    enableVulnerabilityAlerts: [
      "PUT /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    generateReleaseNotes: [
      "POST /repos/{owner}/{repo}/releases/generate-notes"
    ],
    get: ["GET /repos/{owner}/{repo}"],
    getAccessRestrictions: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
    ],
    getAdminBranchProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    getAllDeploymentProtectionRules: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
    ],
    getAllEnvironments: ["GET /repos/{owner}/{repo}/environments"],
    getAllStatusCheckContexts: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts"
    ],
    getAllTopics: ["GET /repos/{owner}/{repo}/topics"],
    getAppsWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps"
    ],
    getAutolink: ["GET /repos/{owner}/{repo}/autolinks/{autolink_id}"],
    getBranch: ["GET /repos/{owner}/{repo}/branches/{branch}"],
    getBranchProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    getBranchRules: ["GET /repos/{owner}/{repo}/rules/branches/{branch}"],
    getClones: ["GET /repos/{owner}/{repo}/traffic/clones"],
    getCodeFrequencyStats: ["GET /repos/{owner}/{repo}/stats/code_frequency"],
    getCollaboratorPermissionLevel: [
      "GET /repos/{owner}/{repo}/collaborators/{username}/permission"
    ],
    getCombinedStatusForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/status"],
    getCommit: ["GET /repos/{owner}/{repo}/commits/{ref}"],
    getCommitActivityStats: ["GET /repos/{owner}/{repo}/stats/commit_activity"],
    getCommitComment: ["GET /repos/{owner}/{repo}/comments/{comment_id}"],
    getCommitSignatureProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    getCommunityProfileMetrics: ["GET /repos/{owner}/{repo}/community/profile"],
    getContent: ["GET /repos/{owner}/{repo}/contents/{path}"],
    getContributorsStats: ["GET /repos/{owner}/{repo}/stats/contributors"],
    getCustomDeploymentProtectionRule: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
    ],
    getCustomPropertiesValues: ["GET /repos/{owner}/{repo}/properties/values"],
    getDeployKey: ["GET /repos/{owner}/{repo}/keys/{key_id}"],
    getDeployment: ["GET /repos/{owner}/{repo}/deployments/{deployment_id}"],
    getDeploymentBranchPolicy: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    getDeploymentStatus: [
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses/{status_id}"
    ],
    getEnvironment: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    getLatestPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/latest"],
    getLatestRelease: ["GET /repos/{owner}/{repo}/releases/latest"],
    getOrgRuleSuite: ["GET /orgs/{org}/rulesets/rule-suites/{rule_suite_id}"],
    getOrgRuleSuites: ["GET /orgs/{org}/rulesets/rule-suites"],
    getOrgRuleset: ["GET /orgs/{org}/rulesets/{ruleset_id}"],
    getOrgRulesets: ["GET /orgs/{org}/rulesets"],
    getPages: ["GET /repos/{owner}/{repo}/pages"],
    getPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/{build_id}"],
    getPagesDeployment: [
      "GET /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}"
    ],
    getPagesHealthCheck: ["GET /repos/{owner}/{repo}/pages/health"],
    getParticipationStats: ["GET /repos/{owner}/{repo}/stats/participation"],
    getPullRequestReviewProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    getPunchCardStats: ["GET /repos/{owner}/{repo}/stats/punch_card"],
    getReadme: ["GET /repos/{owner}/{repo}/readme"],
    getReadmeInDirectory: ["GET /repos/{owner}/{repo}/readme/{dir}"],
    getRelease: ["GET /repos/{owner}/{repo}/releases/{release_id}"],
    getReleaseAsset: ["GET /repos/{owner}/{repo}/releases/assets/{asset_id}"],
    getReleaseByTag: ["GET /repos/{owner}/{repo}/releases/tags/{tag}"],
    getRepoRuleSuite: [
      "GET /repos/{owner}/{repo}/rulesets/rule-suites/{rule_suite_id}"
    ],
    getRepoRuleSuites: ["GET /repos/{owner}/{repo}/rulesets/rule-suites"],
    getRepoRuleset: ["GET /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    getRepoRulesets: ["GET /repos/{owner}/{repo}/rulesets"],
    getStatusChecksProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    getTeamsWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams"
    ],
    getTopPaths: ["GET /repos/{owner}/{repo}/traffic/popular/paths"],
    getTopReferrers: ["GET /repos/{owner}/{repo}/traffic/popular/referrers"],
    getUsersWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users"
    ],
    getViews: ["GET /repos/{owner}/{repo}/traffic/views"],
    getWebhook: ["GET /repos/{owner}/{repo}/hooks/{hook_id}"],
    getWebhookConfigForRepo: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/config"
    ],
    getWebhookDelivery: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}"
    ],
    listActivities: ["GET /repos/{owner}/{repo}/activity"],
    listAttestations: [
      "GET /repos/{owner}/{repo}/attestations/{subject_digest}"
    ],
    listAutolinks: ["GET /repos/{owner}/{repo}/autolinks"],
    listBranches: ["GET /repos/{owner}/{repo}/branches"],
    listBranchesForHeadCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/branches-where-head"
    ],
    listCollaborators: ["GET /repos/{owner}/{repo}/collaborators"],
    listCommentsForCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/comments"
    ],
    listCommitCommentsForRepo: ["GET /repos/{owner}/{repo}/comments"],
    listCommitStatusesForRef: [
      "GET /repos/{owner}/{repo}/commits/{ref}/statuses"
    ],
    listCommits: ["GET /repos/{owner}/{repo}/commits"],
    listContributors: ["GET /repos/{owner}/{repo}/contributors"],
    listCustomDeploymentRuleIntegrations: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps"
    ],
    listDeployKeys: ["GET /repos/{owner}/{repo}/keys"],
    listDeploymentBranchPolicies: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
    ],
    listDeploymentStatuses: [
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
    ],
    listDeployments: ["GET /repos/{owner}/{repo}/deployments"],
    listForAuthenticatedUser: ["GET /user/repos"],
    listForOrg: ["GET /orgs/{org}/repos"],
    listForUser: ["GET /users/{username}/repos"],
    listForks: ["GET /repos/{owner}/{repo}/forks"],
    listInvitations: ["GET /repos/{owner}/{repo}/invitations"],
    listInvitationsForAuthenticatedUser: ["GET /user/repository_invitations"],
    listLanguages: ["GET /repos/{owner}/{repo}/languages"],
    listPagesBuilds: ["GET /repos/{owner}/{repo}/pages/builds"],
    listPublic: ["GET /repositories"],
    listPullRequestsAssociatedWithCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls"
    ],
    listReleaseAssets: [
      "GET /repos/{owner}/{repo}/releases/{release_id}/assets"
    ],
    listReleases: ["GET /repos/{owner}/{repo}/releases"],
    listTags: ["GET /repos/{owner}/{repo}/tags"],
    listTeams: ["GET /repos/{owner}/{repo}/teams"],
    listWebhookDeliveries: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries"
    ],
    listWebhooks: ["GET /repos/{owner}/{repo}/hooks"],
    merge: ["POST /repos/{owner}/{repo}/merges"],
    mergeUpstream: ["POST /repos/{owner}/{repo}/merge-upstream"],
    pingWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/pings"],
    redeliverWebhookDelivery: [
      "POST /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
    ],
    removeAppAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    removeCollaborator: [
      "DELETE /repos/{owner}/{repo}/collaborators/{username}"
    ],
    removeStatusCheckContexts: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    removeStatusCheckProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    removeTeamAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    removeUserAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    renameBranch: ["POST /repos/{owner}/{repo}/branches/{branch}/rename"],
    replaceAllTopics: ["PUT /repos/{owner}/{repo}/topics"],
    requestPagesBuild: ["POST /repos/{owner}/{repo}/pages/builds"],
    setAdminBranchProtection: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    setAppAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    setStatusCheckContexts: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    setTeamAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    setUserAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    testPushWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/tests"],
    transfer: ["POST /repos/{owner}/{repo}/transfer"],
    update: ["PATCH /repos/{owner}/{repo}"],
    updateBranchProtection: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    updateCommitComment: ["PATCH /repos/{owner}/{repo}/comments/{comment_id}"],
    updateDeploymentBranchPolicy: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    updateInformationAboutPagesSite: ["PUT /repos/{owner}/{repo}/pages"],
    updateInvitation: [
      "PATCH /repos/{owner}/{repo}/invitations/{invitation_id}"
    ],
    updateOrgRuleset: ["PUT /orgs/{org}/rulesets/{ruleset_id}"],
    updatePullRequestReviewProtection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    updateRelease: ["PATCH /repos/{owner}/{repo}/releases/{release_id}"],
    updateReleaseAsset: [
      "PATCH /repos/{owner}/{repo}/releases/assets/{asset_id}"
    ],
    updateRepoRuleset: ["PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    updateStatusCheckPotection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks",
      {},
      { renamed: ["repos", "updateStatusCheckProtection"] }
    ],
    updateStatusCheckProtection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    updateWebhook: ["PATCH /repos/{owner}/{repo}/hooks/{hook_id}"],
    updateWebhookConfigForRepo: [
      "PATCH /repos/{owner}/{repo}/hooks/{hook_id}/config"
    ],
    uploadReleaseAsset: [
      "POST /repos/{owner}/{repo}/releases/{release_id}/assets{?name,label}",
      { baseUrl: "https://uploads.github.com" }
    ]
  },
  search: {
    code: ["GET /search/code"],
    commits: ["GET /search/commits"],
    issuesAndPullRequests: ["GET /search/issues"],
    labels: ["GET /search/labels"],
    repos: ["GET /search/repositories"],
    topics: ["GET /search/topics"],
    users: ["GET /search/users"]
  },
  secretScanning: {
    createPushProtectionBypass: [
      "POST /repos/{owner}/{repo}/secret-scanning/push-protection-bypasses"
    ],
    getAlert: [
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
    ],
    getScanHistory: ["GET /repos/{owner}/{repo}/secret-scanning/scan-history"],
    listAlertsForEnterprise: [
      "GET /enterprises/{enterprise}/secret-scanning/alerts"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/secret-scanning/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/secret-scanning/alerts"],
    listLocationsForAlert: [
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations"
    ],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
    ]
  },
  securityAdvisories: {
    createFork: [
      "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/forks"
    ],
    createPrivateVulnerabilityReport: [
      "POST /repos/{owner}/{repo}/security-advisories/reports"
    ],
    createRepositoryAdvisory: [
      "POST /repos/{owner}/{repo}/security-advisories"
    ],
    createRepositoryAdvisoryCveRequest: [
      "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve"
    ],
    getGlobalAdvisory: ["GET /advisories/{ghsa_id}"],
    getRepositoryAdvisory: [
      "GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    ],
    listGlobalAdvisories: ["GET /advisories"],
    listOrgRepositoryAdvisories: ["GET /orgs/{org}/security-advisories"],
    listRepositoryAdvisories: ["GET /repos/{owner}/{repo}/security-advisories"],
    updateRepositoryAdvisory: [
      "PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    ]
  },
  teams: {
    addOrUpdateMembershipForUserInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    addOrUpdateProjectPermissionsInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/projects/{project_id}"
    ],
    addOrUpdateRepoPermissionsInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    checkPermissionsForProjectInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/projects/{project_id}"
    ],
    checkPermissionsForRepoInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    create: ["POST /orgs/{org}/teams"],
    createDiscussionCommentInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
    ],
    createDiscussionInOrg: ["POST /orgs/{org}/teams/{team_slug}/discussions"],
    deleteDiscussionCommentInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    deleteDiscussionInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    deleteInOrg: ["DELETE /orgs/{org}/teams/{team_slug}"],
    getByName: ["GET /orgs/{org}/teams/{team_slug}"],
    getDiscussionCommentInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    getDiscussionInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    getMembershipForUserInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    list: ["GET /orgs/{org}/teams"],
    listChildInOrg: ["GET /orgs/{org}/teams/{team_slug}/teams"],
    listDiscussionCommentsInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
    ],
    listDiscussionsInOrg: ["GET /orgs/{org}/teams/{team_slug}/discussions"],
    listForAuthenticatedUser: ["GET /user/teams"],
    listMembersInOrg: ["GET /orgs/{org}/teams/{team_slug}/members"],
    listPendingInvitationsInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/invitations"
    ],
    listProjectsInOrg: ["GET /orgs/{org}/teams/{team_slug}/projects"],
    listReposInOrg: ["GET /orgs/{org}/teams/{team_slug}/repos"],
    removeMembershipForUserInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    removeProjectInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/projects/{project_id}"
    ],
    removeRepoInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    updateDiscussionCommentInOrg: [
      "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    updateDiscussionInOrg: [
      "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    updateInOrg: ["PATCH /orgs/{org}/teams/{team_slug}"]
  },
  users: {
    addEmailForAuthenticated: [
      "POST /user/emails",
      {},
      { renamed: ["users", "addEmailForAuthenticatedUser"] }
    ],
    addEmailForAuthenticatedUser: ["POST /user/emails"],
    addSocialAccountForAuthenticatedUser: ["POST /user/social_accounts"],
    block: ["PUT /user/blocks/{username}"],
    checkBlocked: ["GET /user/blocks/{username}"],
    checkFollowingForUser: ["GET /users/{username}/following/{target_user}"],
    checkPersonIsFollowedByAuthenticated: ["GET /user/following/{username}"],
    createGpgKeyForAuthenticated: [
      "POST /user/gpg_keys",
      {},
      { renamed: ["users", "createGpgKeyForAuthenticatedUser"] }
    ],
    createGpgKeyForAuthenticatedUser: ["POST /user/gpg_keys"],
    createPublicSshKeyForAuthenticated: [
      "POST /user/keys",
      {},
      { renamed: ["users", "createPublicSshKeyForAuthenticatedUser"] }
    ],
    createPublicSshKeyForAuthenticatedUser: ["POST /user/keys"],
    createSshSigningKeyForAuthenticatedUser: ["POST /user/ssh_signing_keys"],
    deleteEmailForAuthenticated: [
      "DELETE /user/emails",
      {},
      { renamed: ["users", "deleteEmailForAuthenticatedUser"] }
    ],
    deleteEmailForAuthenticatedUser: ["DELETE /user/emails"],
    deleteGpgKeyForAuthenticated: [
      "DELETE /user/gpg_keys/{gpg_key_id}",
      {},
      { renamed: ["users", "deleteGpgKeyForAuthenticatedUser"] }
    ],
    deleteGpgKeyForAuthenticatedUser: ["DELETE /user/gpg_keys/{gpg_key_id}"],
    deletePublicSshKeyForAuthenticated: [
      "DELETE /user/keys/{key_id}",
      {},
      { renamed: ["users", "deletePublicSshKeyForAuthenticatedUser"] }
    ],
    deletePublicSshKeyForAuthenticatedUser: ["DELETE /user/keys/{key_id}"],
    deleteSocialAccountForAuthenticatedUser: ["DELETE /user/social_accounts"],
    deleteSshSigningKeyForAuthenticatedUser: [
      "DELETE /user/ssh_signing_keys/{ssh_signing_key_id}"
    ],
    follow: ["PUT /user/following/{username}"],
    getAuthenticated: ["GET /user"],
    getById: ["GET /user/{account_id}"],
    getByUsername: ["GET /users/{username}"],
    getContextForUser: ["GET /users/{username}/hovercard"],
    getGpgKeyForAuthenticated: [
      "GET /user/gpg_keys/{gpg_key_id}",
      {},
      { renamed: ["users", "getGpgKeyForAuthenticatedUser"] }
    ],
    getGpgKeyForAuthenticatedUser: ["GET /user/gpg_keys/{gpg_key_id}"],
    getPublicSshKeyForAuthenticated: [
      "GET /user/keys/{key_id}",
      {},
      { renamed: ["users", "getPublicSshKeyForAuthenticatedUser"] }
    ],
    getPublicSshKeyForAuthenticatedUser: ["GET /user/keys/{key_id}"],
    getSshSigningKeyForAuthenticatedUser: [
      "GET /user/ssh_signing_keys/{ssh_signing_key_id}"
    ],
    list: ["GET /users"],
    listAttestations: ["GET /users/{username}/attestations/{subject_digest}"],
    listBlockedByAuthenticated: [
      "GET /user/blocks",
      {},
      { renamed: ["users", "listBlockedByAuthenticatedUser"] }
    ],
    listBlockedByAuthenticatedUser: ["GET /user/blocks"],
    listEmailsForAuthenticated: [
      "GET /user/emails",
      {},
      { renamed: ["users", "listEmailsForAuthenticatedUser"] }
    ],
    listEmailsForAuthenticatedUser: ["GET /user/emails"],
    listFollowedByAuthenticated: [
      "GET /user/following",
      {},
      { renamed: ["users", "listFollowedByAuthenticatedUser"] }
    ],
    listFollowedByAuthenticatedUser: ["GET /user/following"],
    listFollowersForAuthenticatedUser: ["GET /user/followers"],
    listFollowersForUser: ["GET /users/{username}/followers"],
    listFollowingForUser: ["GET /users/{username}/following"],
    listGpgKeysForAuthenticated: [
      "GET /user/gpg_keys",
      {},
      { renamed: ["users", "listGpgKeysForAuthenticatedUser"] }
    ],
    listGpgKeysForAuthenticatedUser: ["GET /user/gpg_keys"],
    listGpgKeysForUser: ["GET /users/{username}/gpg_keys"],
    listPublicEmailsForAuthenticated: [
      "GET /user/public_emails",
      {},
      { renamed: ["users", "listPublicEmailsForAuthenticatedUser"] }
    ],
    listPublicEmailsForAuthenticatedUser: ["GET /user/public_emails"],
    listPublicKeysForUser: ["GET /users/{username}/keys"],
    listPublicSshKeysForAuthenticated: [
      "GET /user/keys",
      {},
      { renamed: ["users", "listPublicSshKeysForAuthenticatedUser"] }
    ],
    listPublicSshKeysForAuthenticatedUser: ["GET /user/keys"],
    listSocialAccountsForAuthenticatedUser: ["GET /user/social_accounts"],
    listSocialAccountsForUser: ["GET /users/{username}/social_accounts"],
    listSshSigningKeysForAuthenticatedUser: ["GET /user/ssh_signing_keys"],
    listSshSigningKeysForUser: ["GET /users/{username}/ssh_signing_keys"],
    setPrimaryEmailVisibilityForAuthenticated: [
      "PATCH /user/email/visibility",
      {},
      { renamed: ["users", "setPrimaryEmailVisibilityForAuthenticatedUser"] }
    ],
    setPrimaryEmailVisibilityForAuthenticatedUser: [
      "PATCH /user/email/visibility"
    ],
    unblock: ["DELETE /user/blocks/{username}"],
    unfollow: ["DELETE /user/following/{username}"],
    updateAuthenticated: ["PATCH /user"]
  }
};
var Ew = lw;
const kt = /* @__PURE__ */ new Map();
for (const [e, A] of Object.entries(Ew))
  for (const [t, r] of Object.entries(A)) {
    const [s, o, n] = r, [i, a] = s.split(/ /), g = Object.assign(
      {
        method: i,
        url: a
      },
      o
    );
    kt.has(e) || kt.set(e, /* @__PURE__ */ new Map()), kt.get(e).set(t, {
      scope: e,
      methodName: t,
      endpointDefaults: g,
      decorations: n
    });
  }
const uw = {
  has({ scope: e }, A) {
    return kt.get(e).has(A);
  },
  getOwnPropertyDescriptor(e, A) {
    return {
      value: this.get(e, A),
      // ensures method is in the cache
      configurable: !0,
      writable: !0,
      enumerable: !0
    };
  },
  defineProperty(e, A, t) {
    return Object.defineProperty(e.cache, A, t), !0;
  },
  deleteProperty(e, A) {
    return delete e.cache[A], !0;
  },
  ownKeys({ scope: e }) {
    return [...kt.get(e).keys()];
  },
  set(e, A, t) {
    return e.cache[A] = t;
  },
  get({ octokit: e, scope: A, cache: t }, r) {
    if (t[r])
      return t[r];
    const s = kt.get(A).get(r);
    if (!s)
      return;
    const { endpointDefaults: o, decorations: n } = s;
    return n ? t[r] = dw(
      e,
      A,
      r,
      o,
      n
    ) : t[r] = e.request.defaults(o), t[r];
  }
};
function hw(e) {
  const A = {};
  for (const t of kt.keys())
    A[t] = new Proxy({ octokit: e, scope: t, cache: {} }, uw);
  return A;
}
function dw(e, A, t, r, s) {
  const o = e.request.defaults(r);
  function n(...i) {
    let a = o.endpoint.merge(...i);
    if (s.mapToData)
      return a = Object.assign({}, a, {
        data: a[s.mapToData],
        [s.mapToData]: void 0
      }), o(a);
    if (s.renamed) {
      const [g, c] = s.renamed;
      e.log.warn(
        `octokit.${A}.${t}() has been renamed to octokit.${g}.${c}()`
      );
    }
    if (s.deprecated && e.log.warn(s.deprecated), s.renamedParameters) {
      const g = o.endpoint.merge(...i);
      for (const [c, E] of Object.entries(
        s.renamedParameters
      ))
        c in g && (e.log.warn(
          `"${c}" parameter is deprecated for "octokit.${A}.${t}()". Use "${E}" instead`
        ), E in g || (g[E] = g[c]), delete g[c]);
      return o(g);
    }
    return o(...i);
  }
  return Object.assign(n, o);
}
function Ru(e) {
  return {
    rest: hw(e)
  };
}
Ru.VERSION = gw;
var Du = { exports: {} };
(function(e, A) {
  (function(t, r) {
    e.exports = r();
  })(O, function() {
    var t = typeof globalThis < "u" ? globalThis : typeof window < "u" ? window : typeof O < "u" ? O : typeof self < "u" ? self : {};
    function r(_) {
      return _ && _.default || _;
    }
    var s = function(_, D, p = {}) {
      var k, G, L;
      for (k in D)
        L = D[k], p[k] = (G = _[k]) != null ? G : L;
      return p;
    }, o = function(_, D, p = {}) {
      var k, G;
      for (k in _)
        G = _[k], D[k] !== void 0 && (p[k] = G);
      return p;
    }, n = {
      load: s,
      overwrite: o
    }, i;
    i = class {
      constructor(D, p) {
        this.incr = D, this.decr = p, this._first = null, this._last = null, this.length = 0;
      }
      push(D) {
        var p;
        this.length++, typeof this.incr == "function" && this.incr(), p = {
          value: D,
          prev: this._last,
          next: null
        }, this._last != null ? (this._last.next = p, this._last = p) : this._first = this._last = p;
      }
      shift() {
        var D;
        if (this._first != null)
          return this.length--, typeof this.decr == "function" && this.decr(), D = this._first.value, (this._first = this._first.next) != null ? this._first.prev = null : this._last = null, D;
      }
      first() {
        if (this._first != null)
          return this._first.value;
      }
      getArray() {
        var D, p, k;
        for (D = this._first, k = []; D != null; )
          k.push((p = D, D = D.next, p.value));
        return k;
      }
      forEachShift(D) {
        var p;
        for (p = this.shift(); p != null; )
          D(p), p = this.shift();
      }
      debug() {
        var D, p, k, G, L;
        for (D = this._first, L = []; D != null; )
          L.push((p = D, D = D.next, {
            value: p.value,
            prev: (k = p.prev) != null ? k.value : void 0,
            next: (G = p.next) != null ? G.value : void 0
          }));
        return L;
      }
    };
    var a = i, g;
    g = class {
      constructor(D) {
        if (this.instance = D, this._events = {}, this.instance.on != null || this.instance.once != null || this.instance.removeAllListeners != null)
          throw new Error("An Emitter already exists for this object");
        this.instance.on = (p, k) => this._addListener(p, "many", k), this.instance.once = (p, k) => this._addListener(p, "once", k), this.instance.removeAllListeners = (p = null) => p != null ? delete this._events[p] : this._events = {};
      }
      _addListener(D, p, k) {
        var G;
        return (G = this._events)[D] == null && (G[D] = []), this._events[D].push({ cb: k, status: p }), this.instance;
      }
      listenerCount(D) {
        return this._events[D] != null ? this._events[D].length : 0;
      }
      async trigger(D, ...p) {
        var k, G;
        try {
          return D !== "debug" && this.trigger("debug", `Event triggered: ${D}`, p), this._events[D] == null ? void 0 : (this._events[D] = this._events[D].filter(function(L) {
            return L.status !== "none";
          }), G = this._events[D].map(async (L) => {
            var V, se;
            if (L.status !== "none") {
              L.status === "once" && (L.status = "none");
              try {
                return se = typeof L.cb == "function" ? L.cb(...p) : void 0, typeof se?.then == "function" ? await se : se;
              } catch (fe) {
                return V = fe, this.trigger("error", V), null;
              }
            }
          }), (await Promise.all(G)).find(function(L) {
            return L != null;
          }));
        } catch (L) {
          return k = L, this.trigger("error", k), null;
        }
      }
    };
    var c = g, E, l, Q;
    E = a, l = c, Q = class {
      constructor(D) {
        this.Events = new l(this), this._length = 0, this._lists = function() {
          var p, k, G;
          for (G = [], p = 1, k = D; 1 <= k ? p <= k : p >= k; 1 <= k ? ++p : --p)
            G.push(new E(() => this.incr(), () => this.decr()));
          return G;
        }.call(this);
      }
      incr() {
        if (this._length++ === 0)
          return this.Events.trigger("leftzero");
      }
      decr() {
        if (--this._length === 0)
          return this.Events.trigger("zero");
      }
      push(D) {
        return this._lists[D.options.priority].push(D);
      }
      queued(D) {
        return D != null ? this._lists[D].length : this._length;
      }
      shiftAll(D) {
        return this._lists.forEach(function(p) {
          return p.forEachShift(D);
        });
      }
      getFirst(D = this._lists) {
        var p, k, G;
        for (p = 0, k = D.length; p < k; p++)
          if (G = D[p], G.length > 0)
            return G;
        return [];
      }
      shiftLastFrom(D) {
        return this.getFirst(this._lists.slice(D).reverse()).shift();
      }
    };
    var I = Q, d;
    d = class extends Error {
    };
    var h = d, C, u, B, m, f;
    m = 10, u = 5, f = n, C = h, B = class {
      constructor(D, p, k, G, L, V, se, fe) {
        this.task = D, this.args = p, this.rejectOnDrop = L, this.Events = V, this._states = se, this.Promise = fe, this.options = f.load(k, G), this.options.priority = this._sanitizePriority(this.options.priority), this.options.id === G.id && (this.options.id = `${this.options.id}-${this._randomIndex()}`), this.promise = new this.Promise((Ve, xe) => {
          this._resolve = Ve, this._reject = xe;
        }), this.retryCount = 0;
      }
      _sanitizePriority(D) {
        var p;
        return p = ~~D !== D ? u : D, p < 0 ? 0 : p > m - 1 ? m - 1 : p;
      }
      _randomIndex() {
        return Math.random().toString(36).slice(2);
      }
      doDrop({ error: D, message: p = "This job has been dropped by Bottleneck" } = {}) {
        return this._states.remove(this.options.id) ? (this.rejectOnDrop && this._reject(D ?? new C(p)), this.Events.trigger("dropped", { args: this.args, options: this.options, task: this.task, promise: this.promise }), !0) : !1;
      }
      _assertStatus(D) {
        var p;
        if (p = this._states.jobStatus(this.options.id), !(p === D || D === "DONE" && p === null))
          throw new C(`Invalid job status ${p}, expected ${D}. Please open an issue at https://github.com/SGrondin/bottleneck/issues`);
      }
      doReceive() {
        return this._states.start(this.options.id), this.Events.trigger("received", { args: this.args, options: this.options });
      }
      doQueue(D, p) {
        return this._assertStatus("RECEIVED"), this._states.next(this.options.id), this.Events.trigger("queued", { args: this.args, options: this.options, reachedHWM: D, blocked: p });
      }
      doRun() {
        return this.retryCount === 0 ? (this._assertStatus("QUEUED"), this._states.next(this.options.id)) : this._assertStatus("EXECUTING"), this.Events.trigger("scheduled", { args: this.args, options: this.options });
      }
      async doExecute(D, p, k, G) {
        var L, V, se;
        this.retryCount === 0 ? (this._assertStatus("RUNNING"), this._states.next(this.options.id)) : this._assertStatus("EXECUTING"), V = { args: this.args, options: this.options, retryCount: this.retryCount }, this.Events.trigger("executing", V);
        try {
          if (se = await (D != null ? D.schedule(this.options, this.task, ...this.args) : this.task(...this.args)), p())
            return this.doDone(V), await G(this.options, V), this._assertStatus("DONE"), this._resolve(se);
        } catch (fe) {
          return L = fe, this._onFailure(L, V, p, k, G);
        }
      }
      doExpire(D, p, k) {
        var G, L;
        return this._states.jobStatus(this.options.id === "RUNNING") && this._states.next(this.options.id), this._assertStatus("EXECUTING"), L = { args: this.args, options: this.options, retryCount: this.retryCount }, G = new C(`This job timed out after ${this.options.expiration} ms.`), this._onFailure(G, L, D, p, k);
      }
      async _onFailure(D, p, k, G, L) {
        var V, se;
        if (k())
          return V = await this.Events.trigger("failed", D, p), V != null ? (se = ~~V, this.Events.trigger("retry", `Retrying ${this.options.id} after ${se} ms`, p), this.retryCount++, G(se)) : (this.doDone(p), await L(this.options, p), this._assertStatus("DONE"), this._reject(D));
      }
      doDone(D) {
        return this._assertStatus("EXECUTING"), this._states.next(this.options.id), this.Events.trigger("done", D);
      }
    };
    var y = B, b, w, S;
    S = n, b = h, w = class {
      constructor(D, p, k) {
        this.instance = D, this.storeOptions = p, this.clientId = this.instance._randomIndex(), S.load(k, k, this), this._nextRequest = this._lastReservoirRefresh = this._lastReservoirIncrease = Date.now(), this._running = 0, this._done = 0, this._unblockTime = 0, this.ready = this.Promise.resolve(), this.clients = {}, this._startHeartbeat();
      }
      _startHeartbeat() {
        var D;
        return this.heartbeat == null && (this.storeOptions.reservoirRefreshInterval != null && this.storeOptions.reservoirRefreshAmount != null || this.storeOptions.reservoirIncreaseInterval != null && this.storeOptions.reservoirIncreaseAmount != null) ? typeof (D = this.heartbeat = setInterval(() => {
          var p, k, G, L, V;
          if (L = Date.now(), this.storeOptions.reservoirRefreshInterval != null && L >= this._lastReservoirRefresh + this.storeOptions.reservoirRefreshInterval && (this._lastReservoirRefresh = L, this.storeOptions.reservoir = this.storeOptions.reservoirRefreshAmount, this.instance._drainAll(this.computeCapacity())), this.storeOptions.reservoirIncreaseInterval != null && L >= this._lastReservoirIncrease + this.storeOptions.reservoirIncreaseInterval && ({
            reservoirIncreaseAmount: p,
            reservoirIncreaseMaximum: G,
            reservoir: V
          } = this.storeOptions, this._lastReservoirIncrease = L, k = G != null ? Math.min(p, G - V) : p, k > 0))
            return this.storeOptions.reservoir += k, this.instance._drainAll(this.computeCapacity());
        }, this.heartbeatInterval)).unref == "function" ? D.unref() : void 0 : clearInterval(this.heartbeat);
      }
      async __publish__(D) {
        return await this.yieldLoop(), this.instance.Events.trigger("message", D.toString());
      }
      async __disconnect__(D) {
        return await this.yieldLoop(), clearInterval(this.heartbeat), this.Promise.resolve();
      }
      yieldLoop(D = 0) {
        return new this.Promise(function(p, k) {
          return setTimeout(p, D);
        });
      }
      computePenalty() {
        var D;
        return (D = this.storeOptions.penalty) != null ? D : 15 * this.storeOptions.minTime || 5e3;
      }
      async __updateSettings__(D) {
        return await this.yieldLoop(), S.overwrite(D, D, this.storeOptions), this._startHeartbeat(), this.instance._drainAll(this.computeCapacity()), !0;
      }
      async __running__() {
        return await this.yieldLoop(), this._running;
      }
      async __queued__() {
        return await this.yieldLoop(), this.instance.queued();
      }
      async __done__() {
        return await this.yieldLoop(), this._done;
      }
      async __groupCheck__(D) {
        return await this.yieldLoop(), this._nextRequest + this.timeout < D;
      }
      computeCapacity() {
        var D, p;
        return { maxConcurrent: D, reservoir: p } = this.storeOptions, D != null && p != null ? Math.min(D - this._running, p) : D != null ? D - this._running : p ?? null;
      }
      conditionsCheck(D) {
        var p;
        return p = this.computeCapacity(), p == null || D <= p;
      }
      async __incrementReservoir__(D) {
        var p;
        return await this.yieldLoop(), p = this.storeOptions.reservoir += D, this.instance._drainAll(this.computeCapacity()), p;
      }
      async __currentReservoir__() {
        return await this.yieldLoop(), this.storeOptions.reservoir;
      }
      isBlocked(D) {
        return this._unblockTime >= D;
      }
      check(D, p) {
        return this.conditionsCheck(D) && this._nextRequest - p <= 0;
      }
      async __check__(D) {
        var p;
        return await this.yieldLoop(), p = Date.now(), this.check(D, p);
      }
      async __register__(D, p, k) {
        var G, L;
        return await this.yieldLoop(), G = Date.now(), this.conditionsCheck(p) ? (this._running += p, this.storeOptions.reservoir != null && (this.storeOptions.reservoir -= p), L = Math.max(this._nextRequest - G, 0), this._nextRequest = G + L + this.storeOptions.minTime, {
          success: !0,
          wait: L,
          reservoir: this.storeOptions.reservoir
        }) : {
          success: !1
        };
      }
      strategyIsBlock() {
        return this.storeOptions.strategy === 3;
      }
      async __submit__(D, p) {
        var k, G, L;
        if (await this.yieldLoop(), this.storeOptions.maxConcurrent != null && p > this.storeOptions.maxConcurrent)
          throw new b(`Impossible to add a job having a weight of ${p} to a limiter having a maxConcurrent setting of ${this.storeOptions.maxConcurrent}`);
        return G = Date.now(), L = this.storeOptions.highWater != null && D === this.storeOptions.highWater && !this.check(p, G), k = this.strategyIsBlock() && (L || this.isBlocked(G)), k && (this._unblockTime = G + this.computePenalty(), this._nextRequest = this._unblockTime + this.storeOptions.minTime, this.instance._dropAllQueued()), {
          reachedHWM: L,
          blocked: k,
          strategy: this.storeOptions.strategy
        };
      }
      async __free__(D, p) {
        return await this.yieldLoop(), this._running -= p, this._done += p, this.instance._drainAll(this.computeCapacity()), {
          running: this._running
        };
      }
    };
    var v = w, N, F;
    N = h, F = class {
      constructor(D) {
        this.status = D, this._jobs = {}, this.counts = this.status.map(function() {
          return 0;
        });
      }
      next(D) {
        var p, k;
        if (p = this._jobs[D], k = p + 1, p != null && k < this.status.length)
          return this.counts[p]--, this.counts[k]++, this._jobs[D]++;
        if (p != null)
          return this.counts[p]--, delete this._jobs[D];
      }
      start(D) {
        var p;
        return p = 0, this._jobs[D] = p, this.counts[p]++;
      }
      remove(D) {
        var p;
        return p = this._jobs[D], p != null && (this.counts[p]--, delete this._jobs[D]), p != null;
      }
      jobStatus(D) {
        var p;
        return (p = this.status[this._jobs[D]]) != null ? p : null;
      }
      statusJobs(D) {
        var p, k, G, L, V;
        if (D != null) {
          if (k = this.status.indexOf(D), k < 0)
            throw new N(`status must be one of ${this.status.join(", ")}`);
          G = this._jobs, L = [];
          for (p in G)
            V = G[p], V === k && L.push(p);
          return L;
        } else
          return Object.keys(this._jobs);
      }
      statusCounts() {
        return this.counts.reduce((D, p, k) => (D[this.status[k]] = p, D), {});
      }
    };
    var j = F, M, K;
    M = a, K = class {
      constructor(D, p) {
        this.schedule = this.schedule.bind(this), this.name = D, this.Promise = p, this._running = 0, this._queue = new M();
      }
      isEmpty() {
        return this._queue.length === 0;
      }
      async _tryToRun() {
        var D, p, k, G, L, V, se;
        if (this._running < 1 && this._queue.length > 0)
          return this._running++, { task: se, args: D, resolve: L, reject: G } = this._queue.shift(), p = await async function() {
            try {
              return V = await se(...D), function() {
                return L(V);
              };
            } catch (fe) {
              return k = fe, function() {
                return G(k);
              };
            }
          }(), this._running--, this._tryToRun(), p();
      }
      schedule(D, ...p) {
        var k, G, L;
        return L = G = null, k = new this.Promise(function(V, se) {
          return L = V, G = se;
        }), this._queue.push({ task: D, args: p, resolve: L, reject: G }), this._tryToRun(), k;
      }
    };
    var ee = K, ie = "2.19.5", re = {
      version: ie
    }, ge = /* @__PURE__ */ Object.freeze({
      version: ie,
      default: re
    }), Y = () => console.log("You must import the full version of Bottleneck in order to use this feature."), Ae = () => console.log("You must import the full version of Bottleneck in order to use this feature."), ae = () => console.log("You must import the full version of Bottleneck in order to use this feature."), de, R, H, $, X, z;
    z = n, de = c, $ = Y, H = Ae, X = ae, R = function() {
      class _ {
        constructor(p = {}) {
          this.deleteKey = this.deleteKey.bind(this), this.limiterOptions = p, z.load(this.limiterOptions, this.defaults, this), this.Events = new de(this), this.instances = {}, this.Bottleneck = T, this._startAutoCleanup(), this.sharedConnection = this.connection != null, this.connection == null && (this.limiterOptions.datastore === "redis" ? this.connection = new $(Object.assign({}, this.limiterOptions, { Events: this.Events })) : this.limiterOptions.datastore === "ioredis" && (this.connection = new H(Object.assign({}, this.limiterOptions, { Events: this.Events }))));
        }
        key(p = "") {
          var k;
          return (k = this.instances[p]) != null ? k : (() => {
            var G;
            return G = this.instances[p] = new this.Bottleneck(Object.assign(this.limiterOptions, {
              id: `${this.id}-${p}`,
              timeout: this.timeout,
              connection: this.connection
            })), this.Events.trigger("created", G, p), G;
          })();
        }
        async deleteKey(p = "") {
          var k, G;
          return G = this.instances[p], this.connection && (k = await this.connection.__runCommand__(["del", ...X.allKeys(`${this.id}-${p}`)])), G != null && (delete this.instances[p], await G.disconnect()), G != null || k > 0;
        }
        limiters() {
          var p, k, G, L;
          k = this.instances, G = [];
          for (p in k)
            L = k[p], G.push({
              key: p,
              limiter: L
            });
          return G;
        }
        keys() {
          return Object.keys(this.instances);
        }
        async clusterKeys() {
          var p, k, G, L, V, se, fe, Ve, xe;
          if (this.connection == null)
            return this.Promise.resolve(this.keys());
          for (se = [], p = null, xe = `b_${this.id}-`.length, k = 9; p !== 0; )
            for ([Ve, G] = await this.connection.__runCommand__(["scan", p ?? 0, "match", `b_${this.id}-*_settings`, "count", 1e4]), p = ~~Ve, L = 0, fe = G.length; L < fe; L++)
              V = G[L], se.push(V.slice(xe, -k));
          return se;
        }
        _startAutoCleanup() {
          var p;
          return clearInterval(this.interval), typeof (p = this.interval = setInterval(async () => {
            var k, G, L, V, se, fe;
            se = Date.now(), L = this.instances, V = [];
            for (G in L) {
              fe = L[G];
              try {
                await fe._store.__groupCheck__(se) ? V.push(this.deleteKey(G)) : V.push(void 0);
              } catch (Ve) {
                k = Ve, V.push(fe.Events.trigger("error", k));
              }
            }
            return V;
          }, this.timeout / 2)).unref == "function" ? p.unref() : void 0;
        }
        updateSettings(p = {}) {
          if (z.overwrite(p, this.defaults, this), z.overwrite(p, p, this.limiterOptions), p.timeout != null)
            return this._startAutoCleanup();
        }
        disconnect(p = !0) {
          var k;
          if (!this.sharedConnection)
            return (k = this.connection) != null ? k.disconnect(p) : void 0;
        }
      }
      return _.prototype.defaults = {
        timeout: 1e3 * 60 * 5,
        connection: null,
        Promise,
        id: "group-key"
      }, _;
    }.call(t);
    var W = R, P, le, Qe;
    Qe = n, le = c, P = function() {
      class _ {
        constructor(p = {}) {
          this.options = p, Qe.load(this.options, this.defaults, this), this.Events = new le(this), this._arr = [], this._resetPromise(), this._lastFlush = Date.now();
        }
        _resetPromise() {
          return this._promise = new this.Promise((p, k) => this._resolve = p);
        }
        _flush() {
          return clearTimeout(this._timeout), this._lastFlush = Date.now(), this._resolve(), this.Events.trigger("batch", this._arr), this._arr = [], this._resetPromise();
        }
        add(p) {
          var k;
          return this._arr.push(p), k = this._promise, this._arr.length === this.maxSize ? this._flush() : this.maxTime != null && this._arr.length === 1 && (this._timeout = setTimeout(() => this._flush(), this.maxTime)), k;
        }
      }
      return _.prototype.defaults = {
        maxTime: null,
        maxSize: null,
        Promise
      }, _;
    }.call(t);
    var Ee = P, Ge = () => console.log("You must import the full version of Bottleneck in order to use this feature."), De = r(ge), Ue, ye, Ce, Ie, me, Ne, oA, Be, Te, eA, $e, Nt = [].splice;
    Ne = 10, ye = 5, $e = n, oA = I, Ie = y, me = v, Be = Ge, Ce = c, Te = j, eA = ee, Ue = function() {
      class _ {
        constructor(p = {}, ...k) {
          var G, L;
          this._addToQueue = this._addToQueue.bind(this), this._validateOptions(p, k), $e.load(p, this.instanceDefaults, this), this._queues = new oA(Ne), this._scheduled = {}, this._states = new Te(["RECEIVED", "QUEUED", "RUNNING", "EXECUTING"].concat(this.trackDoneStatus ? ["DONE"] : [])), this._limiter = null, this.Events = new Ce(this), this._submitLock = new eA("submit", this.Promise), this._registerLock = new eA("register", this.Promise), L = $e.load(p, this.storeDefaults, {}), this._store = function() {
            if (this.datastore === "redis" || this.datastore === "ioredis" || this.connection != null)
              return G = $e.load(p, this.redisStoreDefaults, {}), new Be(this, L, G);
            if (this.datastore === "local")
              return G = $e.load(p, this.localStoreDefaults, {}), new me(this, L, G);
            throw new _.prototype.BottleneckError(`Invalid datastore type: ${this.datastore}`);
          }.call(this), this._queues.on("leftzero", () => {
            var V;
            return (V = this._store.heartbeat) != null && typeof V.ref == "function" ? V.ref() : void 0;
          }), this._queues.on("zero", () => {
            var V;
            return (V = this._store.heartbeat) != null && typeof V.unref == "function" ? V.unref() : void 0;
          });
        }
        _validateOptions(p, k) {
          if (!(p != null && typeof p == "object" && k.length === 0))
            throw new _.prototype.BottleneckError("Bottleneck v2 takes a single object argument. Refer to https://github.com/SGrondin/bottleneck#upgrading-to-v2 if you're upgrading from Bottleneck v1.");
        }
        ready() {
          return this._store.ready;
        }
        clients() {
          return this._store.clients;
        }
        channel() {
          return `b_${this.id}`;
        }
        channel_client() {
          return `b_${this.id}_${this._store.clientId}`;
        }
        publish(p) {
          return this._store.__publish__(p);
        }
        disconnect(p = !0) {
          return this._store.__disconnect__(p);
        }
        chain(p) {
          return this._limiter = p, this;
        }
        queued(p) {
          return this._queues.queued(p);
        }
        clusterQueued() {
          return this._store.__queued__();
        }
        empty() {
          return this.queued() === 0 && this._submitLock.isEmpty();
        }
        running() {
          return this._store.__running__();
        }
        done() {
          return this._store.__done__();
        }
        jobStatus(p) {
          return this._states.jobStatus(p);
        }
        jobs(p) {
          return this._states.statusJobs(p);
        }
        counts() {
          return this._states.statusCounts();
        }
        _randomIndex() {
          return Math.random().toString(36).slice(2);
        }
        check(p = 1) {
          return this._store.__check__(p);
        }
        _clearGlobalState(p) {
          return this._scheduled[p] != null ? (clearTimeout(this._scheduled[p].expiration), delete this._scheduled[p], !0) : !1;
        }
        async _free(p, k, G, L) {
          var V, se;
          try {
            if ({ running: se } = await this._store.__free__(p, G.weight), this.Events.trigger("debug", `Freed ${G.id}`, L), se === 0 && this.empty())
              return this.Events.trigger("idle");
          } catch (fe) {
            return V = fe, this.Events.trigger("error", V);
          }
        }
        _run(p, k, G) {
          var L, V, se;
          return k.doRun(), L = this._clearGlobalState.bind(this, p), se = this._run.bind(this, p, k), V = this._free.bind(this, p, k), this._scheduled[p] = {
            timeout: setTimeout(() => k.doExecute(this._limiter, L, se, V), G),
            expiration: k.options.expiration != null ? setTimeout(function() {
              return k.doExpire(L, se, V);
            }, G + k.options.expiration) : void 0,
            job: k
          };
        }
        _drainOne(p) {
          return this._registerLock.schedule(() => {
            var k, G, L, V, se;
            return this.queued() === 0 ? this.Promise.resolve(null) : (se = this._queues.getFirst(), { options: V, args: k } = L = se.first(), p != null && V.weight > p ? this.Promise.resolve(null) : (this.Events.trigger("debug", `Draining ${V.id}`, { args: k, options: V }), G = this._randomIndex(), this._store.__register__(G, V.weight, V.expiration).then(({ success: fe, wait: Ve, reservoir: xe }) => {
              var jA;
              return this.Events.trigger("debug", `Drained ${V.id}`, { success: fe, args: k, options: V }), fe ? (se.shift(), jA = this.empty(), jA && this.Events.trigger("empty"), xe === 0 && this.Events.trigger("depleted", jA), this._run(G, L, Ve), this.Promise.resolve(V.weight)) : this.Promise.resolve(null);
            })));
          });
        }
        _drainAll(p, k = 0) {
          return this._drainOne(p).then((G) => {
            var L;
            return G != null ? (L = p != null ? p - G : p, this._drainAll(L, k + G)) : this.Promise.resolve(k);
          }).catch((G) => this.Events.trigger("error", G));
        }
        _dropAllQueued(p) {
          return this._queues.shiftAll(function(k) {
            return k.doDrop({ message: p });
          });
        }
        stop(p = {}) {
          var k, G;
          return p = $e.load(p, this.stopDefaults), G = (L) => {
            var V;
            return V = () => {
              var se;
              return se = this._states.counts, se[0] + se[1] + se[2] + se[3] === L;
            }, new this.Promise((se, fe) => V() ? se() : this.on("done", () => {
              if (V())
                return this.removeAllListeners("done"), se();
            }));
          }, k = p.dropWaitingJobs ? (this._run = function(L, V) {
            return V.doDrop({
              message: p.dropErrorMessage
            });
          }, this._drainOne = () => this.Promise.resolve(null), this._registerLock.schedule(() => this._submitLock.schedule(() => {
            var L, V, se;
            V = this._scheduled;
            for (L in V)
              se = V[L], this.jobStatus(se.job.options.id) === "RUNNING" && (clearTimeout(se.timeout), clearTimeout(se.expiration), se.job.doDrop({
                message: p.dropErrorMessage
              }));
            return this._dropAllQueued(p.dropErrorMessage), G(0);
          }))) : this.schedule({
            priority: Ne - 1,
            weight: 0
          }, () => G(1)), this._receive = function(L) {
            return L._reject(new _.prototype.BottleneckError(p.enqueueErrorMessage));
          }, this.stop = () => this.Promise.reject(new _.prototype.BottleneckError("stop() has already been called")), k;
        }
        async _addToQueue(p) {
          var k, G, L, V, se, fe, Ve;
          ({ args: k, options: V } = p);
          try {
            ({ reachedHWM: se, blocked: G, strategy: Ve } = await this._store.__submit__(this.queued(), V.weight));
          } catch (xe) {
            return L = xe, this.Events.trigger("debug", `Could not queue ${V.id}`, { args: k, options: V, error: L }), p.doDrop({ error: L }), !1;
          }
          return G ? (p.doDrop(), !0) : se && (fe = Ve === _.prototype.strategy.LEAK ? this._queues.shiftLastFrom(V.priority) : Ve === _.prototype.strategy.OVERFLOW_PRIORITY ? this._queues.shiftLastFrom(V.priority + 1) : Ve === _.prototype.strategy.OVERFLOW ? p : void 0, fe?.doDrop(), fe == null || Ve === _.prototype.strategy.OVERFLOW) ? (fe == null && p.doDrop(), se) : (p.doQueue(se, G), this._queues.push(p), await this._drainAll(), se);
        }
        _receive(p) {
          return this._states.jobStatus(p.options.id) != null ? (p._reject(new _.prototype.BottleneckError(`A job with the same id already exists (id=${p.options.id})`)), !1) : (p.doReceive(), this._submitLock.schedule(this._addToQueue, p));
        }
        submit(...p) {
          var k, G, L, V, se, fe, Ve;
          return typeof p[0] == "function" ? (se = p, [G, ...p] = se, [k] = Nt.call(p, -1), V = $e.load({}, this.jobDefaults)) : (fe = p, [V, G, ...p] = fe, [k] = Nt.call(p, -1), V = $e.load(V, this.jobDefaults)), Ve = (...xe) => new this.Promise(function(jA, oo) {
            return G(...xe, function(...ur) {
              return (ur[0] != null ? oo : jA)(ur);
            });
          }), L = new Ie(Ve, p, V, this.jobDefaults, this.rejectOnDrop, this.Events, this._states, this.Promise), L.promise.then(function(xe) {
            return typeof k == "function" ? k(...xe) : void 0;
          }).catch(function(xe) {
            return Array.isArray(xe) ? typeof k == "function" ? k(...xe) : void 0 : typeof k == "function" ? k(xe) : void 0;
          }), this._receive(L);
        }
        schedule(...p) {
          var k, G, L;
          return typeof p[0] == "function" ? ([L, ...p] = p, G = {}) : [G, L, ...p] = p, k = new Ie(L, p, G, this.jobDefaults, this.rejectOnDrop, this.Events, this._states, this.Promise), this._receive(k), k.promise;
        }
        wrap(p) {
          var k, G;
          return k = this.schedule.bind(this), G = function(...L) {
            return k(p.bind(this), ...L);
          }, G.withOptions = function(L, ...V) {
            return k(L, p, ...V);
          }, G;
        }
        async updateSettings(p = {}) {
          return await this._store.__updateSettings__($e.overwrite(p, this.storeDefaults)), $e.overwrite(p, this.instanceDefaults, this), this;
        }
        currentReservoir() {
          return this._store.__currentReservoir__();
        }
        incrementReservoir(p = 0) {
          return this._store.__incrementReservoir__(p);
        }
      }
      return _.default = _, _.Events = Ce, _.version = _.prototype.version = De.version, _.strategy = _.prototype.strategy = {
        LEAK: 1,
        OVERFLOW: 2,
        OVERFLOW_PRIORITY: 4,
        BLOCK: 3
      }, _.BottleneckError = _.prototype.BottleneckError = h, _.Group = _.prototype.Group = W, _.RedisConnection = _.prototype.RedisConnection = Y, _.IORedisConnection = _.prototype.IORedisConnection = Ae, _.Batcher = _.prototype.Batcher = Ee, _.prototype.jobDefaults = {
        priority: ye,
        weight: 1,
        expiration: null,
        id: "<no-id>"
      }, _.prototype.storeDefaults = {
        maxConcurrent: null,
        minTime: 0,
        highWater: null,
        strategy: _.prototype.strategy.LEAK,
        penalty: null,
        reservoir: null,
        reservoirRefreshInterval: null,
        reservoirRefreshAmount: null,
        reservoirIncreaseInterval: null,
        reservoirIncreaseAmount: null,
        reservoirIncreaseMaximum: null
      }, _.prototype.localStoreDefaults = {
        Promise,
        timeout: null,
        heartbeatInterval: 250
      }, _.prototype.redisStoreDefaults = {
        Promise,
        timeout: null,
        heartbeatInterval: 5e3,
        clientTimeout: 1e4,
        Redis: null,
        clientOptions: {},
        clusterNodes: null,
        clearDatastore: !1,
        connection: null
      }, _.prototype.instanceDefaults = {
        datastore: "local",
        connection: null,
        id: "<no-id>",
        rejectOnDrop: !0,
        trackDoneStatus: !1,
        Promise
      }, _.prototype.stopDefaults = {
        enqueueErrorMessage: "This limiter has been stopped and cannot accept new jobs.",
        dropWaitingJobs: !0,
        dropErrorMessage: "This limiter has been stopped."
      }, _;
    }.call(t);
    var T = Ue, x = T;
    return x;
  });
})(Du);
var Qw = Du.exports;
const Tu = /* @__PURE__ */ el(Qw);
var Cw = "0.0.0-development";
async function ku(e, A, t, r) {
  if (!t.request || !t.request.request)
    throw t;
  if (t.status >= 400 && !e.doNotRetry.includes(t.status)) {
    const s = r.request.retries != null ? r.request.retries : e.retries, o = Math.pow((r.request.retryCount || 0) + 1, 2);
    throw A.retry.retryRequest(t, s, o);
  }
  throw t;
}
async function Bw(e, A, t, r) {
  const s = new Tu();
  return s.on("failed", function(o, n) {
    const i = ~~o.request.request.retries, a = ~~o.request.request.retryAfter;
    if (r.request.retryCount = n.retryCount + 1, i > n.retryCount)
      return a * e.retryAfterBaseValue;
  }), s.schedule(
    Iw.bind(null, e, A, t),
    r
  );
}
async function Iw(e, A, t, r) {
  const s = await t(t, r);
  if (s.data && s.data.errors && s.data.errors.length > 0 && /Something went wrong while executing your query/.test(
    s.data.errors[0].message
  )) {
    const o = new Gr(s.data.errors[0].message, 500, {
      request: r,
      response: s
    });
    return ku(e, A, o, r);
  }
  return s;
}
function Fu(e, A) {
  const t = Object.assign(
    {
      enabled: !0,
      retryAfterBaseValue: 1e3,
      doNotRetry: [400, 401, 403, 404, 422, 451],
      retries: 3
    },
    A.retry
  );
  return t.enabled && (e.hook.error("request", ku.bind(null, t, e)), e.hook.wrap("request", Bw.bind(null, t, e))), {
    retry: {
      retryRequest: (r, s, o) => (r.request.request = Object.assign({}, r.request.request, {
        retries: s,
        retryAfter: o
      }), r)
    }
  };
}
Fu.VERSION = Cw;
var pw = "0.0.0-development", Yn = () => Promise.resolve();
function fw(e, A, t) {
  return e.retryLimiter.schedule(mw, e, A, t);
}
async function mw(e, A, t) {
  const r = t.method !== "GET" && t.method !== "HEAD", { pathname: s } = new URL(t.url, "http://github.test"), o = t.method === "GET" && s.startsWith("/search/"), n = s.startsWith("/graphql"), a = ~~A.retryCount > 0 ? { priority: 0, weight: 0 } : {};
  e.clustering && (a.expiration = 1e3 * 60), (r || n) && await e.write.key(e.id).schedule(a, Yn), r && e.triggersNotification(s) && await e.notifications.key(e.id).schedule(a, Yn), o && await e.search.key(e.id).schedule(a, Yn);
  const g = e.global.key(e.id).schedule(a, A, t);
  if (n) {
    const c = await g;
    if (c.data.errors != null && c.data.errors.some((E) => E.type === "RATE_LIMITED"))
      throw Object.assign(new Error("GraphQL Rate Limit Exceeded"), {
        response: c,
        data: c.data
      });
  }
  return g;
}
var ww = [
  "/orgs/{org}/invitations",
  "/orgs/{org}/invitations/{invitation_id}",
  "/orgs/{org}/teams/{team_slug}/discussions",
  "/orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments",
  "/repos/{owner}/{repo}/collaborators/{username}",
  "/repos/{owner}/{repo}/commits/{commit_sha}/comments",
  "/repos/{owner}/{repo}/issues",
  "/repos/{owner}/{repo}/issues/{issue_number}/comments",
  "/repos/{owner}/{repo}/issues/{issue_number}/sub_issue",
  "/repos/{owner}/{repo}/issues/{issue_number}/sub_issues/priority",
  "/repos/{owner}/{repo}/pulls",
  "/repos/{owner}/{repo}/pulls/{pull_number}/comments",
  "/repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies",
  "/repos/{owner}/{repo}/pulls/{pull_number}/merge",
  "/repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers",
  "/repos/{owner}/{repo}/pulls/{pull_number}/reviews",
  "/repos/{owner}/{repo}/releases",
  "/teams/{team_id}/discussions",
  "/teams/{team_id}/discussions/{discussion_number}/comments"
];
function yw(e) {
  const t = `^(?:${e.map(
    (r) => r.split("/").map((s) => s.startsWith("{") ? "(?:.+?)" : s).join("/")
  ).map((r) => `(?:${r})`).join("|")})[^/]*$`;
  return new RegExp(t, "i");
}
var Rg = yw(ww), Su = Rg.test.bind(Rg), $t = {}, bw = function(e, A) {
  $t.global = new e.Group({
    id: "octokit-global",
    maxConcurrent: 10,
    ...A
  }), $t.search = new e.Group({
    id: "octokit-search",
    maxConcurrent: 1,
    minTime: 2e3,
    ...A
  }), $t.write = new e.Group({
    id: "octokit-write",
    maxConcurrent: 1,
    minTime: 1e3,
    ...A
  }), $t.notifications = new e.Group({
    id: "octokit-notifications",
    maxConcurrent: 1,
    minTime: 3e3,
    ...A
  });
};
function Mi(e, A) {
  const {
    enabled: t = !0,
    Bottleneck: r = Tu,
    id: s = "no-id",
    timeout: o = 1e3 * 60 * 2,
    // Redis TTL: 2 minutes
    connection: n
  } = A.throttle || {};
  if (!t)
    return {};
  const i = { timeout: o };
  typeof n < "u" && (i.connection = n), $t.global == null && bw(r, i);
  const a = Object.assign(
    {
      clustering: n != null,
      triggersNotification: Su,
      fallbackSecondaryRateRetryAfter: 60,
      retryAfterBaseValue: 1e3,
      retryLimiter: new r(),
      id: s,
      ...$t
    },
    A.throttle
  );
  if (typeof a.onSecondaryRateLimit != "function" || typeof a.onRateLimit != "function")
    throw new Error(`octokit/plugin-throttling error:
        You must pass the onSecondaryRateLimit and onRateLimit error handlers.
        See https://octokit.github.io/rest.js/#throttling

        const octokit = new Octokit({
          throttle: {
            onSecondaryRateLimit: (retryAfter, options) => {/* ... */},
            onRateLimit: (retryAfter, options) => {/* ... */}
          }
        })
    `);
  const g = {}, c = new r.Events(g);
  return g.on("secondary-limit", a.onSecondaryRateLimit), g.on("rate-limit", a.onRateLimit), g.on(
    "error",
    (E) => e.log.warn("Error in throttling-plugin limit handler", E)
  ), a.retryLimiter.on("failed", async function(E, l) {
    const [Q, I, d] = l.args, { pathname: h } = new URL(d.url, "http://github.test");
    if (!(h.startsWith("/graphql") && E.status !== 401 || E.status === 403 || E.status === 429))
      return;
    const u = ~~I.retryCount;
    I.retryCount = u, d.request.retryCount = u;
    const { wantRetry: B, retryAfter: m = 0 } = await async function() {
      if (/\bsecondary rate\b/i.test(E.message)) {
        const f = Number(E.response.headers["retry-after"]) || Q.fallbackSecondaryRateRetryAfter;
        return { wantRetry: await c.trigger(
          "secondary-limit",
          f,
          d,
          e,
          u
        ), retryAfter: f };
      }
      if (E.response.headers != null && E.response.headers["x-ratelimit-remaining"] === "0" || (E.response.data?.errors ?? []).some(
        (f) => f.type === "RATE_LIMITED"
      )) {
        const f = new Date(
          ~~E.response.headers["x-ratelimit-reset"] * 1e3
        ).getTime(), y = Math.max(
          // Add one second so we retry _after_ the reset time
          // https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#exceeding-the-rate-limit
          Math.ceil((f - Date.now()) / 1e3) + 1,
          0
        );
        return { wantRetry: await c.trigger(
          "rate-limit",
          y,
          d,
          e,
          u
        ), retryAfter: y };
      }
      return {};
    }();
    if (B)
      return I.retryCount++, m * Q.retryAfterBaseValue;
  }), e.hook.wrap("request", fw.bind(null, a)), {};
}
Mi.VERSION = pw;
Mi.triggersNotification = Su;
var Rw = "0.0.0-development", Dw = zm.plugin(
  Ru,
  fu,
  cw,
  Fu,
  Mi
).defaults({
  userAgent: `octokit.js/${Rw}`,
  throttle: {
    onRateLimit: Tw,
    onSecondaryRateLimit: kw
  }
});
function Tw(e, A, t) {
  if (t.log.warn(
    `Request quota exhausted for request ${A.method} ${A.url}`
  ), A.request.retryCount === 0)
    return t.log.info(`Retrying after ${e} seconds!`), !0;
}
function kw(e, A, t) {
  if (t.log.warn(
    `SecondaryRateLimit detected for request ${A.method} ${A.url}`
  ), A.request.retryCount === 0)
    return t.log.info(`Retrying after ${e} seconds!`), !0;
}
async function Fw(e, A) {
  const t = new Dw({ auth: e });
  try {
    return (await t.rest.pulls.get({
      owner: A.repo.owner,
      repo: A.repo.repo,
      pull_number: A.issue.number,
      mediaType: { format: "diff" }
    })).data;
  } catch (r) {
    throw new Error(`Failed to get PR diff: ${r.message}`);
  }
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var Dg;
(function(e) {
  e.HARM_CATEGORY_UNSPECIFIED = "HARM_CATEGORY_UNSPECIFIED", e.HARM_CATEGORY_HATE_SPEECH = "HARM_CATEGORY_HATE_SPEECH", e.HARM_CATEGORY_SEXUALLY_EXPLICIT = "HARM_CATEGORY_SEXUALLY_EXPLICIT", e.HARM_CATEGORY_HARASSMENT = "HARM_CATEGORY_HARASSMENT", e.HARM_CATEGORY_DANGEROUS_CONTENT = "HARM_CATEGORY_DANGEROUS_CONTENT";
})(Dg || (Dg = {}));
var Tg;
(function(e) {
  e.HARM_BLOCK_THRESHOLD_UNSPECIFIED = "HARM_BLOCK_THRESHOLD_UNSPECIFIED", e.BLOCK_LOW_AND_ABOVE = "BLOCK_LOW_AND_ABOVE", e.BLOCK_MEDIUM_AND_ABOVE = "BLOCK_MEDIUM_AND_ABOVE", e.BLOCK_ONLY_HIGH = "BLOCK_ONLY_HIGH", e.BLOCK_NONE = "BLOCK_NONE";
})(Tg || (Tg = {}));
var kg;
(function(e) {
  e.HARM_PROBABILITY_UNSPECIFIED = "HARM_PROBABILITY_UNSPECIFIED", e.NEGLIGIBLE = "NEGLIGIBLE", e.LOW = "LOW", e.MEDIUM = "MEDIUM", e.HIGH = "HIGH";
})(kg || (kg = {}));
var Fg;
(function(e) {
  e.BLOCKED_REASON_UNSPECIFIED = "BLOCKED_REASON_UNSPECIFIED", e.SAFETY = "SAFETY", e.OTHER = "OTHER";
})(Fg || (Fg = {}));
var Ps;
(function(e) {
  e.FINISH_REASON_UNSPECIFIED = "FINISH_REASON_UNSPECIFIED", e.STOP = "STOP", e.MAX_TOKENS = "MAX_TOKENS", e.SAFETY = "SAFETY", e.RECITATION = "RECITATION", e.OTHER = "OTHER";
})(Ps || (Ps = {}));
var Sg;
(function(e) {
  e.TASK_TYPE_UNSPECIFIED = "TASK_TYPE_UNSPECIFIED", e.RETRIEVAL_QUERY = "RETRIEVAL_QUERY", e.RETRIEVAL_DOCUMENT = "RETRIEVAL_DOCUMENT", e.SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY", e.CLASSIFICATION = "CLASSIFICATION", e.CLUSTERING = "CLUSTERING";
})(Sg || (Sg = {}));
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
class Jr extends Error {
  constructor(A) {
    super(`[GoogleGenerativeAI Error]: ${A}`);
  }
}
class Ug extends Jr {
  constructor(A, t) {
    super(A), this.response = t;
  }
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const Sw = "https://generativelanguage.googleapis.com", Uw = "v1", Gw = "0.1.3", _w = "genai-js";
var St;
(function(e) {
  e.GENERATE_CONTENT = "generateContent", e.STREAM_GENERATE_CONTENT = "streamGenerateContent", e.COUNT_TOKENS = "countTokens", e.EMBED_CONTENT = "embedContent", e.BATCH_EMBED_CONTENTS = "batchEmbedContents";
})(St || (St = {}));
class As {
  constructor(A, t, r, s) {
    this.model = A, this.task = t, this.apiKey = r, this.stream = s;
  }
  toString() {
    let A = `${Sw}/${Uw}/models/${this.model}:${this.task}`;
    return this.stream && (A += "?alt=sse"), A;
  }
}
function Nw() {
  return `${_w}/${Gw}`;
}
async function ts(e, A) {
  let t;
  try {
    if (t = await fetch(e.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-client": Nw(),
        "x-goog-api-key": e.apiKey
      },
      body: A
    }), !t.ok) {
      let r = "";
      try {
        const s = await t.json();
        r = s.error.message, s.error.details && (r += ` ${JSON.stringify(s.error.details)}`);
      } catch {
      }
      throw new Error(`[${t.status} ${t.statusText}] ${r}`);
    }
  } catch (r) {
    const s = new Jr(`Error fetching from ${e.toString()}: ${r.message}`);
    throw s.stack = r.stack, s;
  }
  return t;
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
function Oi(e) {
  return e.text = () => {
    if (e.candidates && e.candidates.length > 0) {
      if (e.candidates.length > 1 && console.warn(`This response had ${e.candidates.length} candidates. Returning text from the first candidate only. Access response.candidates directly to use the other candidates.`), Uu(e.candidates[0]))
        throw new Ug(`${Ys(e)}`, e);
      return vw(e);
    } else if (e.promptFeedback)
      throw new Ug(`Text not available. ${Ys(e)}`, e);
    return "";
  }, e;
}
function vw(e) {
  var A, t, r, s;
  return !((s = (r = (t = (A = e.candidates) === null || A === void 0 ? void 0 : A[0].content) === null || t === void 0 ? void 0 : t.parts) === null || r === void 0 ? void 0 : r[0]) === null || s === void 0) && s.text ? e.candidates[0].content.parts[0].text : "";
}
const Lw = [Ps.RECITATION, Ps.SAFETY];
function Uu(e) {
  return !!e.finishReason && Lw.includes(e.finishReason);
}
function Ys(e) {
  var A, t, r;
  let s = "";
  if ((!e.candidates || e.candidates.length === 0) && e.promptFeedback)
    s += "Response was blocked", !((A = e.promptFeedback) === null || A === void 0) && A.blockReason && (s += ` due to ${e.promptFeedback.blockReason}`), !((t = e.promptFeedback) === null || t === void 0) && t.blockReasonMessage && (s += `: ${e.promptFeedback.blockReasonMessage}`);
  else if (!((r = e.candidates) === null || r === void 0) && r[0]) {
    const o = e.candidates[0];
    Uu(o) && (s += `Candidate was blocked due to ${o.finishReason}`, o.finishMessage && (s += `: ${o.finishMessage}`));
  }
  return s;
}
function Hr(e) {
  return this instanceof Hr ? (this.v = e, this) : new Hr(e);
}
function Mw(e, A, t) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var r = t.apply(e, A || []), s, o = [];
  return s = {}, n("next"), n("throw"), n("return"), s[Symbol.asyncIterator] = function() {
    return this;
  }, s;
  function n(l) {
    r[l] && (s[l] = function(Q) {
      return new Promise(function(I, d) {
        o.push([l, Q, I, d]) > 1 || i(l, Q);
      });
    });
  }
  function i(l, Q) {
    try {
      a(r[l](Q));
    } catch (I) {
      E(o[0][3], I);
    }
  }
  function a(l) {
    l.value instanceof Hr ? Promise.resolve(l.value.v).then(g, c) : E(o[0][2], l);
  }
  function g(l) {
    i("next", l);
  }
  function c(l) {
    i("throw", l);
  }
  function E(l, Q) {
    l(Q), o.shift(), o.length && i(o[0][0], o[0][1]);
  }
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const Gg = /^data\: (.*)(?:\n\n|\r\r|\r\n\r\n)/;
function Ow(e) {
  const A = e.body.pipeThrough(new TextDecoderStream("utf8", { fatal: !0 })), t = xw(A), [r, s] = t.tee();
  return {
    stream: Yw(r),
    response: Pw(s)
  };
}
async function Pw(e) {
  const A = [], t = e.getReader();
  for (; ; ) {
    const { done: r, value: s } = await t.read();
    if (r)
      return Oi(Jw(A));
    A.push(s);
  }
}
function Yw(e) {
  return Mw(this, arguments, function* () {
    const t = e.getReader();
    for (; ; ) {
      const { value: r, done: s } = yield Hr(t.read());
      if (s)
        break;
      yield yield Hr(Oi(r));
    }
  });
}
function xw(e) {
  const A = e.getReader();
  return new ReadableStream({
    start(r) {
      let s = "";
      return o();
      function o() {
        return A.read().then(({ value: n, done: i }) => {
          if (i) {
            if (s.trim()) {
              r.error(new Jr("Failed to parse stream"));
              return;
            }
            r.close();
            return;
          }
          s += n;
          let a = s.match(Gg), g;
          for (; a; ) {
            try {
              g = JSON.parse(a[1]);
            } catch {
              r.error(new Jr(`Error parsing JSON response: "${a[1]}"`));
              return;
            }
            r.enqueue(g), s = s.substring(a[0].length), a = s.match(Gg);
          }
          return o();
        });
      }
    }
  });
}
function Jw(e) {
  const A = e[e.length - 1], t = {
    promptFeedback: A?.promptFeedback
  };
  for (const r of e)
    if (r.candidates)
      for (const s of r.candidates) {
        const o = s.index;
        if (t.candidates || (t.candidates = []), t.candidates[o] || (t.candidates[o] = {
          index: s.index
        }), t.candidates[o].citationMetadata = s.citationMetadata, t.candidates[o].finishReason = s.finishReason, t.candidates[o].finishMessage = s.finishMessage, t.candidates[o].safetyRatings = s.safetyRatings, s.content && s.content.parts) {
          t.candidates[o].content || (t.candidates[o].content = {
            role: s.content.role || "user",
            parts: [{ text: "" }]
          });
          for (const n of s.content.parts)
            n.text && (t.candidates[o].content.parts[0].text += n.text);
        }
      }
  return t;
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
async function Gu(e, A, t) {
  const r = new As(
    A,
    St.STREAM_GENERATE_CONTENT,
    e,
    /* stream */
    !0
  ), s = await ts(r, JSON.stringify(t));
  return Ow(s);
}
async function _u(e, A, t) {
  const r = new As(
    A,
    St.GENERATE_CONTENT,
    e,
    /* stream */
    !1
  ), o = await (await ts(r, JSON.stringify(t))).json();
  return {
    response: Oi(o)
  };
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
function Mr(e, A) {
  let t = [];
  if (typeof e == "string")
    t = [{ text: e }];
  else
    for (const r of e)
      typeof r == "string" ? t.push({ text: r }) : t.push(r);
  return { role: A, parts: t };
}
function xn(e) {
  return e.contents ? e : { contents: [Mr(e, "user")] };
}
function Hw(e) {
  return typeof e == "string" || Array.isArray(e) ? { content: Mr(e, "user") } : e;
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const _g = "SILENT_ERROR";
class Vw {
  constructor(A, t, r) {
    this.model = t, this.params = r, this._history = [], this._sendPromise = Promise.resolve(), this._apiKey = A, r?.history && (this._history = r.history.map((s) => {
      if (!s.role)
        throw new Error("Missing role for history item: " + JSON.stringify(s));
      return Mr(s.parts, s.role);
    }));
  }
  /**
   * Gets the chat history so far. Blocked prompts are not added to history.
   * Blocked candidates are not added to history, nor are the prompts that
   * generated them.
   */
  async getHistory() {
    return await this._sendPromise, this._history;
  }
  /**
   * Sends a chat message and receives a non-streaming
   * {@link GenerateContentResult}
   */
  async sendMessage(A) {
    var t, r;
    await this._sendPromise;
    const s = Mr(A, "user"), o = {
      safetySettings: (t = this.params) === null || t === void 0 ? void 0 : t.safetySettings,
      generationConfig: (r = this.params) === null || r === void 0 ? void 0 : r.generationConfig,
      contents: [...this._history, s]
    };
    let n;
    return this._sendPromise = this._sendPromise.then(() => _u(this._apiKey, this.model, o)).then((i) => {
      var a;
      if (i.response.candidates && i.response.candidates.length > 0) {
        this._history.push(s);
        const g = Object.assign({
          parts: [],
          // Response seems to come back without a role set.
          role: "model"
        }, (a = i.response.candidates) === null || a === void 0 ? void 0 : a[0].content);
        this._history.push(g);
      } else {
        const g = Ys(i.response);
        g && console.warn(`sendMessage() was unsuccessful. ${g}. Inspect response object for details.`);
      }
      n = i;
    }), await this._sendPromise, n;
  }
  /**
   * Sends a chat message and receives the response as a
   * {@link GenerateContentStreamResult} containing an iterable stream
   * and a response promise.
   */
  async sendMessageStream(A) {
    var t, r;
    await this._sendPromise;
    const s = Mr(A, "user"), o = {
      safetySettings: (t = this.params) === null || t === void 0 ? void 0 : t.safetySettings,
      generationConfig: (r = this.params) === null || r === void 0 ? void 0 : r.generationConfig,
      contents: [...this._history, s]
    }, n = Gu(this._apiKey, this.model, o);
    return this._sendPromise = this._sendPromise.then(() => n).catch((i) => {
      throw new Error(_g);
    }).then((i) => i.response).then((i) => {
      if (i.candidates && i.candidates.length > 0) {
        this._history.push(s);
        const a = Object.assign({}, i.candidates[0].content);
        a.role || (a.role = "model"), this._history.push(a);
      } else {
        const a = Ys(i);
        a && console.warn(`sendMessageStream() was unsuccessful. ${a}. Inspect response object for details.`);
      }
    }).catch((i) => {
      i.message !== _g && console.error(i);
    }), n;
  }
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
async function qw(e, A, t) {
  const r = new As(A, St.COUNT_TOKENS, e, !1);
  return (await ts(r, JSON.stringify(Object.assign(Object.assign({}, t), { model: A })))).json();
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
async function Ww(e, A, t) {
  const r = new As(A, St.EMBED_CONTENT, e, !1);
  return (await ts(r, JSON.stringify(t))).json();
}
async function jw(e, A, t) {
  const r = new As(A, St.BATCH_EMBED_CONTENTS, e, !1), s = t.requests.map((n) => Object.assign(Object.assign({}, n), { model: `models/${A}` }));
  return (await ts(r, JSON.stringify({ requests: s }))).json();
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
class $w {
  constructor(A, t) {
    var r;
    this.apiKey = A, t.model.startsWith("models/") ? this.model = (r = t.model.split("models/")) === null || r === void 0 ? void 0 : r[1] : this.model = t.model, this.generationConfig = t.generationConfig || {}, this.safetySettings = t.safetySettings || [];
  }
  /**
   * Makes a single non-streaming call to the model
   * and returns an object containing a single {@link GenerateContentResponse}.
   */
  async generateContent(A) {
    const t = xn(A);
    return _u(this.apiKey, this.model, Object.assign({ generationConfig: this.generationConfig, safetySettings: this.safetySettings }, t));
  }
  /**
   * Makes a single streaming call to the model
   * and returns an object containing an iterable stream that iterates
   * over all chunks in the streaming response as well as
   * a promise that returns the final aggregated response.
   */
  async generateContentStream(A) {
    const t = xn(A);
    return Gu(this.apiKey, this.model, Object.assign({ generationConfig: this.generationConfig, safetySettings: this.safetySettings }, t));
  }
  /**
   * Gets a new {@link ChatSession} instance which can be used for
   * multi-turn chats.
   */
  startChat(A) {
    return new Vw(this.apiKey, this.model, A);
  }
  /**
   * Counts the tokens in the provided request.
   */
  async countTokens(A) {
    const t = xn(A);
    return qw(this.apiKey, this.model, t);
  }
  /**
   * Embeds the provided content.
   */
  async embedContent(A) {
    const t = Hw(A);
    return Ww(this.apiKey, this.model, t);
  }
  /**
   * Embeds an array of {@link EmbedContentRequest}s.
   */
  async batchEmbedContents(A) {
    return jw(this.apiKey, this.model, A);
  }
}
/**
 * @license
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
class Kw {
  constructor(A) {
    this.apiKey = A;
  }
  /**
   * Gets a {@link GenerativeModel} instance for the provided model name.
   */
  getGenerativeModel(A) {
    if (!A.model)
      throw new Jr("Must provide a model name. Example: genai.getGenerativeModel({ model: 'my-model-name' })");
    return new $w(this.apiKey, A);
  }
}
async function zw(e, A, t) {
  const s = new Kw(e).getGenerativeModel({
    model: "gemini-1.5-flash",
    systemInstruction: `Analyze code changes against this standard: ${A.shortname} - ${A.description}.
      Use these examples to guide your analysis:
      Good Example:
      \`\`\`${A.positiveExample}\`\`\`
      
      Bad Example:
      \`\`\`${A.negativeExample}\`\`\`
      
      Respond in format: "${A.shortname}: [PASSED/FAILED]
Lines [X-Y]: [Explanation]"`
  });
  try {
    const n = await (await s.generateContent([
      `Code diff:
${t}

Assessment:`
    ])).response.text();
    return Zw(n);
  } catch (o) {
    throw new Error(`Gemini API error: ${o.message}`);
  }
}
function Zw(e) {
  const A = e.split(`
`), t = {
    standardName: "",
    foundIssues: !1,
    details: []
  };
  return A.forEach((r) => {
    const s = r.match(/(.*?):\s*(PASSED|FAILED)/);
    s ? (t.standardName = s[1], t.foundIssues = s[2] === "FAILED") : r.startsWith("Lines") && t.details.push(r);
  }), {
    foundIssues: t.foundIssues,
    details: t.details.join(`
`)
  };
}
var Jn = {}, rr = {}, gt = {};
Object.defineProperty(gt, "__esModule", { value: !0 });
gt.toCommandProperties = gt.toCommandValue = void 0;
function Xw(e) {
  return e == null ? "" : typeof e == "string" || e instanceof String ? e : JSON.stringify(e);
}
gt.toCommandValue = Xw;
function ey(e) {
  return Object.keys(e).length ? {
    title: e.title,
    file: e.file,
    line: e.startLine,
    endLine: e.endLine,
    col: e.startColumn,
    endColumn: e.endColumn
  } : {};
}
gt.toCommandProperties = ey;
var Ay = O && O.__createBinding || (Object.create ? function(e, A, t, r) {
  r === void 0 && (r = t);
  var s = Object.getOwnPropertyDescriptor(A, t);
  (!s || ("get" in s ? !A.__esModule : s.writable || s.configurable)) && (s = { enumerable: !0, get: function() {
    return A[t];
  } }), Object.defineProperty(e, r, s);
} : function(e, A, t, r) {
  r === void 0 && (r = t), e[r] = A[t];
}), ty = O && O.__setModuleDefault || (Object.create ? function(e, A) {
  Object.defineProperty(e, "default", { enumerable: !0, value: A });
} : function(e, A) {
  e.default = A;
}), ry = O && O.__importStar || function(e) {
  if (e && e.__esModule) return e;
  var A = {};
  if (e != null) for (var t in e) t !== "default" && Object.prototype.hasOwnProperty.call(e, t) && Ay(A, e, t);
  return ty(A, e), A;
};
Object.defineProperty(rr, "__esModule", { value: !0 });
rr.issue = rr.issueCommand = void 0;
const sy = ry(Ut), Nu = gt;
function vu(e, A, t) {
  const r = new ny(e, A, t);
  process.stdout.write(r.toString() + sy.EOL);
}
rr.issueCommand = vu;
function oy(e, A = "") {
  vu(e, {}, A);
}
rr.issue = oy;
const Ng = "::";
class ny {
  constructor(A, t, r) {
    A || (A = "missing.command"), this.command = A, this.properties = t, this.message = r;
  }
  toString() {
    let A = Ng + this.command;
    if (this.properties && Object.keys(this.properties).length > 0) {
      A += " ";
      let t = !0;
      for (const r in this.properties)
        if (this.properties.hasOwnProperty(r)) {
          const s = this.properties[r];
          s && (t ? t = !1 : A += ",", A += `${r}=${ay(s)}`);
        }
    }
    return A += `${Ng}${iy(this.message)}`, A;
  }
}
function iy(e) {
  return (0, Nu.toCommandValue)(e).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function ay(e) {
  return (0, Nu.toCommandValue)(e).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}
var sr = {}, cy = O && O.__createBinding || (Object.create ? function(e, A, t, r) {
  r === void 0 && (r = t);
  var s = Object.getOwnPropertyDescriptor(A, t);
  (!s || ("get" in s ? !A.__esModule : s.writable || s.configurable)) && (s = { enumerable: !0, get: function() {
    return A[t];
  } }), Object.defineProperty(e, r, s);
} : function(e, A, t, r) {
  r === void 0 && (r = t), e[r] = A[t];
}), gy = O && O.__setModuleDefault || (Object.create ? function(e, A) {
  Object.defineProperty(e, "default", { enumerable: !0, value: A });
} : function(e, A) {
  e.default = A;
}), Pi = O && O.__importStar || function(e) {
  if (e && e.__esModule) return e;
  var A = {};
  if (e != null) for (var t in e) t !== "default" && Object.prototype.hasOwnProperty.call(e, t) && cy(A, e, t);
  return gy(A, e), A;
};
Object.defineProperty(sr, "__esModule", { value: !0 });
sr.prepareKeyValueMessage = sr.issueFileCommand = void 0;
const ly = Pi(Wu), vg = Pi(xs), li = Pi(Ut), Lu = gt;
function Ey(e, A) {
  const t = process.env[`GITHUB_${e}`];
  if (!t)
    throw new Error(`Unable to find environment variable for file command ${e}`);
  if (!vg.existsSync(t))
    throw new Error(`Missing file at path: ${t}`);
  vg.appendFileSync(t, `${(0, Lu.toCommandValue)(A)}${li.EOL}`, {
    encoding: "utf8"
  });
}
sr.issueFileCommand = Ey;
function uy(e, A) {
  const t = `ghadelimiter_${ly.randomUUID()}`, r = (0, Lu.toCommandValue)(A);
  if (e.includes(t))
    throw new Error(`Unexpected input: name should not contain the delimiter "${t}"`);
  if (r.includes(t))
    throw new Error(`Unexpected input: value should not contain the delimiter "${t}"`);
  return `${e}<<${t}${li.EOL}${r}${li.EOL}${t}`;
}
sr.prepareKeyValueMessage = uy;
var kr = {}, at = {}, Yi = O && O.__awaiter || function(e, A, t, r) {
  function s(o) {
    return o instanceof t ? o : new t(function(n) {
      n(o);
    });
  }
  return new (t || (t = Promise))(function(o, n) {
    function i(c) {
      try {
        g(r.next(c));
      } catch (E) {
        n(E);
      }
    }
    function a(c) {
      try {
        g(r.throw(c));
      } catch (E) {
        n(E);
      }
    }
    function g(c) {
      c.done ? o(c.value) : s(c.value).then(i, a);
    }
    g((r = r.apply(e, A || [])).next());
  });
};
Object.defineProperty(at, "__esModule", { value: !0 });
at.PersonalAccessTokenCredentialHandler = at.BearerCredentialHandler = at.BasicCredentialHandler = void 0;
class hy {
  constructor(A, t) {
    this.username = A, this.password = t;
  }
  prepareRequest(A) {
    if (!A.headers)
      throw Error("The request has no headers");
    A.headers.Authorization = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
  }
  // This handler cannot handle 401
  canHandleAuthentication() {
    return !1;
  }
  handleAuthentication() {
    return Yi(this, void 0, void 0, function* () {
      throw new Error("not implemented");
    });
  }
}
at.BasicCredentialHandler = hy;
class dy {
  constructor(A) {
    this.token = A;
  }
  // currently implements pre-authorization
  // TODO: support preAuth = false where it hooks on 401
  prepareRequest(A) {
    if (!A.headers)
      throw Error("The request has no headers");
    A.headers.Authorization = `Bearer ${this.token}`;
  }
  // This handler cannot handle 401
  canHandleAuthentication() {
    return !1;
  }
  handleAuthentication() {
    return Yi(this, void 0, void 0, function* () {
      throw new Error("not implemented");
    });
  }
}
at.BearerCredentialHandler = dy;
class Qy {
  constructor(A) {
    this.token = A;
  }
  // currently implements pre-authorization
  // TODO: support preAuth = false where it hooks on 401
  prepareRequest(A) {
    if (!A.headers)
      throw Error("The request has no headers");
    A.headers.Authorization = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
  }
  // This handler cannot handle 401
  canHandleAuthentication() {
    return !1;
  }
  handleAuthentication() {
    return Yi(this, void 0, void 0, function* () {
      throw new Error("not implemented");
    });
  }
}
at.PersonalAccessTokenCredentialHandler = Qy;
var Lg;
function Cy() {
  if (Lg) return kr;
  Lg = 1;
  var e = O && O.__awaiter || function(o, n, i, a) {
    function g(c) {
      return c instanceof i ? c : new i(function(E) {
        E(c);
      });
    }
    return new (i || (i = Promise))(function(c, E) {
      function l(d) {
        try {
          I(a.next(d));
        } catch (h) {
          E(h);
        }
      }
      function Q(d) {
        try {
          I(a.throw(d));
        } catch (h) {
          E(h);
        }
      }
      function I(d) {
        d.done ? c(d.value) : g(d.value).then(l, Q);
      }
      I((a = a.apply(o, n || [])).next());
    });
  };
  Object.defineProperty(kr, "__esModule", { value: !0 }), kr.OidcClient = void 0;
  const A = We, t = at, r = Ou();
  class s {
    static createHttpClient(n = !0, i = 10) {
      const a = {
        allowRetries: n,
        maxRetries: i
      };
      return new A.HttpClient("actions/oidc-client", [new t.BearerCredentialHandler(s.getRequestToken())], a);
    }
    static getRequestToken() {
      const n = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
      if (!n)
        throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
      return n;
    }
    static getIDTokenUrl() {
      const n = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
      if (!n)
        throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
      return n;
    }
    static getCall(n) {
      var i;
      return e(this, void 0, void 0, function* () {
        const c = (i = (yield s.createHttpClient().getJson(n).catch((E) => {
          throw new Error(`Failed to get ID Token. 
 
        Error Code : ${E.statusCode}
 
        Error Message: ${E.message}`);
        })).result) === null || i === void 0 ? void 0 : i.value;
        if (!c)
          throw new Error("Response json body do not have ID Token field");
        return c;
      });
    }
    static getIDToken(n) {
      return e(this, void 0, void 0, function* () {
        try {
          let i = s.getIDTokenUrl();
          if (n) {
            const g = encodeURIComponent(n);
            i = `${i}&audience=${g}`;
          }
          (0, r.debug)(`ID token url is ${i}`);
          const a = yield s.getCall(i);
          return (0, r.setSecret)(a), a;
        } catch (i) {
          throw new Error(`Error message: ${i.message}`);
        }
      });
    }
  }
  return kr.OidcClient = s, kr;
}
var Hn = {}, Mg;
function Og() {
  return Mg || (Mg = 1, function(e) {
    var A = O && O.__awaiter || function(g, c, E, l) {
      function Q(I) {
        return I instanceof E ? I : new E(function(d) {
          d(I);
        });
      }
      return new (E || (E = Promise))(function(I, d) {
        function h(B) {
          try {
            u(l.next(B));
          } catch (m) {
            d(m);
          }
        }
        function C(B) {
          try {
            u(l.throw(B));
          } catch (m) {
            d(m);
          }
        }
        function u(B) {
          B.done ? I(B.value) : Q(B.value).then(h, C);
        }
        u((l = l.apply(g, c || [])).next());
      });
    };
    Object.defineProperty(e, "__esModule", { value: !0 }), e.summary = e.markdownSummary = e.SUMMARY_DOCS_URL = e.SUMMARY_ENV_VAR = void 0;
    const t = Ut, r = xs, { access: s, appendFile: o, writeFile: n } = r.promises;
    e.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY", e.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    class i {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return A(this, void 0, void 0, function* () {
          if (this._filePath)
            return this._filePath;
          const c = process.env[e.SUMMARY_ENV_VAR];
          if (!c)
            throw new Error(`Unable to find environment variable for $${e.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          try {
            yield s(c, r.constants.R_OK | r.constants.W_OK);
          } catch {
            throw new Error(`Unable to access summary file: '${c}'. Check if the file has correct read/write permissions.`);
          }
          return this._filePath = c, this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(c, E, l = {}) {
        const Q = Object.entries(l).map(([I, d]) => ` ${I}="${d}"`).join("");
        return E ? `<${c}${Q}>${E}</${c}>` : `<${c}${Q}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(c) {
        return A(this, void 0, void 0, function* () {
          const E = !!c?.overwrite, l = yield this.filePath();
          return yield (E ? n : o)(l, this._buffer, { encoding: "utf8" }), this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return A(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: !0 });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        return this._buffer = "", this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(c, E = !1) {
        return this._buffer += c, E ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(t.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(c, E) {
        const l = Object.assign({}, E && { lang: E }), Q = this.wrap("pre", this.wrap("code", c), l);
        return this.addRaw(Q).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(c, E = !1) {
        const l = E ? "ol" : "ul", Q = c.map((d) => this.wrap("li", d)).join(""), I = this.wrap(l, Q);
        return this.addRaw(I).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(c) {
        const E = c.map((Q) => {
          const I = Q.map((d) => {
            if (typeof d == "string")
              return this.wrap("td", d);
            const { header: h, data: C, colspan: u, rowspan: B } = d, m = h ? "th" : "td", f = Object.assign(Object.assign({}, u && { colspan: u }), B && { rowspan: B });
            return this.wrap(m, C, f);
          }).join("");
          return this.wrap("tr", I);
        }).join(""), l = this.wrap("table", E);
        return this.addRaw(l).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(c, E) {
        const l = this.wrap("details", this.wrap("summary", c) + E);
        return this.addRaw(l).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(c, E, l) {
        const { width: Q, height: I } = l || {}, d = Object.assign(Object.assign({}, Q && { width: Q }), I && { height: I }), h = this.wrap("img", null, Object.assign({ src: c, alt: E }, d));
        return this.addRaw(h).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(c, E) {
        const l = `h${E}`, Q = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(l) ? l : "h1", I = this.wrap(Q, c);
        return this.addRaw(I).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const c = this.wrap("hr", null);
        return this.addRaw(c).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const c = this.wrap("br", null);
        return this.addRaw(c).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(c, E) {
        const l = Object.assign({}, E && { cite: E }), Q = this.wrap("blockquote", c, l);
        return this.addRaw(Q).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(c, E) {
        const l = this.wrap("a", c, { href: E });
        return this.addRaw(l).addEOL();
      }
    }
    const a = new i();
    e.markdownSummary = a, e.summary = a;
  }(Hn)), Hn;
}
var YA = {}, Pg;
function By() {
  if (Pg) return YA;
  Pg = 1;
  var e = O && O.__createBinding || (Object.create ? function(i, a, g, c) {
    c === void 0 && (c = g);
    var E = Object.getOwnPropertyDescriptor(a, g);
    (!E || ("get" in E ? !a.__esModule : E.writable || E.configurable)) && (E = { enumerable: !0, get: function() {
      return a[g];
    } }), Object.defineProperty(i, c, E);
  } : function(i, a, g, c) {
    c === void 0 && (c = g), i[c] = a[g];
  }), A = O && O.__setModuleDefault || (Object.create ? function(i, a) {
    Object.defineProperty(i, "default", { enumerable: !0, value: a });
  } : function(i, a) {
    i.default = a;
  }), t = O && O.__importStar || function(i) {
    if (i && i.__esModule) return i;
    var a = {};
    if (i != null) for (var g in i) g !== "default" && Object.prototype.hasOwnProperty.call(i, g) && e(a, i, g);
    return A(a, i), a;
  };
  Object.defineProperty(YA, "__esModule", { value: !0 }), YA.toPlatformPath = YA.toWin32Path = YA.toPosixPath = void 0;
  const r = t(qr);
  function s(i) {
    return i.replace(/[\\]/g, "/");
  }
  YA.toPosixPath = s;
  function o(i) {
    return i.replace(/[/]/g, "\\");
  }
  YA.toWin32Path = o;
  function n(i) {
    return i.replace(/[/\\]/g, r.sep);
  }
  return YA.toPlatformPath = n, YA;
}
var Vn = {}, mt = {}, wt = {}, iA = {}, qn = {}, Yg;
function Mu() {
  return Yg || (Yg = 1, function(e) {
    var A = O && O.__createBinding || (Object.create ? function(d, h, C, u) {
      u === void 0 && (u = C), Object.defineProperty(d, u, { enumerable: !0, get: function() {
        return h[C];
      } });
    } : function(d, h, C, u) {
      u === void 0 && (u = C), d[u] = h[C];
    }), t = O && O.__setModuleDefault || (Object.create ? function(d, h) {
      Object.defineProperty(d, "default", { enumerable: !0, value: h });
    } : function(d, h) {
      d.default = h;
    }), r = O && O.__importStar || function(d) {
      if (d && d.__esModule) return d;
      var h = {};
      if (d != null) for (var C in d) C !== "default" && Object.hasOwnProperty.call(d, C) && A(h, d, C);
      return t(h, d), h;
    }, s = O && O.__awaiter || function(d, h, C, u) {
      function B(m) {
        return m instanceof C ? m : new C(function(f) {
          f(m);
        });
      }
      return new (C || (C = Promise))(function(m, f) {
        function y(S) {
          try {
            w(u.next(S));
          } catch (v) {
            f(v);
          }
        }
        function b(S) {
          try {
            w(u.throw(S));
          } catch (v) {
            f(v);
          }
        }
        function w(S) {
          S.done ? m(S.value) : B(S.value).then(y, b);
        }
        w((u = u.apply(d, h || [])).next());
      });
    }, o;
    Object.defineProperty(e, "__esModule", { value: !0 }), e.getCmdPath = e.tryGetExecutablePath = e.isRooted = e.isDirectory = e.exists = e.READONLY = e.UV_FS_O_EXLOCK = e.IS_WINDOWS = e.unlink = e.symlink = e.stat = e.rmdir = e.rm = e.rename = e.readlink = e.readdir = e.open = e.mkdir = e.lstat = e.copyFile = e.chmod = void 0;
    const n = r(xs), i = r(qr);
    o = n.promises, e.chmod = o.chmod, e.copyFile = o.copyFile, e.lstat = o.lstat, e.mkdir = o.mkdir, e.open = o.open, e.readdir = o.readdir, e.readlink = o.readlink, e.rename = o.rename, e.rm = o.rm, e.rmdir = o.rmdir, e.stat = o.stat, e.symlink = o.symlink, e.unlink = o.unlink, e.IS_WINDOWS = process.platform === "win32", e.UV_FS_O_EXLOCK = 268435456, e.READONLY = n.constants.O_RDONLY;
    function a(d) {
      return s(this, void 0, void 0, function* () {
        try {
          yield e.stat(d);
        } catch (h) {
          if (h.code === "ENOENT")
            return !1;
          throw h;
        }
        return !0;
      });
    }
    e.exists = a;
    function g(d, h = !1) {
      return s(this, void 0, void 0, function* () {
        return (h ? yield e.stat(d) : yield e.lstat(d)).isDirectory();
      });
    }
    e.isDirectory = g;
    function c(d) {
      if (d = l(d), !d)
        throw new Error('isRooted() parameter "p" cannot be empty');
      return e.IS_WINDOWS ? d.startsWith("\\") || /^[A-Z]:/i.test(d) : d.startsWith("/");
    }
    e.isRooted = c;
    function E(d, h) {
      return s(this, void 0, void 0, function* () {
        let C;
        try {
          C = yield e.stat(d);
        } catch (B) {
          B.code !== "ENOENT" && console.log(`Unexpected error attempting to determine if executable file exists '${d}': ${B}`);
        }
        if (C && C.isFile()) {
          if (e.IS_WINDOWS) {
            const B = i.extname(d).toUpperCase();
            if (h.some((m) => m.toUpperCase() === B))
              return d;
          } else if (Q(C))
            return d;
        }
        const u = d;
        for (const B of h) {
          d = u + B, C = void 0;
          try {
            C = yield e.stat(d);
          } catch (m) {
            m.code !== "ENOENT" && console.log(`Unexpected error attempting to determine if executable file exists '${d}': ${m}`);
          }
          if (C && C.isFile()) {
            if (e.IS_WINDOWS) {
              try {
                const m = i.dirname(d), f = i.basename(d).toUpperCase();
                for (const y of yield e.readdir(m))
                  if (f === y.toUpperCase()) {
                    d = i.join(m, y);
                    break;
                  }
              } catch (m) {
                console.log(`Unexpected error attempting to determine the actual case of the file '${d}': ${m}`);
              }
              return d;
            } else if (Q(C))
              return d;
          }
        }
        return "";
      });
    }
    e.tryGetExecutablePath = E;
    function l(d) {
      return d = d || "", e.IS_WINDOWS ? (d = d.replace(/\//g, "\\"), d.replace(/\\\\+/g, "\\")) : d.replace(/\/\/+/g, "/");
    }
    function Q(d) {
      return (d.mode & 1) > 0 || (d.mode & 8) > 0 && d.gid === process.getgid() || (d.mode & 64) > 0 && d.uid === process.getuid();
    }
    function I() {
      var d;
      return (d = process.env.COMSPEC) !== null && d !== void 0 ? d : "cmd.exe";
    }
    e.getCmdPath = I;
  }(qn)), qn;
}
var xg;
function Iy() {
  if (xg) return iA;
  xg = 1;
  var e = O && O.__createBinding || (Object.create ? function(h, C, u, B) {
    B === void 0 && (B = u), Object.defineProperty(h, B, { enumerable: !0, get: function() {
      return C[u];
    } });
  } : function(h, C, u, B) {
    B === void 0 && (B = u), h[B] = C[u];
  }), A = O && O.__setModuleDefault || (Object.create ? function(h, C) {
    Object.defineProperty(h, "default", { enumerable: !0, value: C });
  } : function(h, C) {
    h.default = C;
  }), t = O && O.__importStar || function(h) {
    if (h && h.__esModule) return h;
    var C = {};
    if (h != null) for (var u in h) u !== "default" && Object.hasOwnProperty.call(h, u) && e(C, h, u);
    return A(C, h), C;
  }, r = O && O.__awaiter || function(h, C, u, B) {
    function m(f) {
      return f instanceof u ? f : new u(function(y) {
        y(f);
      });
    }
    return new (u || (u = Promise))(function(f, y) {
      function b(v) {
        try {
          S(B.next(v));
        } catch (N) {
          y(N);
        }
      }
      function w(v) {
        try {
          S(B.throw(v));
        } catch (N) {
          y(N);
        }
      }
      function S(v) {
        v.done ? f(v.value) : m(v.value).then(b, w);
      }
      S((B = B.apply(h, C || [])).next());
    });
  };
  Object.defineProperty(iA, "__esModule", { value: !0 }), iA.findInPath = iA.which = iA.mkdirP = iA.rmRF = iA.mv = iA.cp = void 0;
  const s = Me, o = t(qr), n = t(Mu());
  function i(h, C, u = {}) {
    return r(this, void 0, void 0, function* () {
      const { force: B, recursive: m, copySourceDirectory: f } = Q(u), y = (yield n.exists(C)) ? yield n.stat(C) : null;
      if (y && y.isFile() && !B)
        return;
      const b = y && y.isDirectory() && f ? o.join(C, o.basename(h)) : C;
      if (!(yield n.exists(h)))
        throw new Error(`no such file or directory: ${h}`);
      if ((yield n.stat(h)).isDirectory())
        if (m)
          yield I(h, b, 0, B);
        else
          throw new Error(`Failed to copy. ${h} is a directory, but tried to copy without recursive flag.`);
      else {
        if (o.relative(h, b) === "")
          throw new Error(`'${b}' and '${h}' are the same file`);
        yield d(h, b, B);
      }
    });
  }
  iA.cp = i;
  function a(h, C, u = {}) {
    return r(this, void 0, void 0, function* () {
      if (yield n.exists(C)) {
        let B = !0;
        if ((yield n.isDirectory(C)) && (C = o.join(C, o.basename(h)), B = yield n.exists(C)), B)
          if (u.force == null || u.force)
            yield g(C);
          else
            throw new Error("Destination already exists");
      }
      yield c(o.dirname(C)), yield n.rename(h, C);
    });
  }
  iA.mv = a;
  function g(h) {
    return r(this, void 0, void 0, function* () {
      if (n.IS_WINDOWS && /[*"<>|]/.test(h))
        throw new Error('File path must not contain `*`, `"`, `<`, `>` or `|` on Windows');
      try {
        yield n.rm(h, {
          force: !0,
          maxRetries: 3,
          recursive: !0,
          retryDelay: 300
        });
      } catch (C) {
        throw new Error(`File was unable to be removed ${C}`);
      }
    });
  }
  iA.rmRF = g;
  function c(h) {
    return r(this, void 0, void 0, function* () {
      s.ok(h, "a path argument must be provided"), yield n.mkdir(h, { recursive: !0 });
    });
  }
  iA.mkdirP = c;
  function E(h, C) {
    return r(this, void 0, void 0, function* () {
      if (!h)
        throw new Error("parameter 'tool' is required");
      if (C) {
        const B = yield E(h, !1);
        if (!B)
          throw n.IS_WINDOWS ? new Error(`Unable to locate executable file: ${h}. Please verify either the file path exists or the file can be found within a directory specified by the PATH environment variable. Also verify the file has a valid extension for an executable file.`) : new Error(`Unable to locate executable file: ${h}. Please verify either the file path exists or the file can be found within a directory specified by the PATH environment variable. Also check the file mode to verify the file is executable.`);
        return B;
      }
      const u = yield l(h);
      return u && u.length > 0 ? u[0] : "";
    });
  }
  iA.which = E;
  function l(h) {
    return r(this, void 0, void 0, function* () {
      if (!h)
        throw new Error("parameter 'tool' is required");
      const C = [];
      if (n.IS_WINDOWS && process.env.PATHEXT)
        for (const m of process.env.PATHEXT.split(o.delimiter))
          m && C.push(m);
      if (n.isRooted(h)) {
        const m = yield n.tryGetExecutablePath(h, C);
        return m ? [m] : [];
      }
      if (h.includes(o.sep))
        return [];
      const u = [];
      if (process.env.PATH)
        for (const m of process.env.PATH.split(o.delimiter))
          m && u.push(m);
      const B = [];
      for (const m of u) {
        const f = yield n.tryGetExecutablePath(o.join(m, h), C);
        f && B.push(f);
      }
      return B;
    });
  }
  iA.findInPath = l;
  function Q(h) {
    const C = h.force == null ? !0 : h.force, u = !!h.recursive, B = h.copySourceDirectory == null ? !0 : !!h.copySourceDirectory;
    return { force: C, recursive: u, copySourceDirectory: B };
  }
  function I(h, C, u, B) {
    return r(this, void 0, void 0, function* () {
      if (u >= 255)
        return;
      u++, yield c(C);
      const m = yield n.readdir(h);
      for (const f of m) {
        const y = `${h}/${f}`, b = `${C}/${f}`;
        (yield n.lstat(y)).isDirectory() ? yield I(y, b, u, B) : yield d(y, b, B);
      }
      yield n.chmod(C, (yield n.stat(h)).mode);
    });
  }
  function d(h, C, u) {
    return r(this, void 0, void 0, function* () {
      if ((yield n.lstat(h)).isSymbolicLink()) {
        try {
          yield n.lstat(C), yield n.unlink(C);
        } catch (m) {
          m.code === "EPERM" && (yield n.chmod(C, "0666"), yield n.unlink(C));
        }
        const B = yield n.readlink(h);
        yield n.symlink(B, C, n.IS_WINDOWS ? "junction" : null);
      } else (!(yield n.exists(C)) || u) && (yield n.copyFile(h, C));
    });
  }
  return iA;
}
var Jg;
function py() {
  if (Jg) return wt;
  Jg = 1;
  var e = O && O.__createBinding || (Object.create ? function(d, h, C, u) {
    u === void 0 && (u = C), Object.defineProperty(d, u, { enumerable: !0, get: function() {
      return h[C];
    } });
  } : function(d, h, C, u) {
    u === void 0 && (u = C), d[u] = h[C];
  }), A = O && O.__setModuleDefault || (Object.create ? function(d, h) {
    Object.defineProperty(d, "default", { enumerable: !0, value: h });
  } : function(d, h) {
    d.default = h;
  }), t = O && O.__importStar || function(d) {
    if (d && d.__esModule) return d;
    var h = {};
    if (d != null) for (var C in d) C !== "default" && Object.hasOwnProperty.call(d, C) && e(h, d, C);
    return A(h, d), h;
  }, r = O && O.__awaiter || function(d, h, C, u) {
    function B(m) {
      return m instanceof C ? m : new C(function(f) {
        f(m);
      });
    }
    return new (C || (C = Promise))(function(m, f) {
      function y(S) {
        try {
          w(u.next(S));
        } catch (v) {
          f(v);
        }
      }
      function b(S) {
        try {
          w(u.throw(S));
        } catch (v) {
          f(v);
        }
      }
      function w(S) {
        S.done ? m(S.value) : B(S.value).then(y, b);
      }
      w((u = u.apply(d, h || [])).next());
    });
  };
  Object.defineProperty(wt, "__esModule", { value: !0 }), wt.argStringToArray = wt.ToolRunner = void 0;
  const s = t(Ut), o = t(nr), n = t(ju), i = t(qr), a = t(Iy()), g = t(Mu()), c = $u, E = process.platform === "win32";
  class l extends o.EventEmitter {
    constructor(h, C, u) {
      if (super(), !h)
        throw new Error("Parameter 'toolPath' cannot be null or empty.");
      this.toolPath = h, this.args = C || [], this.options = u || {};
    }
    _debug(h) {
      this.options.listeners && this.options.listeners.debug && this.options.listeners.debug(h);
    }
    _getCommandString(h, C) {
      const u = this._getSpawnFileName(), B = this._getSpawnArgs(h);
      let m = C ? "" : "[command]";
      if (E)
        if (this._isCmdFile()) {
          m += u;
          for (const f of B)
            m += ` ${f}`;
        } else if (h.windowsVerbatimArguments) {
          m += `"${u}"`;
          for (const f of B)
            m += ` ${f}`;
        } else {
          m += this._windowsQuoteCmdArg(u);
          for (const f of B)
            m += ` ${this._windowsQuoteCmdArg(f)}`;
        }
      else {
        m += u;
        for (const f of B)
          m += ` ${f}`;
      }
      return m;
    }
    _processLineBuffer(h, C, u) {
      try {
        let B = C + h.toString(), m = B.indexOf(s.EOL);
        for (; m > -1; ) {
          const f = B.substring(0, m);
          u(f), B = B.substring(m + s.EOL.length), m = B.indexOf(s.EOL);
        }
        return B;
      } catch (B) {
        return this._debug(`error processing line. Failed with error ${B}`), "";
      }
    }
    _getSpawnFileName() {
      return E && this._isCmdFile() ? process.env.COMSPEC || "cmd.exe" : this.toolPath;
    }
    _getSpawnArgs(h) {
      if (E && this._isCmdFile()) {
        let C = `/D /S /C "${this._windowsQuoteCmdArg(this.toolPath)}`;
        for (const u of this.args)
          C += " ", C += h.windowsVerbatimArguments ? u : this._windowsQuoteCmdArg(u);
        return C += '"', [C];
      }
      return this.args;
    }
    _endsWith(h, C) {
      return h.endsWith(C);
    }
    _isCmdFile() {
      const h = this.toolPath.toUpperCase();
      return this._endsWith(h, ".CMD") || this._endsWith(h, ".BAT");
    }
    _windowsQuoteCmdArg(h) {
      if (!this._isCmdFile())
        return this._uvQuoteCmdArg(h);
      if (!h)
        return '""';
      const C = [
        " ",
        "	",
        "&",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "^",
        "=",
        ";",
        "!",
        "'",
        "+",
        ",",
        "`",
        "~",
        "|",
        "<",
        ">",
        '"'
      ];
      let u = !1;
      for (const f of h)
        if (C.some((y) => y === f)) {
          u = !0;
          break;
        }
      if (!u)
        return h;
      let B = '"', m = !0;
      for (let f = h.length; f > 0; f--)
        B += h[f - 1], m && h[f - 1] === "\\" ? B += "\\" : h[f - 1] === '"' ? (m = !0, B += '"') : m = !1;
      return B += '"', B.split("").reverse().join("");
    }
    _uvQuoteCmdArg(h) {
      if (!h)
        return '""';
      if (!h.includes(" ") && !h.includes("	") && !h.includes('"'))
        return h;
      if (!h.includes('"') && !h.includes("\\"))
        return `"${h}"`;
      let C = '"', u = !0;
      for (let B = h.length; B > 0; B--)
        C += h[B - 1], u && h[B - 1] === "\\" ? C += "\\" : h[B - 1] === '"' ? (u = !0, C += "\\") : u = !1;
      return C += '"', C.split("").reverse().join("");
    }
    _cloneExecOptions(h) {
      h = h || {};
      const C = {
        cwd: h.cwd || process.cwd(),
        env: h.env || process.env,
        silent: h.silent || !1,
        windowsVerbatimArguments: h.windowsVerbatimArguments || !1,
        failOnStdErr: h.failOnStdErr || !1,
        ignoreReturnCode: h.ignoreReturnCode || !1,
        delay: h.delay || 1e4
      };
      return C.outStream = h.outStream || process.stdout, C.errStream = h.errStream || process.stderr, C;
    }
    _getSpawnOptions(h, C) {
      h = h || {};
      const u = {};
      return u.cwd = h.cwd, u.env = h.env, u.windowsVerbatimArguments = h.windowsVerbatimArguments || this._isCmdFile(), h.windowsVerbatimArguments && (u.argv0 = `"${C}"`), u;
    }
    /**
     * Exec a tool.
     * Output will be streamed to the live console.
     * Returns promise with return code
     *
     * @param     tool     path to tool to exec
     * @param     options  optional exec options.  See ExecOptions
     * @returns   number
     */
    exec() {
      return r(this, void 0, void 0, function* () {
        return !g.isRooted(this.toolPath) && (this.toolPath.includes("/") || E && this.toolPath.includes("\\")) && (this.toolPath = i.resolve(process.cwd(), this.options.cwd || process.cwd(), this.toolPath)), this.toolPath = yield a.which(this.toolPath, !0), new Promise((h, C) => r(this, void 0, void 0, function* () {
          this._debug(`exec tool: ${this.toolPath}`), this._debug("arguments:");
          for (const w of this.args)
            this._debug(`   ${w}`);
          const u = this._cloneExecOptions(this.options);
          !u.silent && u.outStream && u.outStream.write(this._getCommandString(u) + s.EOL);
          const B = new I(u, this.toolPath);
          if (B.on("debug", (w) => {
            this._debug(w);
          }), this.options.cwd && !(yield g.exists(this.options.cwd)))
            return C(new Error(`The cwd: ${this.options.cwd} does not exist!`));
          const m = this._getSpawnFileName(), f = n.spawn(m, this._getSpawnArgs(u), this._getSpawnOptions(this.options, m));
          let y = "";
          f.stdout && f.stdout.on("data", (w) => {
            this.options.listeners && this.options.listeners.stdout && this.options.listeners.stdout(w), !u.silent && u.outStream && u.outStream.write(w), y = this._processLineBuffer(w, y, (S) => {
              this.options.listeners && this.options.listeners.stdline && this.options.listeners.stdline(S);
            });
          });
          let b = "";
          if (f.stderr && f.stderr.on("data", (w) => {
            B.processStderr = !0, this.options.listeners && this.options.listeners.stderr && this.options.listeners.stderr(w), !u.silent && u.errStream && u.outStream && (u.failOnStdErr ? u.errStream : u.outStream).write(w), b = this._processLineBuffer(w, b, (S) => {
              this.options.listeners && this.options.listeners.errline && this.options.listeners.errline(S);
            });
          }), f.on("error", (w) => {
            B.processError = w.message, B.processExited = !0, B.processClosed = !0, B.CheckComplete();
          }), f.on("exit", (w) => {
            B.processExitCode = w, B.processExited = !0, this._debug(`Exit code ${w} received from tool '${this.toolPath}'`), B.CheckComplete();
          }), f.on("close", (w) => {
            B.processExitCode = w, B.processExited = !0, B.processClosed = !0, this._debug(`STDIO streams have closed for tool '${this.toolPath}'`), B.CheckComplete();
          }), B.on("done", (w, S) => {
            y.length > 0 && this.emit("stdline", y), b.length > 0 && this.emit("errline", b), f.removeAllListeners(), w ? C(w) : h(S);
          }), this.options.input) {
            if (!f.stdin)
              throw new Error("child process missing stdin");
            f.stdin.end(this.options.input);
          }
        }));
      });
    }
  }
  wt.ToolRunner = l;
  function Q(d) {
    const h = [];
    let C = !1, u = !1, B = "";
    function m(f) {
      u && f !== '"' && (B += "\\"), B += f, u = !1;
    }
    for (let f = 0; f < d.length; f++) {
      const y = d.charAt(f);
      if (y === '"') {
        u ? m(y) : C = !C;
        continue;
      }
      if (y === "\\" && u) {
        m(y);
        continue;
      }
      if (y === "\\" && C) {
        u = !0;
        continue;
      }
      if (y === " " && !C) {
        B.length > 0 && (h.push(B), B = "");
        continue;
      }
      m(y);
    }
    return B.length > 0 && h.push(B.trim()), h;
  }
  wt.argStringToArray = Q;
  class I extends o.EventEmitter {
    constructor(h, C) {
      if (super(), this.processClosed = !1, this.processError = "", this.processExitCode = 0, this.processExited = !1, this.processStderr = !1, this.delay = 1e4, this.done = !1, this.timeout = null, !C)
        throw new Error("toolPath must not be empty");
      this.options = h, this.toolPath = C, h.delay && (this.delay = h.delay);
    }
    CheckComplete() {
      this.done || (this.processClosed ? this._setResult() : this.processExited && (this.timeout = c.setTimeout(I.HandleTimeout, this.delay, this)));
    }
    _debug(h) {
      this.emit("debug", h);
    }
    _setResult() {
      let h;
      this.processExited && (this.processError ? h = new Error(`There was an error when attempting to execute the process '${this.toolPath}'. This may indicate the process failed to start. Error: ${this.processError}`) : this.processExitCode !== 0 && !this.options.ignoreReturnCode ? h = new Error(`The process '${this.toolPath}' failed with exit code ${this.processExitCode}`) : this.processStderr && this.options.failOnStdErr && (h = new Error(`The process '${this.toolPath}' failed because one or more lines were written to the STDERR stream`))), this.timeout && (clearTimeout(this.timeout), this.timeout = null), this.done = !0, this.emit("done", h, this.processExitCode);
    }
    static HandleTimeout(h) {
      if (!h.done) {
        if (!h.processClosed && h.processExited) {
          const C = `The STDIO streams did not close within ${h.delay / 1e3} seconds of the exit event from process '${h.toolPath}'. This may indicate a child process inherited the STDIO streams and has not yet exited.`;
          h._debug(C);
        }
        h._setResult();
      }
    }
  }
  return wt;
}
var Hg;
function fy() {
  if (Hg) return mt;
  Hg = 1;
  var e = O && O.__createBinding || (Object.create ? function(a, g, c, E) {
    E === void 0 && (E = c), Object.defineProperty(a, E, { enumerable: !0, get: function() {
      return g[c];
    } });
  } : function(a, g, c, E) {
    E === void 0 && (E = c), a[E] = g[c];
  }), A = O && O.__setModuleDefault || (Object.create ? function(a, g) {
    Object.defineProperty(a, "default", { enumerable: !0, value: g });
  } : function(a, g) {
    a.default = g;
  }), t = O && O.__importStar || function(a) {
    if (a && a.__esModule) return a;
    var g = {};
    if (a != null) for (var c in a) c !== "default" && Object.hasOwnProperty.call(a, c) && e(g, a, c);
    return A(g, a), g;
  }, r = O && O.__awaiter || function(a, g, c, E) {
    function l(Q) {
      return Q instanceof c ? Q : new c(function(I) {
        I(Q);
      });
    }
    return new (c || (c = Promise))(function(Q, I) {
      function d(u) {
        try {
          C(E.next(u));
        } catch (B) {
          I(B);
        }
      }
      function h(u) {
        try {
          C(E.throw(u));
        } catch (B) {
          I(B);
        }
      }
      function C(u) {
        u.done ? Q(u.value) : l(u.value).then(d, h);
      }
      C((E = E.apply(a, g || [])).next());
    });
  };
  Object.defineProperty(mt, "__esModule", { value: !0 }), mt.getExecOutput = mt.exec = void 0;
  const s = Zg, o = t(py());
  function n(a, g, c) {
    return r(this, void 0, void 0, function* () {
      const E = o.argStringToArray(a);
      if (E.length === 0)
        throw new Error("Parameter 'commandLine' cannot be null or empty.");
      const l = E[0];
      return g = E.slice(1).concat(g || []), new o.ToolRunner(l, g, c).exec();
    });
  }
  mt.exec = n;
  function i(a, g, c) {
    var E, l;
    return r(this, void 0, void 0, function* () {
      let Q = "", I = "";
      const d = new s.StringDecoder("utf8"), h = new s.StringDecoder("utf8"), C = (E = c?.listeners) === null || E === void 0 ? void 0 : E.stdout, u = (l = c?.listeners) === null || l === void 0 ? void 0 : l.stderr, B = (b) => {
        I += h.write(b), u && u(b);
      }, m = (b) => {
        Q += d.write(b), C && C(b);
      }, f = Object.assign(Object.assign({}, c?.listeners), { stdout: m, stderr: B }), y = yield n(a, g, Object.assign(Object.assign({}, c), { listeners: f }));
      return Q += d.end(), I += h.end(), {
        exitCode: y,
        stdout: Q,
        stderr: I
      };
    });
  }
  return mt.getExecOutput = i, mt;
}
var Vg;
function my() {
  return Vg || (Vg = 1, function(e) {
    var A = O && O.__createBinding || (Object.create ? function(l, Q, I, d) {
      d === void 0 && (d = I);
      var h = Object.getOwnPropertyDescriptor(Q, I);
      (!h || ("get" in h ? !Q.__esModule : h.writable || h.configurable)) && (h = { enumerable: !0, get: function() {
        return Q[I];
      } }), Object.defineProperty(l, d, h);
    } : function(l, Q, I, d) {
      d === void 0 && (d = I), l[d] = Q[I];
    }), t = O && O.__setModuleDefault || (Object.create ? function(l, Q) {
      Object.defineProperty(l, "default", { enumerable: !0, value: Q });
    } : function(l, Q) {
      l.default = Q;
    }), r = O && O.__importStar || function(l) {
      if (l && l.__esModule) return l;
      var Q = {};
      if (l != null) for (var I in l) I !== "default" && Object.prototype.hasOwnProperty.call(l, I) && A(Q, l, I);
      return t(Q, l), Q;
    }, s = O && O.__awaiter || function(l, Q, I, d) {
      function h(C) {
        return C instanceof I ? C : new I(function(u) {
          u(C);
        });
      }
      return new (I || (I = Promise))(function(C, u) {
        function B(y) {
          try {
            f(d.next(y));
          } catch (b) {
            u(b);
          }
        }
        function m(y) {
          try {
            f(d.throw(y));
          } catch (b) {
            u(b);
          }
        }
        function f(y) {
          y.done ? C(y.value) : h(y.value).then(B, m);
        }
        f((d = d.apply(l, Q || [])).next());
      });
    }, o = O && O.__importDefault || function(l) {
      return l && l.__esModule ? l : { default: l };
    };
    Object.defineProperty(e, "__esModule", { value: !0 }), e.getDetails = e.isLinux = e.isMacOS = e.isWindows = e.arch = e.platform = void 0;
    const n = o(Ut), i = r(fy()), a = () => s(void 0, void 0, void 0, function* () {
      const { stdout: l } = yield i.getExecOutput('powershell -command "(Get-CimInstance -ClassName Win32_OperatingSystem).Version"', void 0, {
        silent: !0
      }), { stdout: Q } = yield i.getExecOutput('powershell -command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"', void 0, {
        silent: !0
      });
      return {
        name: Q.trim(),
        version: l.trim()
      };
    }), g = () => s(void 0, void 0, void 0, function* () {
      var l, Q, I, d;
      const { stdout: h } = yield i.getExecOutput("sw_vers", void 0, {
        silent: !0
      }), C = (Q = (l = h.match(/ProductVersion:\s*(.+)/)) === null || l === void 0 ? void 0 : l[1]) !== null && Q !== void 0 ? Q : "";
      return {
        name: (d = (I = h.match(/ProductName:\s*(.+)/)) === null || I === void 0 ? void 0 : I[1]) !== null && d !== void 0 ? d : "",
        version: C
      };
    }), c = () => s(void 0, void 0, void 0, function* () {
      const { stdout: l } = yield i.getExecOutput("lsb_release", ["-i", "-r", "-s"], {
        silent: !0
      }), [Q, I] = l.trim().split(`
`);
      return {
        name: Q,
        version: I
      };
    });
    e.platform = n.default.platform(), e.arch = n.default.arch(), e.isWindows = e.platform === "win32", e.isMacOS = e.platform === "darwin", e.isLinux = e.platform === "linux";
    function E() {
      return s(this, void 0, void 0, function* () {
        return Object.assign(Object.assign({}, yield e.isWindows ? a() : e.isMacOS ? g() : c()), {
          platform: e.platform,
          arch: e.arch,
          isWindows: e.isWindows,
          isMacOS: e.isMacOS,
          isLinux: e.isLinux
        });
      });
    }
    e.getDetails = E;
  }(Vn)), Vn;
}
var qg;
function Ou() {
  return qg || (qg = 1, function(e) {
    var A = O && O.__createBinding || (Object.create ? function(Y, Ae, ae, de) {
      de === void 0 && (de = ae);
      var R = Object.getOwnPropertyDescriptor(Ae, ae);
      (!R || ("get" in R ? !Ae.__esModule : R.writable || R.configurable)) && (R = { enumerable: !0, get: function() {
        return Ae[ae];
      } }), Object.defineProperty(Y, de, R);
    } : function(Y, Ae, ae, de) {
      de === void 0 && (de = ae), Y[de] = Ae[ae];
    }), t = O && O.__setModuleDefault || (Object.create ? function(Y, Ae) {
      Object.defineProperty(Y, "default", { enumerable: !0, value: Ae });
    } : function(Y, Ae) {
      Y.default = Ae;
    }), r = O && O.__importStar || function(Y) {
      if (Y && Y.__esModule) return Y;
      var Ae = {};
      if (Y != null) for (var ae in Y) ae !== "default" && Object.prototype.hasOwnProperty.call(Y, ae) && A(Ae, Y, ae);
      return t(Ae, Y), Ae;
    }, s = O && O.__awaiter || function(Y, Ae, ae, de) {
      function R(H) {
        return H instanceof ae ? H : new ae(function($) {
          $(H);
        });
      }
      return new (ae || (ae = Promise))(function(H, $) {
        function X(P) {
          try {
            W(de.next(P));
          } catch (le) {
            $(le);
          }
        }
        function z(P) {
          try {
            W(de.throw(P));
          } catch (le) {
            $(le);
          }
        }
        function W(P) {
          P.done ? H(P.value) : R(P.value).then(X, z);
        }
        W((de = de.apply(Y, Ae || [])).next());
      });
    };
    Object.defineProperty(e, "__esModule", { value: !0 }), e.platform = e.toPlatformPath = e.toWin32Path = e.toPosixPath = e.markdownSummary = e.summary = e.getIDToken = e.getState = e.saveState = e.group = e.endGroup = e.startGroup = e.info = e.notice = e.warning = e.error = e.debug = e.isDebug = e.setFailed = e.setCommandEcho = e.setOutput = e.getBooleanInput = e.getMultilineInput = e.getInput = e.addPath = e.setSecret = e.exportVariable = e.ExitCode = void 0;
    const o = rr, n = sr, i = gt, a = r(Ut), g = r(qr), c = Cy();
    var E;
    (function(Y) {
      Y[Y.Success = 0] = "Success", Y[Y.Failure = 1] = "Failure";
    })(E || (e.ExitCode = E = {}));
    function l(Y, Ae) {
      const ae = (0, i.toCommandValue)(Ae);
      if (process.env[Y] = ae, process.env.GITHUB_ENV || "")
        return (0, n.issueFileCommand)("ENV", (0, n.prepareKeyValueMessage)(Y, Ae));
      (0, o.issueCommand)("set-env", { name: Y }, ae);
    }
    e.exportVariable = l;
    function Q(Y) {
      (0, o.issueCommand)("add-mask", {}, Y);
    }
    e.setSecret = Q;
    function I(Y) {
      process.env.GITHUB_PATH || "" ? (0, n.issueFileCommand)("PATH", Y) : (0, o.issueCommand)("add-path", {}, Y), process.env.PATH = `${Y}${g.delimiter}${process.env.PATH}`;
    }
    e.addPath = I;
    function d(Y, Ae) {
      const ae = process.env[`INPUT_${Y.replace(/ /g, "_").toUpperCase()}`] || "";
      if (Ae && Ae.required && !ae)
        throw new Error(`Input required and not supplied: ${Y}`);
      return Ae && Ae.trimWhitespace === !1 ? ae : ae.trim();
    }
    e.getInput = d;
    function h(Y, Ae) {
      const ae = d(Y, Ae).split(`
`).filter((de) => de !== "");
      return Ae && Ae.trimWhitespace === !1 ? ae : ae.map((de) => de.trim());
    }
    e.getMultilineInput = h;
    function C(Y, Ae) {
      const ae = ["true", "True", "TRUE"], de = ["false", "False", "FALSE"], R = d(Y, Ae);
      if (ae.includes(R))
        return !0;
      if (de.includes(R))
        return !1;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${Y}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    e.getBooleanInput = C;
    function u(Y, Ae) {
      if (process.env.GITHUB_OUTPUT || "")
        return (0, n.issueFileCommand)("OUTPUT", (0, n.prepareKeyValueMessage)(Y, Ae));
      process.stdout.write(a.EOL), (0, o.issueCommand)("set-output", { name: Y }, (0, i.toCommandValue)(Ae));
    }
    e.setOutput = u;
    function B(Y) {
      (0, o.issue)("echo", Y ? "on" : "off");
    }
    e.setCommandEcho = B;
    function m(Y) {
      process.exitCode = E.Failure, b(Y);
    }
    e.setFailed = m;
    function f() {
      return process.env.RUNNER_DEBUG === "1";
    }
    e.isDebug = f;
    function y(Y) {
      (0, o.issueCommand)("debug", {}, Y);
    }
    e.debug = y;
    function b(Y, Ae = {}) {
      (0, o.issueCommand)("error", (0, i.toCommandProperties)(Ae), Y instanceof Error ? Y.toString() : Y);
    }
    e.error = b;
    function w(Y, Ae = {}) {
      (0, o.issueCommand)("warning", (0, i.toCommandProperties)(Ae), Y instanceof Error ? Y.toString() : Y);
    }
    e.warning = w;
    function S(Y, Ae = {}) {
      (0, o.issueCommand)("notice", (0, i.toCommandProperties)(Ae), Y instanceof Error ? Y.toString() : Y);
    }
    e.notice = S;
    function v(Y) {
      process.stdout.write(Y + a.EOL);
    }
    e.info = v;
    function N(Y) {
      (0, o.issue)("group", Y);
    }
    e.startGroup = N;
    function F() {
      (0, o.issue)("endgroup");
    }
    e.endGroup = F;
    function j(Y, Ae) {
      return s(this, void 0, void 0, function* () {
        N(Y);
        let ae;
        try {
          ae = yield Ae();
        } finally {
          F();
        }
        return ae;
      });
    }
    e.group = j;
    function M(Y, Ae) {
      if (process.env.GITHUB_STATE || "")
        return (0, n.issueFileCommand)("STATE", (0, n.prepareKeyValueMessage)(Y, Ae));
      (0, o.issueCommand)("save-state", { name: Y }, (0, i.toCommandValue)(Ae));
    }
    e.saveState = M;
    function K(Y) {
      return process.env[`STATE_${Y}`] || "";
    }
    e.getState = K;
    function ee(Y) {
      return s(this, void 0, void 0, function* () {
        return yield c.OidcClient.getIDToken(Y);
      });
    }
    e.getIDToken = ee;
    var ie = Og();
    Object.defineProperty(e, "summary", { enumerable: !0, get: function() {
      return ie.summary;
    } });
    var re = Og();
    Object.defineProperty(e, "markdownSummary", { enumerable: !0, get: function() {
      return re.markdownSummary;
    } });
    var ge = By();
    Object.defineProperty(e, "toPosixPath", { enumerable: !0, get: function() {
      return ge.toPosixPath;
    } }), Object.defineProperty(e, "toWin32Path", { enumerable: !0, get: function() {
      return ge.toWin32Path;
    } }), Object.defineProperty(e, "toPlatformPath", { enumerable: !0, get: function() {
      return ge.toPlatformPath;
    } }), e.platform = r(my());
  }(Jn)), Jn;
}
var _r = Ou();
async function wy(e) {
  const A = _r.getInput("github-token"), t = Eu(A), r = _i;
  await t.rest.issues.createComment({
    ...r.repo,
    issue_number: r.issue.number,
    body: e
  });
}
async function yy() {
  try {
    const e = _r.getInput("github-token"), t = await Fw(e, _i), r = JSON.parse(_r.getInput("standards"));
    let s = `## Scrimsight Code Review Results

`;
    for (const o of r) {
      const n = await zw(
        _r.getInput("gemini-api-key"),
        o,
        t
      );
      s += `### ${o.shortname}
`, s += `_${o.description}_

`, s += n.foundIssues ? `⚠️ **Issues Found**
${n.details}
` : `✅ All checks passed
`, s += `
`;
    }
    await wy(s);
  } catch (e) {
    console.error(e), _r.setFailed(e.message);
  }
}
yy();
