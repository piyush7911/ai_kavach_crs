// Fixture for config/semgrep/kavach_js.yaml. `// ruleid: X` marks the line that MUST be flagged by
// rule X; `// ok: X` marks a similar line that must NOT be. Negatives matter as much as positives:
// they are how we keep precision.
const needle = require("needle");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");

function ssrf(req, res) {
    const url = req.query.url + req.query.symbol;
    // ruleid: kavach-js-ssrf
    needle.get(url, () => {});
    // ok: kavach-js-ssrf
    needle.get("https://api.example.com/quote", () => {});
    const id = encodeURIComponent(req.query.id);
    // ok: kavach-js-ssrf
    needle.get("https://api.example.com/q/" + id, () => {});
}

function code(req, res) {
    // ruleid: kavach-js-code-injection
    const a = eval(req.body.preTax);
    // ok: kavach-js-code-injection
    const b = parseInt(req.body.preTax);
    // ok: kavach-js-code-injection
    const c = eval("1 + 2");
    return [a, b, c];
}

function cmd(req, res) {
    // ruleid: kavach-js-command-injection
    exec("ping " + req.query.host);
    // ok: kavach-js-command-injection
    exec("uptime");
}

function files(req, res) {
    // ruleid: kavach-js-path-traversal
    fs.readFile("/data/" + req.query.name, () => {});
    // ok: kavach-js-path-traversal
    fs.readFile("/data/" + path.basename(req.query.name), () => {});
    // ok: kavach-js-path-traversal
    fs.readFile("/data/static.txt", () => {});
}

function nosql(uid, threshold) {
    // ruleid: kavach-js-nosql-where
    const q1 = { $where: `this.userId == ${uid} && this.stocks > '${threshold}'` };
    // ruleid: kavach-js-nosql-where
    const q2 = { $where: "this.userId == " + uid };
    // ok: kavach-js-nosql-where
    const q3 = { $where: "this.stocks > 0" };
    // ok: kavach-js-nosql-where
    const q4 = { userId: uid, stocks: { $gt: threshold } };
    return [q1, q2, q3, q4];
}

// ruleid: kavach-js-hardcoded-secret
const config = { cookieSecret: "session_cookie_secret_key_here", port: 4000 };
// ok: kavach-js-hardcoded-secret
const config2 = { cookieSecret: process.env.COOKIE_SECRET, port: 4000 };
// ok: kavach-js-hardcoded-secret
const config3 = { passwordMinLength: "8", title: "A perfectly ordinary title" };

// ok: kavach-js-hardcoded-secret
const invalidPasswordErrorMessage = "Invalid password";
// ok: kavach-js-hardcoded-secret
const config4 = { passwordHelp: "Use at least eight characters" };

// ruleid: kavach-js-redos-nested-quantifier
const bad = /([0-9]+)+\#/;
// ok: kavach-js-redos-nested-quantifier
const good = /^[0-9]+#$/;

// The request is recognised by role (first parameter of a handler), not by the name `req`.
function renamed(incoming, outgoing) {
    // ruleid: kavach-js-ssrf
    needle.get(incoming.query.target, () => {});
}
const arrowHandler = async (r, s) => {
    // ruleid: kavach-js-code-injection
    eval(r.body.code);
};
function notAHandler(config) {
    // ok: kavach-js-ssrf
    needle.get(config.body, () => {});
}

module.exports = { renamed, arrowHandler, notAHandler, ssrf, code, cmd, files, nosql, config, config2, config3, bad, good };
