"use strict";
// Force every TCP server in the target app to bind to loopback only, whatever host
// the app asks for. Loaded with `node --require <this>` from the runner, and kept
// OUTSIDE the target tree so a generated patch can never see or disable it.
//
// Why: NodeGoat (and many apps) call `.listen(port)` with no host, which binds to
// 0.0.0.0 — reachable by anyone on the venue LAN. Combined with the app's own
// injection bugs that is remote code execution on this machine. We judge exploits
// over loopback only; nothing the harness starts should be reachable off-box.
const net = require("net");
const LOOPBACK = "127.0.0.1";
const orig = net.Server.prototype.listen;

net.Server.prototype.listen = function (...args) {
  let cb;
  if (typeof args[args.length - 1] === "function") cb = args.pop();
  const first = args[0];
  if (first !== null && typeof first === "object") {
    // listen(options[, cb]) — pin the host, keep everything else
    args[0] = Object.assign({}, first, { host: LOOPBACK });
  } else if (typeof first === "number" || typeof first === "string") {
    // listen(port[, host[, backlog]][, cb]) — drop any host, force loopback
    const port = first;
    const backlog = typeof args[2] === "number" ? args[2] : undefined;
    args = backlog !== undefined ? [port, LOOPBACK, backlog] : [port, LOOPBACK];
  }
  // Any other shape (unix socket path handle, etc.) is left untouched.
  if (cb) args.push(cb);
  return orig.apply(this, args);
};
