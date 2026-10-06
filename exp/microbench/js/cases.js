// One taint pattern per function. Source = taintSource(), sink = sink(x).
function taintSource() { return "x"; }
function sink(s) { }
const db = { findOne: function (q, cb) { cb(null, taintSource()); }, find: function (q, cb) { cb(null, [taintSource()]); } };

function j1_direct() { const s = taintSource(); sink(s); }
function j2_foreach_capture() { const arr = [taintSource()]; let out = ""; arr.forEach((x) => { out += x; }); sink(out); }
function j3_for_of() { const arr = [taintSource()]; let out = ""; for (const x of arr) { out += x; } sink(out); }
function j4_sink_in_callback() { [taintSource()].forEach((x) => { sink(x); }); }
function j5_db_callback_param() { db.findOne({}, function (err, doc) { sink(doc); }); }
function getUser(cb) { db.findOne({}, function (err, d) { cb(null, d); }); }
function j6_callback_through_wrapper() { getUser(function (err, doc) { sink(doc); }); }
function j7_promise_then() { Promise.resolve(taintSource()).then((x) => { sink(x); }); }
function j8_map_chain() { sink([taintSource()].map((x) => x + "!").join("")); }
function j9_closure_object_mutation() { const box = {}; [taintSource()].forEach((x) => { box.v = x; }); sink(box.v); }
function j10_array_push_capture() { const acc = []; ["a"].forEach(() => { acc.push(taintSource()); }); sink(acc.join("")); }
