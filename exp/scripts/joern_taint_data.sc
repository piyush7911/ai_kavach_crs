// Data-driven Joern taint scan: sources / sinks / sanitizers come from a JSON knowledge file
// (exp/knowledge/<lang>.json, mined from community Semgrep taint rules by mine_taint_rules.py). No hand-written tables.
//   joern --script exp/scripts/joern_taint_data.sc --param cpgFile=<cpg> --param knowledge=<json> --param outFile=<tsv>
//         [--param sanitize=true|false] [--param wide=true] [--param ext=<json>]
// wide=true adds "every non-underscore function parameter is a source" (a generic entry-point model; used only as a variant).
// Output rows: FLOW \t class \t sinkFile \t sinkLine \t sinkMethod \t srcFile \t srcLine \t srcMethod
import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, knowledge: String, outFile: String, sanitize: String = "true", wide: String = "false", routes: String = "", fw: String = "", second: String = "", lang: String = "java", bind: String = "false"): Unit = {
  importCpg(cpgFile)
  // ---------- callback binding: resolve calls through function-valued parameters ----------
  // `cb(null, d)` where `cb` is a parameter (or captured parameter) of an enclosing function: add a CALL edge to every function literal passed for that
  // parameter at the callers (following pass-through parameters up to 3 levels). The graph otherwise resolves such calls only to a placeholder.
  var boundEdges = 0
  def refOf(r: MethodRef): Option[Method] = scala.util.Try(r.referencedMethod).toOption   // some method references (e.g. this::helper) have no resolved target
  def parentOf(m: Method): Option[Method] = { val i = m.fullName.lastIndexOf(':'); if (i <= 0) None else cpg.method.fullNameExact(m.fullName.substring(0, i)).headOption }
  def aliases(m: Method): Set[String] = {
    val base: Set[String] = if (!m.name.startsWith("<")) Set(m.name) else Set.empty
    val viaRef: Set[String] = cpg.methodRef.filter(r => refOf(r).contains(m)).flatMap { r => r.astParent match {
      case a: Call if a.name == "<operator>.assignment" => a.argument.l.headOption.map(_.code.split("[.\\s\\]\\[\"']").filter(_.nonEmpty).lastOption.getOrElse("")).toList
      case _ => Nil } }.l.toSet
    base ++ viaRef
  }
  val callsByName: Map[String, List[Call]] = cpg.call.filterNot(_.name.startsWith("<")).l.groupBy(_.name)
  def lambdasPassed(m: Method, idx: Int, depth: Int): List[Method] =
    aliases(m).toList.flatMap(a => callsByName.getOrElse(a, Nil)).flatMap { site =>
      site.argument.l.find(_.argumentIndex == idx).toList.flatMap {
        case r: MethodRef => refOf(r).toList
        case id: Identifier if depth > 0 =>
          var cur: Option[Method] = Some(site.method); var found: Option[(Method, Int)] = None
          while (cur.isDefined && found.isEmpty) { found = cur.get.parameter.l.find(_.name == id.name).map(p => (cur.get, p.index)); cur = if (found.isEmpty) parentOf(cur.get) else None }
          found.toList.flatMap { case (pm, k) => lambdasPassed(pm, k, depth - 1) }
        case _ => Nil } }
  if (bind == "true") {
    val diff = io.shiftleft.codepropertygraph.generated.Cpg.newDiffGraphBuilder
    cpg.call.filterNot(_.name.startsWith("<")).l.foreach { c =>
      var cur: Option[Method] = Some(c.method); var found: Option[(Method, Int)] = None
      while (cur.isDefined && found.isEmpty) { found = cur.get.parameter.l.find(pp => pp.name == c.name && pp.index > 0).map(p => (cur.get, p.index)); cur = if (found.isEmpty) parentOf(cur.get) else None }
      found.foreach { case (pm, k) => lambdasPassed(pm, k, 3).distinct.foreach { t => diff.addEdge(c, t, io.shiftleft.codepropertygraph.generated.EdgeTypes.CALL); boundEdges += 1 } }
      // a call through a local variable that holds a function literal: `const f = () => {...}; f()`
      if (found.isEmpty) {
        var scope: Option[Method] = Some(c.method); var done = false
        while (scope.isDefined && !done) {
          val targets = scope.get.ast.isCall.name("<operator>.assignment").l.filter(a => a.argument.l.headOption.exists(_.code == c.name)).flatMap(a => a.argument.l.drop(1).collect { case r: MethodRef => refOf(r) }.flatten)
          targets.distinct.foreach { t => diff.addEdge(c, t, io.shiftleft.codepropertygraph.generated.EdgeTypes.CALL); boundEdges += 1 }
          done = targets.nonEmpty; scope = if (done) None else parentOf(scope.get)
        }
      }
    }
    // instance-method resolution through the constructor name: the front end links `obj.m(...)` only to an external placeholder `Ctor:m`.
    // Link the call to the internal method that is assigned as `this.m = ...` (or Ctor.prototype.m = ...) inside `Ctor`.
    if (lang == "js") {
      val internal = cpg.method.isExternal(false).l
      val aliasIdx: Map[String, List[Method]] = internal.flatMap(m => aliases(m).toList.map(a => (a, m))).groupBy(_._1).map { case (k, v) => k -> v.map(_._2) }
      cpg.call.filterNot(_.name.startsWith("<")).l.foreach { c =>
        val cs = c.callee.l
        if (cs.nonEmpty && cs.forall(_.isExternal)) {
          cs.foreach { ph =>
            val tail = ph.fullName.split("::").lastOption.getOrElse("").stripPrefix("program:").split(":").toList
            if (tail.size >= 2) {
              val ctor = tail(tail.size - 2); val meth = tail.last
              val phFile = ph.fullName.split("::").headOption.getOrElse("")
              val cands = aliasIdx.getOrElse(meth, Nil)
              val byCtor = cands.filter(m => m.fullName.contains(":" + ctor + ":"))
              (if (byCtor.nonEmpty) byCtor else cands.filter(m => m.filename == phFile)).foreach { t => diff.addEdge(c, t, io.shiftleft.codepropertygraph.generated.EdgeTypes.CALL); boundEdges += 1 }
            }
          }
        }
      }
    }
    flatgraph.DiffGraphApplier.applyDiff(cpg.graph, diff)
  }
  val kb = ujson.read(os.read(os.Path(knowledge, os.pwd)))
  val allCalls: List[Call] = cpg.call.l
  val accessOps = Set("<operator>.fieldAccess", "<operator>.indexAccess", "<operator>.indirectIndexAccess", "<operator>.indirectFieldAccess")

  def str(v: ujson.Value): Option[String] = v match { case ujson.Null => None; case x => Some(x.str) }

  // does call `c` match a mined call/access spec?
  def callMatches(c: Call, s: ujson.Value): Boolean = {
    val kind = s("kind").str; val name = s("name").str; val recv = str(s("recv"))
    val ctor = s.obj.get("ctor").exists(_.bool)
    val mfn = s.obj.get("mfn").flatMap(m => if (m == ujson.Null) None else Some(m.str))
    if (mfn.isDefined) {
      c.methodFullName.matches("(?s)" + mfn.get)          // LLM specs are anchored to the exact resolved API
    } else if (kind == "access") {
      accessOps.contains(c.name) && (recv match {
        case Some(r) => c.code.matches("(?s).*" + r + "\\s*(\\.|\\[)\\s*['\"]?" + name + ".*")
        case None    => name != ".*" && c.code.matches("(?s)(^|.*\\W)" + name + "\\b.*")
      })
    } else if (ctor) {
      (c.name == "<init>" || c.name == "<operator>.new") && (name == ".*" || c.code.matches("(?s).*\\bnew\\s+[\\w.]*" + name + "\\b.*") || c.methodFullName.matches("(?s).*" + name + ".*"))
    } else {
      c.name.matches(name) && !c.name.startsWith("<operator>") && (recv match {
        case Some(r) => c.code.matches("(?s).*" + r + "\\s*\\.\\s*" + (if (name == ".*") "[\\w$]+" else name) + "\\b.*") || c.methodFullName.matches("(?s).*" + r + ".*")
        case None    => true
      }) && (str(s("type")) match {
        case Some(t) => c.methodFullName.contains(t) || c.methodFullName.contains("<unresolved") || c.methodFullName.contains("<unknown")
        case None    => true
      })
    }
  }
  def nodesFor(specs: List[ujson.Value], asSink: Boolean): List[CfgNode] = {
    val out = scala.collection.mutable.ListBuffer[CfgNode]()
    specs.foreach { s =>
      s("kind").str match {
        case "param" =>
          val anns = s("annotations").arr.map(_.str).mkString("|")
          if (anns.nonEmpty && !asSink) out ++= cpg.parameter.where(_.annotation.name(anns)).l
        case "typed" =>
          if (!asSink) out ++= cpg.parameter.typeFullName(".*" + s("type").str + ".*").l
        case _ =>
          val hits = allCalls.filter(c => callMatches(c, s))
          if (asSink) {
            val idx = s.obj.get("arg").flatMap(a => if (a == ujson.Null) None else Some(a.num.toInt))
            hits.foreach { c => idx match { case Some(i) => out ++= c.argument.l.filter(_.argumentIndex == i + 1).collect { case n: CfgNode => n }; case None => out ++= c.argument.l.collect { case n: CfgNode => n } } }
          } else out ++= hits
      }
    }
    out.toList
  }
  def specsOf(section: String, cls: String): List[ujson.Value] = kb(section).obj.get(cls).map(_.arr.toList).getOrElse(Nil)

  val known = Set("sql-injection", "nosql-injection", "command-injection", "code-injection", "xss", "path-traversal", "ssrf", "open-redirect",
                  "xxe", "deserialization", "ssti", "ldap-injection", "xpath-injection")
  val wideSrc: List[CfgNode] = if (wide == "true")
    cpg.method.isExternal(false).filterNot(_.name.startsWith("<")).filterNot(_.name.startsWith("_")).parameter.filterNot(p => p.name == "self" || p.name == "cls").l else Nil

  // Step 1: route-map entry points. Each (file, function) handler listed in the route map contributes its parameters as sources.
  val routeSrc: List[CfgNode] = if (routes.isEmpty) Nil else {
    val rm = ujson.read(os.read(os.Path(routes, os.pwd)))("routes").arr.toList
    rm.flatMap { r =>
      val f = r("file").str; val fn = r("function").str
      if (f.isEmpty || fn.isEmpty || fn.startsWith("<")) Nil
      else cpg.method.nameExact(fn).filter(_.filename.endsWith(f)).parameter.filterNot(p => p.name == "self" || p.name == "cls" || p.name == "this").l
    }.collect { case c: CfgNode => c }.distinct
  }
  // ---------- Step 2: framework checks as data ----------
  def constStr(n: AstNode): Option[String] = n match {
    case l: Literal => Some(l.code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'"))
    case _ =>
      val name = n.code.split("[.\\s]").lastOption.getOrElse("")
      if (name.isEmpty) None else cpg.assignment.filter(a => a.target.code.split("[.\\s]").lastOption.contains(name)).source.isLiteral.code.l.headOption.map(_.stripPrefix("\"").stripSuffix("\""))
  }
  val fwChecks: List[ujson.Value] = if (fw.isEmpty) Nil else ujson.read(os.read(os.Path(fw, os.pwd)))("checks").arr.toList
  def fwSinks(cls: String): List[CfgNode] = fwChecks.filter(_("class").str == cls).flatMap { ck =>
    ck("kind").str match {
      case "return_value" =>
        val ann = ck("handler_annotation").str; val rt = ck("return_type").str
        cpg.method.where(_.annotation.name(ann)).filter(m => m.code.matches("(?s).*" + rt + ".*")).ast.isReturn.l.collect { case n: CfgNode => n }
      case "status_ctor" =>
        val st = ck("status").str
        cpg.call.methodFullName("(?s)" + ck("type").str + "\\.<init>.*").l.flatMap { c =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          if (args.exists(a => a.code.matches("(?s).*\\b(" + st + ")\\b.*"))) args.filterNot(a => a.code.matches("(?s).*\\b(" + st + ")\\b.*")).collect { case n: CfgNode => n } else Nil }
      case "header_write" =>
        val hre = ck("header").str; val apis = ck("apis").str
        cpg.call.name(apis).l.flatMap { c =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          val byName = if (args.size >= 2 && constStr(args(0)).exists(_.matches(hre))) List(args(1)) else Nil
          val byChain = c.argument.l.find(_.argumentIndex == 0).toList.flatMap {
            case r: Call if Set("get", "getFirst", "computeIfAbsent", "getOrDefault", "getHeaders").contains(r.name) =>
              r.argument.l.filter(_.argumentIndex >= 1).headOption.filter(a => constStr(a).exists(_.matches(hre))).toList.flatMap(_ => args.headOption)
            case _ => Nil }
          val single = if (c.name.matches("(?i)setLocation|location") && args.nonEmpty) List(args.head) else Nil
          (byName ++ byChain ++ single).collect { case n: CfgNode => n } }
      case "property_sink" =>
        val pr = ck("property").str
        cpg.assignment.filter(a => a.argument.l.headOption.exists(t => t.code.matches("(?s).*\\.(" + pr + ")$"))).l.flatMap(a => a.argument.l.drop(1)).collect { case n: CfgNode => n }
      case "html_string_build" =>
        val hre = ck("html").str
        cpg.call.name(ck("names").str).l.flatMap { c =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          val lits = args.collect { case l: Literal if l.code.matches(hre) => l }
          if (lits.nonEmpty) args.filterNot(_.isInstanceOf[Literal]).collect { case n: CfgNode => n } else Nil }
      case "config_gated_sink" =>
        val gated = cpg.call.name(ck("gate_call").str).code("(?s).*" + ck("gate_code").str + ".*").nonEmpty
        if (!gated) Nil else cpg.call.name(ck("sink_name").str).code("(?s).*" + ck("sink_recv").str + "\\s*\\.\\s*(" + ck("sink_name").str + ").*").l.flatMap(_.argument.l).collect { case n: CfgNode => n }
      case _ => Nil
    }
  }
  val out = new java.io.PrintWriter(outFile)
  out.println(s"META\troute_entry_sources\t${routeSrc.size}")
  out.println(s"META\tbound_callback_edges\t$boundEdges")
  val seen = scala.collection.mutable.Set[String]()
  (kb("sinks").obj.keys.toSet ++ fwChecks.map(_("class").str)).filter(known.contains).foreach { cls =>
    val sinks = nodesFor(specsOf("sinks", cls), true) ++ fwSinks(cls)
    val srcs = nodesFor(specsOf("sources", cls), false) ++ wideSrc ++ routeSrc
    val sans = specsOf("sanitizers", cls)
    out.println(s"META\t$cls\tsinks=${sinks.size}\tsources=${srcs.size}\tsanitizer_specs=${sans.size}")
    if (sinks.nonEmpty && srcs.nonEmpty) {
      sinks.iterator.reachableByFlows(srcs.iterator).foreach { path =>
        val e = path.elements; val s = e.head; val t = e.last
        def f(n: AstNode) = { val l = n.location; l.filename + "\t" + l.lineNumber.getOrElse(-1) + "\t" + l.methodShortName }
        val sanitized = sanitize == "true" && sans.nonEmpty && e.exists { el => el match { case c: Call => sans.exists(sp => sp("kind").str != "param" && sp("kind").str != "typed" && callMatches(c, sp)); case _ => false } }
        val key = cls + f(t) + f(s)
        if (!sanitized && seen.add(key)) out.println(s"FLOW\t$cls\t${f(t)}\t${f(s)}")
      }
    }
  }

  // ---------- Step 4: second-order (store -> load) ----------
  if (second.nonEmpty) {
    val so = ujson.read(os.read(os.Path(second, os.pwd)))
    val soClasses = so("classes").arr.map(_.str).toList
    def tableOf(c: Call): String = c.argument.l.filter(_.argumentIndex >= 1).flatMap(a => constStr(a)).flatMap(sql => "(?i)(?:into|update|from|join)\\s+([A-Za-z_][\\w]*)".r.findFirstMatchIn(sql).map(_.group(1).toLowerCase)).headOption.getOrElse("?")
    def ownerOf(c: Call): String = c.methodFullName.takeWhile(_ != ':').split("\\.").dropRight(1).lastOption.getOrElse("?")
    def recvKey(c: Call): String = c.argument.l.find(_.argumentIndex == 0).map(_.code.takeRight(40)).getOrElse(c.code.takeWhile(_ != '.').takeRight(40))
    def keyOf(c: Call, kind: String): String = kind match { case "owner" => ownerOf(c); case "sql_table" => tableOf(c); case _ => recvKey(c) }
    val stores = so("stores").arr.toList.filter(_("langs").arr.exists(_.str == lang))
    def isWrite(c: Call, s: ujson.Value): Boolean = s.obj.get("write_mfn").map(r => c.methodFullName.matches(r.str)).getOrElse(false) || s.obj.get("write_name").exists(r => c.name.matches(r.str) && !c.name.startsWith("<") && s.obj.get("write_recv").forall(rr => c.code.matches("(?s)" + rr.str)))
    def isRead(c: Call, s: ujson.Value): Boolean = s.obj.get("read_mfn").map(r => c.methodFullName.matches(r.str)).getOrElse(false) || s.obj.get("read_name").exists(r => c.name.matches(r.str) && !c.name.startsWith("<") && s.obj.get("read_recv").forall(rr => c.code.matches("(?s)" + rr.str)))
    val writes: List[(Call, String)] = allCalls.flatMap(c => stores.find(s => isWrite(c, s)).map(s => (c, keyOf(c, s("key").str))))
    val reads: List[(Call, String)]  = allCalls.flatMap(c => stores.find(s => isRead(c, s)).map(s => (c, keyOf(c, s("key").str))))
    val reqSrc: List[CfgNode] = nodesFor(specsOf("sources", "xss"), false) ++ routeSrc ++ wideSrc
    val writeArgs: List[(CfgNode, String)] = writes.flatMap { case (w, k) => w.argument.l.filter(_.argumentIndex >= 1).collect { case n: CfgNode => (n, k) } }
    val srcByKey = scala.collection.mutable.Map[String, scala.collection.mutable.Set[(String, String)]]()   // key -> set of (srcLocation columns)
    if (writeArgs.nonEmpty && reqSrc.nonEmpty) {
      val argKey = writeArgs.map { case (n, k) => n.id -> k }.toMap
      writeArgs.map(_._1).iterator.reachableByFlows(reqSrc.iterator).foreach { p =>
        val e = p.elements; val sk = argKey.get(e.last.asInstanceOf[CfgNode].id).getOrElse("?")
        def f(n: AstNode) = { val l = n.location; l.filename + "\t" + l.lineNumber.getOrElse(-1) + "\t" + l.methodShortName }
        srcByKey.getOrElseUpdate(sk, scala.collection.mutable.Set()) += ((f(e.head), f(e.last)))
      }
    }
    out.println(s"META\tsecond_order\twrites=${writes.size}\treads=${reads.size}\ttainted_keys=${srcByKey.keys.mkString("|").take(200)}")
    srcByKey.foreach { case (k, srcLocs) =>
      val readCalls: List[Call] = reads.filter(_._2 == k).map(_._1)
      // stored data delivered through a callback: parameters of the function literals bound to the read call (directly, or via a pass-through parameter)
      val cbParams: List[CfgNode] = readCalls.flatMap { r =>
        r.argument.l.filter(_.argumentIndex >= 1).flatMap {
          case mr: MethodRef => refOf(mr).toList.flatMap(_.parameter.l.filter(_.index > 0))
          case id: Identifier =>
            var cur: Option[Method] = Some(r.method); var found: Option[(Method, Int)] = None
            while (cur.isDefined && found.isEmpty) { found = cur.get.parameter.l.find(pp => pp.name == id.name && pp.index > 0).map(pp => (cur.get, pp.index)); cur = if (found.isEmpty) parentOf(cur.get) else None }
            found.toList.flatMap { case (pm, ix) => lambdasPassed(pm, ix, 3).flatMap(_.parameter.l.filter(_.index > 0)) }
          case _ => Nil } }.collect { case n: CfgNode => n }
      val readNodes: List[CfgNode] = readCalls.collect { case n: CfgNode => n } ++ cbParams
      if (readNodes.nonEmpty) soClasses.foreach { cls =>
        val sinks = nodesFor(specsOf("sinks", cls), true) ++ fwSinks(cls)
        if (sinks.nonEmpty) sinks.iterator.reachableByFlows(readNodes.iterator).foreach { p =>
          val t = p.elements.last
          val tl = t.location
          srcLocs.foreach { case (srcLoc, _) =>
            val key2 = "2nd" + cls + tl.filename + tl.lineNumber + srcLoc
            if (seen.add(key2)) out.println(s"FLOW\t$cls\t${tl.filename}\t${tl.lineNumber.getOrElse(-1)}\t${tl.methodShortName}\t$srcLoc\tsecond-order:$k")
          }
        }
      }
    }
  }
  out.close()
}
