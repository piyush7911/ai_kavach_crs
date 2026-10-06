import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*
@main def exec(cpgFile: String, bind: String = "true", lang: String = "js"): Unit = {
  importCpg(cpgFile)
  var boundEdges = 0
  def parentOf(m: Method): Option[Method] = { val i = m.fullName.lastIndexOf(':'); if (i <= 0) None else cpg.method.fullNameExact(m.fullName.substring(0, i)).headOption }
  def aliases(m: Method): Set[String] = {
    val base: Set[String] = if (!m.name.startsWith("<")) Set(m.name) else Set.empty
    val viaRef: Set[String] = cpg.methodRef.filter(_.referencedMethod == m).flatMap { r => r.astParent match {
      case a: Call if a.name == "<operator>.assignment" => a.argument.l.headOption.map(_.code.split("[.\\s\\]\\[\"']").filter(_.nonEmpty).lastOption.getOrElse("")).toList
      case _ => Nil } }.l.toSet
    base ++ viaRef
  }
  val callsByName: Map[String, List[Call]] = cpg.call.filterNot(_.name.startsWith("<")).l.groupBy(_.name)
  def lambdasPassed(m: Method, idx: Int, depth: Int): List[Method] =
    aliases(m).toList.flatMap(a => callsByName.getOrElse(a, Nil)).flatMap { site =>
      site.argument.l.find(_.argumentIndex == idx).toList.flatMap {
        case r: MethodRef => List(r.referencedMethod)
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
          val targets = scope.get.ast.isCall.name("<operator>.assignment").l.filter(a => a.argument.l.headOption.exists(_.code == c.name)).flatMap(a => a.argument.l.drop(1).collect { case r: MethodRef => r.referencedMethod })
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
  println("bound edges: " + boundEdges)
  val where = cpg.assignment.filter(a => a.argument.l.headOption.exists(t => t.code.matches("(?s).*\\.(\\$where)$"))).l.flatMap(a => a.argument.l.drop(1)).collect { case n: CfgNode => n }
  println("$where sinks: " + where.map(w => w.method.filename.split("/").last + ":" + w.lineNumber.getOrElse(-1) + " " + w.code.take(50)).mkString(" | "))
  val reqs = cpg.call.code("req\\.(query|params|body).*").l.collect { case n: CfgNode => n }
  println("flows req -> $where: " + where.iterator.reachableByFlows(reqs.iterator).size)
  val thr = cpg.method.filter(_.filename.endsWith("allocations-dao.js")).parameter.nameExact("threshold").l.collect { case n: CfgNode => n }
  println("flows threshold param -> $where: " + where.iterator.reachableByFlows(thr.iterator).size)
  val routeCall = cpg.call.name("getByUserIdAndThreshold").filter(_.method.filename.endsWith("routes/allocations.js")).l
  routeCall.foreach(c => println("route call callees now: " + c.callee.fullName.l.mkString(" | ")))
  val args = routeCall.flatMap(_.argument.l.filter(_.argumentIndex == 2)).collect { case n: CfgNode => n }
  println("flows req -> route call arg2 (threshold): " + args.iterator.reachableByFlows(reqs.iterator).size)
  println("flows route call arg2 -> $where: " + where.iterator.reachableByFlows(args.iterator).size)
}
