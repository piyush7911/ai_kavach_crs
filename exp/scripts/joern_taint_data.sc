// Data-driven Joern taint scan: sources / sinks / sanitizers come from a JSON knowledge file
// (exp/knowledge/<lang>.json, mined from community Semgrep taint rules by mine_taint_rules.py). No hand-written tables.
//   joern --script exp/scripts/joern_taint_data.sc --param cpgFile=<cpg> --param knowledge=<json> --param outFile=<tsv>
//         [--param sanitize=true|false] [--param wide=true] [--param ext=<json>]
// wide=true adds "every non-underscore function parameter is a source" (a generic entry-point model; used only as a variant).
// Output rows: FLOW \t class \t sinkFile \t sinkLine \t sinkMethod \t srcFile \t srcLine \t srcMethod
import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, knowledge: String, outFile: String, sanitize: String = "true", wide: String = "false"): Unit = {
  importCpg(cpgFile)
  val kb = ujson.read(os.read(os.Path(knowledge, os.pwd)))
  val allCalls: List[Call] = cpg.call.l
  val accessOps = Set("<operator>.fieldAccess", "<operator>.indexAccess", "<operator>.indirectIndexAccess", "<operator>.indirectFieldAccess")

  def str(v: ujson.Value): Option[String] = v match { case ujson.Null => None; case x => Some(x.str) }

  // does call `c` match a mined call/access spec?
  def callMatches(c: Call, s: ujson.Value): Boolean = {
    val kind = s("kind").str; val name = s("name").str; val recv = str(s("recv"))
    val ctor = s.obj.get("ctor").exists(_.bool)
    if (kind == "access") {
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

  val out = new java.io.PrintWriter(outFile)
  val seen = scala.collection.mutable.Set[String]()
  kb("sinks").obj.keys.filter(known.contains).foreach { cls =>
    val sinks = nodesFor(specsOf("sinks", cls), true)
    val srcs = nodesFor(specsOf("sources", cls), false) ++ wideSrc
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
  out.close()
}
