// Step 3: API-misuse catalogue scan with constant resolution and call-graph capability tagging.
//   joern --script exp/scripts/joern_misuse.sc --param cpgFile=<cpg> --param catalog=<json> --param outFile=<tsv>
// Rows: HIT \t class \t file \t line \t method \t detail          (direct)
//       VIA \t class \t file \t line \t method \t via-callee      (caller of a tagged method, depth <= 3)
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, catalog: String, outFile: String, lang: String = "java"): Unit = {
  importCpg(cpgFile)
  val cat = ujson.read(os.read(os.Path(catalog, os.pwd)))
  val ctxRe = cat("ctx_re").str
  val allCalls: List[Call] = cpg.call.filterNot(_.name.startsWith("<operator>.assign")).l
  def strip(s: String) = s.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")
  def constStr(n: AstNode): Option[String] = n match {
    case l: Literal => Some(strip(l.code))
    case _ =>
      val name = n.code.split("[.\\s]").lastOption.getOrElse("")
      if (name.isEmpty || !name.matches("[A-Za-z_][A-Za-z_0-9]*")) None
      else cpg.assignment.filter(a => a.target.code.split("[.\\s]").lastOption.contains(name)).source.isLiteral.code.l.headOption.map(strip)
  }
  def code(c: Call): String = c.code.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("//[^\\n]*", "")      // comments carry fix hints, not behaviour
  def argAt(c: Call, i: Int): Option[Expression] = c.argument.l.find(_.argumentIndex == i + 1)
  def methodOf(c: AstNode): Option[Method] = c match { case cc: Call => Some(cc.method); case _ => None }
  val out = new java.io.PrintWriter(outFile)
  case class Hit(cls: String, m: Method, line: Int, detail: String)
  val hits = scala.collection.mutable.ListBuffer[Hit]()

  cat("checks").arr.foreach { chk =>
    val cls = chk("class").str
    chk.obj.get("calls").map(_.arr.toList).getOrElse(Nil).foreach { sp =>
      val mfn = sp.obj.get("mfn").map(_.str); val nm = sp.obj.get("name").map(_.str); val recv = sp.obj.get("recv").map(_.str)
      val langOk = sp.obj.get("langs").forall(_.arr.exists(_.str == lang))
      val candidates = if (!langOk) Nil else allCalls.filter { c =>
        mfn.forall(r => c.methodFullName.matches("(?s)" + r)) && nm.forall(r => c.name.matches("(?s)" + r)) &&
        recv.forall(r => code(c).matches("(?s).*(" + r + ").*")) && !(mfn.isEmpty && nm.isEmpty)
      }
      candidates.foreach { c =>
        var ok = true; var detail = c.code.take(70)
        sp.obj.get("arg").foreach { ai =>
          val a = argAt(c, ai.num.toInt); val v = a.flatMap(constStr)
          if (sp.obj.contains("bad")) { ok = ok && v.exists(_.matches("(?s)" + sp("bad").str)); detail = v.getOrElse("?") }
          if (sp.obj.contains("literal_arg")) { ok = ok && a.exists(_.isInstanceOf[Literal]) ; detail = "hardcoded literal key" }
        }
        sp.obj.get("value_arg").foreach { vi =>
          val v = argAt(c, vi.num.toInt).flatMap(constStr); ok = ok && v.exists(_.matches("(?s)" + sp("value_bad").str)); detail = detail + "=" + v.getOrElse("?") }
        sp.obj.get("code_bad").foreach { r => ok = ok && code(c).matches("(?s)" + r.str) }
        sp.obj.get("absent").foreach { r => val rr = r.str; ok = ok && !c.method.call.name.l.exists(_.matches(rr)) }
        if (ok) hits += Hit(cls, c.method, c.lineNumber.getOrElse(-1), detail)
      }
    }
    chk.obj.get("assign").foreach { a =>
      val tre = a("target").str; val minLen = a("min_len").num.toInt; val skip = a("skip_literal").str
      cpg.assignment.l.foreach { asg =>
        val tcode = asg.target.code
        if (tcode.matches("(?s)" + tre) && !tcode.contains("environ") && !tcode.contains("getenv")) asg.source match {
          case l: Literal =>
            val v = strip(l.code); val tn = tcode.split("[.\\s\\[\\]'\"]").filter(_.nonEmpty).lastOption.getOrElse("").toLowerCase
            if (v.length >= minLen && !v.matches(skip) && v.toLowerCase != tn && !tn.contains(v.toLowerCase)) hits += Hit(cls, asg.method, asg.lineNumber.getOrElse(-1), tcode.take(40) + " = <literal>")
          case _ =>
        }
      }
    }
    chk.obj.get("app_absent").foreach { a =>
      if (a("langs").arr.exists(_.str == lang)) {
        val present = allCalls.filter(c => c.name.matches(a("present").str) && c.code.matches("(?s).*(" + a("present_recv").str + ").*"))
        val absent = allCalls.exists(c => c.name.matches(a("absent").str)) || cpg.identifier.name(a("absent").str).nonEmpty
        if (!absent) present.headOption.foreach(c => hits += Hit(cls, c.method, c.lineNumber.getOrElse(-1), "no " + a("absent").str + " middleware anywhere"))
      }
    }
    // tokens: identifiers / field names / literals that name a weak primitive, inside a method that does crypto-ish work
    chk.obj.get("tokens").foreach { tk =>
      val re = tk.str; val trecv = chk.obj.get("token_recv").map(_.str)
      def inCtx(m: Method) = m.code.matches(ctxRe) || m.call.name.l.exists(_.matches("(?i).*(digest|hash|cipher|encrypt|jwt|sign|verify|algorithm).*"))
      cpg.literal.l.filter(l => strip(l.code).matches(re) && trecv.isEmpty).foreach { l => val m = l.inAst.collectAll[Method].headOption; m.filter(inCtx).foreach(mm => hits += Hit(cls, mm, l.lineNumber.getOrElse(-1), "literal " + l.code)) }
      cpg.identifier.l.filter(i => i.name.matches(re) && trecv.isEmpty).foreach { i => i.inAst.collectAll[Method].headOption.filter(inCtx).foreach(mm => hits += Hit(cls, mm, i.lineNumber.getOrElse(-1), "token " + i.name)) }
      cpg.call.name("<operator>.fieldAccess").l.filter { f => val last = f.code.split("[.\\s]").lastOption.getOrElse(""); last.matches(re) && trecv.forall(r => f.code.matches("(?s).*" + r + ".*")) }
        .foreach { f => if (inCtx(f.method)) hits += Hit(cls, f.method, f.lineNumber.getOrElse(-1), "token " + f.code) }
    }
  }
  hits.toList.distinct.foreach(h => out.println(s"HIT\t${h.cls}\t${h.m.filename}\t${h.line}\t${h.m.name}\t${h.detail.replace("\t", " ")}"))
  // capability tagging through the call graph (depth 3)
  hits.toList.map(h => (h.cls, h.m)).distinct.foreach { case (cls, m0) =>
    var frontier = List(m0); val seen = scala.collection.mutable.Set[String](m0.fullName)
    (1 to 3).foreach { _ =>
      val next = frontier.flatMap(m => m.callIn.l.map(c => (c, c.method))).filter(x => seen.add(x._2.fullName))
      next.foreach { case (c, caller) => out.println(s"VIA\t$cls\t${caller.filename}\t${c.lineNumber.getOrElse(-1)}\t${caller.name}\t${m0.name}") }
      frontier = next.map(_._2)
    }
  }
  out.close()
}
