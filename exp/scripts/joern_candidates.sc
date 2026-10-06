// List the distinct library/external API calls an app uses (candidates for LLM spec inference).
//   joern --script exp/scripts/joern_candidates.sc --param cpgFile=<cpg> --param outFile=<tsv>
// Row: name \t receiver-text \t methodFullName \t example-code \t count
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, outFile: String): Unit = {
  importCpg(cpgFile)
  def recvOf(c: Call): String = { val i = c.code.indexOf("(" ); val head = if (i > 0) c.code.substring(0, i) else c.code; val j = head.lastIndexOf('.'); if (j > 0) head.substring(0, j).takeRight(60) else "" }
  val own = cpg.typeDecl.isExternal(false).fullName.l.filter(_.contains(".")).toSet   // types defined by the app itself
  def isOwn(m: String): Boolean = { val q = m.takeWhile(_ != ':'); own.exists(t => q.startsWith(t + ".")) }
  val rows = cpg.call.filterNot(_.name.startsWith("<operator>")).filterNot(_.name.startsWith("<")).filterNot(c => isOwn(c.methodFullName)).filter { c =>
    c.callee.isExternal.nonEmpty || c.methodFullName.contains("<unknown") || c.methodFullName.contains("<unresolved") || c.methodFullName.contains("<dynamic") }.l
  val out = new java.io.PrintWriter(outFile)
  rows.groupBy(c => (c.name, recvOf(c), c.methodFullName)).toList.sortBy(-_._2.size).foreach { case ((n, r, m), cs) =>
    out.println(List(n, r, m, cs.head.code.replace("\t", " ").replace("\n", " ").take(110), cs.size).mkString("\t")) }
  out.close()
}
