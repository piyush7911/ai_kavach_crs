// Joern taint scan: request-input sources -> dangerous-call sinks, per vulnerability class.
// One script for all languages; only the source/sink name tables differ.
//   joern --script exp/scripts/joern_taint.sc --param cpgFile=<cpg> --param lang=<py|js|java> --param outFile=<tsv> [--param wide=true]
// Output rows: FLOW \t class \t sinkFile \t sinkLine \t sinkMethod \t srcFile \t srcLine \t srcMethod
import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*

@main def exec(cpgFile: String, lang: String, outFile: String, wide: String = "false", sanitize: String = "false"): Unit = {
  importCpg(cpgFile)
  val isWide = wide == "true"
  val sanRe = "(?is).*(escape|encode|sanitiz|htmlspecialchars|purif|antisamy|quote|neutraliz|whitelist|allowlist|isValid|matches\\().*"

  // ---------- sources ----------
  def pySources = cpg.call.code("(flask\\.)?request\\.(args|form|json|values|data|cookies|headers|files|GET|POST|body|FILES|META|query_params).*").l ++
    cpg.call.name("get_json|getlist").code(".*request.*").l ++
    cpg.call.code("request\\.(get_json|get_data)\\(.*").l
  def pyWide = cpg.method.isExternal(false).filterNot(_.name.startsWith("<")).filterNot(_.name.startsWith("_")).parameter.filterNot(p => p.name == "self" || p.name == "cls").l
  def jsSources = cpg.call.code("(req|request)\\.(query|body|params|cookies|headers|files)\\b.*").l ++
    cpg.call.code("(req|request)\\.(get|header)\\(.*").l
  def javaSources = cpg.call.name("getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getRequestURI|getRequestURL|getPathInfo|getPart|getParts|getAttribute").l ++
    cpg.parameter.where(_.annotation.name("RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|RequestPart|QueryParam|PathParam|FormParam|HeaderParam|CookieParam")).l ++
    cpg.parameter.typeFullNameExact("org.springframework.web.multipart.MultipartFile").l
  def sources: List[CfgNode] = lang match {
    case "py"   => (if (isWide) pyWide.l ++ pySources else pySources).collect { case c: CfgNode => c }
    case "js"   => jsSources.collect { case c: CfgNode => c }
    case _      => javaSources.collect { case c: CfgNode => c }
  }

  // ---------- sinks: class -> nodes ----------
  def argsOf(calls: Iterator[Call]): List[CfgNode] = calls.argument.l.collect { case c: CfgNode => c }
  // first real argument only (e.g. the SQL text of a JDBC call), so bound parameters are not treated as the sink
  def arg1(calls: Iterator[Call]): List[CfgNode] = calls.argument(1).l.collect { case c: CfgNode => c }
  def mfn1(re: String): List[CfgNode] = arg1(cpg.call.methodFullName(re))
  def pySinks: Map[String, List[CfgNode]] = Map(
    "sql-injection"   -> arg1(cpg.call.name("execute|executemany|executescript|raw|extra|text|read_sql|read_sql_query").filterNot(_.code.startsWith("<"))),
    "command-injection" -> argsOf(cpg.call.name("system|popen|call|check_call|check_output|Popen|run|getoutput|getstatusoutput|spawn.*").code(".*(os|subprocess|commands|sh)\\..*")),
    "code-injection"  -> argsOf(cpg.call.name("eval|exec|compile")),
    "deserialization" -> argsOf(cpg.call.name("loads|load|unsafe_load|Unpickler").code(".*(pickle|yaml|marshal|dill|jsonpickle|shelve)\\..*")),
    "ssrf"            -> argsOf(cpg.call.name("get|post|put|delete|request|urlopen|urlretrieve").code(".*(requests|urllib|httpx|http)\\..*")),
    "path-traversal"  -> argsOf(cpg.call.name("open|send_file|send_from_directory|FileResponse|remove|unlink|rmtree").filterNot(_.code.startsWith("<"))),
    "open-redirect"   -> argsOf(cpg.call.name("redirect|HttpResponseRedirect|HttpResponsePermanentRedirect")),
    "xxe"             -> argsOf(cpg.call.name("fromstring|parse|XMLParser|parseString|XML").code(".*(etree|ElementTree|minidom|lxml|xml)\\..*")),
    "ssti"            -> argsOf(cpg.call.name("render_template_string|from_string|Template")),
    "xss"             -> argsOf(cpg.call.name("Markup|mark_safe|HttpResponse|make_response|SafeString"))
  )
  def jsSinks: Map[String, List[CfgNode]] = Map(
    "eval-injection"    -> argsOf(cpg.call.name("eval|Function|setTimeout|setInterval|runInNewContext|runInThisContext")),
    "command-injection" -> argsOf(cpg.call.name("exec|execSync|spawn|spawnSync|execFile|execFileSync")),
    "nosql-injection"   -> (argsOf(cpg.call.name("find|findOne|findOneAndUpdate|update|updateOne|updateMany|remove|deleteOne|deleteMany|aggregate|count|countDocuments")) ++
                            argsOf(cpg.call.code(".*\\$where.*"))),
    "sql-injection"     -> argsOf(cpg.call.name("query|raw|execute|all|get|run").code(".*(db|sql|connection|knex|pool|client)\\..*")),
    "ssrf"              -> argsOf(cpg.call.name("get|post|request|fetch|needle|axios|urlopen").code(".*(request|needle|axios|http|https|fetch|got)\\b.*")),
    "open-redirect"     -> argsOf(cpg.call.name("redirect")),
    "path-traversal"    -> argsOf(cpg.call.name("readFile|readFileSync|sendFile|createReadStream|writeFile|writeFileSync|unlink|download")),
    "xss"               -> argsOf(cpg.call.name("send|write|end|html")).filter(_ => true),
    "deserialization"   -> argsOf(cpg.call.name("unserialize|deserialize|load|safeLoad").code(".*(serialize|yaml).*"))
  )
  def mfn(re: String): List[CfgNode] = argsOf(cpg.call.methodFullName(re))
  def javaSinks: Map[String, List[CfgNode]] = Map(
    "sql-injection"     -> (arg1(cpg.call.name("executeQuery|executeUpdate|execute|executeLargeUpdate|addBatch|prepareStatement|prepareCall|createQuery|createNativeQuery|queryForObject|queryForList|queryForMap|query|update|batchUpdate")) ++
                            mfn1("(java\\.sql|javax\\.sql|org\\.springframework\\.jdbc|javax\\.persistence|jakarta\\.persistence|org\\.hibernate)\\..*\\.(execute.*|prepare.*|query.*|update|batchUpdate|create.*Query|addBatch):.*")),
    "command-injection" -> mfn("java\\.lang\\.(ProcessBuilder\\.(<init>|command)|Runtime\\.exec).*"),
    "path-traversal"    -> (mfn("java\\.io\\.(File|FileInputStream|FileReader|FileOutputStream|FileWriter|RandomAccessFile)\\.<init>.*") ++
                            mfn("java\\.nio\\.file\\.(Paths\\.get|Path\\.of|Files\\.(read|write|new|copy|delete|create|list|walk|lines|exists).*).*") ++
                            mfn("org\\.springframework\\.core\\.io\\..*Resource.*<init>.*|java\\.lang\\.Class\\.getResource.*|java\\.lang\\.ClassLoader\\.getResource.*")),
    "xss"               -> argsOf(cpg.call.name("println|print|write|append|printf|format|sendError")),
    "xxe"               -> (argsOf(cpg.call.name("parse|unmarshal|createXMLStreamReader|createXMLEventReader|transform|build|read|evaluate|readFromString|newDocumentBuilder").code(".*(Parser|Builder|Reader|Unmarshaller|Transformer|SAX|DOM|XML|Digester|Jaxb|xml|dom).*")) ++
                            mfn("(javax\\.xml|org\\.xml|org\\.w3c|org\\.jdom|org\\.dom4j|jakarta\\.xml)\\..*\\.(parse|unmarshal|createXML.*|transform|build|read|evaluate|newDocumentBuilder):.*")),
    "ldap-injection"    -> mfn(".*(ldap|Ldap|LDAP|javax\\.naming|springframework\\.ldap).*\\.(search|lookup|bind|authenticate|find|findOne|searchForObject|list):.*"),
    "ssrf"              -> (mfn("java\\.net\\.(URL|URI)\\.<init>.*") ++ mfn("java\\.net\\.URI\\.create.*") ++
                            mfn(".*(HttpClient|RestTemplate|WebClient|HttpGet|HttpPost|HttpPut|HttpURLConnection|OkHttp|Request)\\..*(<init>|execute|exchange|getFor.*|postFor.*|send|newCall|get|post|uri|url).*")),
    "deserialization"   -> (argsOf(cpg.call.name("readObject|readUnshared|readValue|fromXML|unserialize|load|loadAs")) ++ mfn("java\\.io\\.ObjectInputStream\\.<init>.*")),
    "open-redirect"     -> (argsOf(cpg.call.name("sendRedirect|RedirectView")) ++ argsOf(cpg.call.name("setHeader|addHeader").argument(1).code("(?i).*location.*").inCall)),
    "code-injection"    -> (argsOf(cpg.call.name("eval|evaluate|compileExpression|parseExpression|getValue|setValue").code(".*(Expression|Script|Ognl|OGNL|Spel|SpEL|Engine|engine).*")) ++
                            mfn("(javax\\.script|org\\.springframework\\.expression|ognl|groovy|org\\.mvel2|org\\.apache\\.commons\\.jexl).*\\.(eval|evaluate|parseExpression|getValue|compile.*|execute):.*"))
  )
  val sinkMap: Map[String, List[CfgNode]] = lang match { case "py" => pySinks; case "js" => jsSinks; case _ => javaSinks }
  // Spring responses: tainted value returned from a request-mapped method (reflected content)
  val retSinks: Map[String, List[CfgNode]] = if (lang == "java")
    Map("xss" -> cpg.method.where(_.annotation.name(".*Mapping")).ast.isReturn.l.collect { case c: CfgNode => c }) else Map()

  val src = sources
  val out = new java.io.PrintWriter(outFile)
  out.println(s"META\tsources\t${src.size}")
  val seen = scala.collection.mutable.Set[String]()
  (sinkMap.toList ++ retSinks.toList.map { case (k, v) => (k + "-ret", v) }).foreach { case (cls, sinks) =>
    out.println(s"META\tsinks:$cls\t${sinks.size}")
    if (sinks.nonEmpty && src.nonEmpty) {
      sinks.iterator.reachableByFlows(src.iterator).foreach { path =>
        val e = path.elements; val s = e.head; val t = e.last
        def f(n: AstNode) = { val l = n.location; l.filename + "\t" + l.lineNumber.getOrElse(-1) + "\t" + l.methodShortName }
        val key = cls + f(t) + f(s)
        val sanitized = sanitize == "true" && e.exists(el => el.code.matches(sanRe))
        if (!sanitized && seen.add(key)) out.println(s"FLOW\t${cls.stripSuffix("-ret")}\t${f(t)}\t${f(s)}")
      }
    }
  }
  out.close()
}
