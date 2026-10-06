@main def exec(cpgFile: String, filePat: String): Unit = {
  importCpg(cpgFile)
  cpg.call.where(_.file.name(filePat)).filterNot(_.name.startsWith("<operator>")).map(c => c.name + " | " + c.typeFullName + " | " + c.methodFullName).dedup.l.sorted.foreach(println)
}
