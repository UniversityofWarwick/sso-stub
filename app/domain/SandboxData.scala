package domain

import uk.co.halfninja.randomnames.Gender.{female, male, nonspecific}
import uk.co.halfninja.randomnames.{CompositeNameGenerator, Name, NameGenerators}

// scalastyle:off magic.number
object SandboxData {
  final val NameGenerator: CompositeNameGenerator = NameGenerators.standardGenerator()
  type NameGender = uk.co.halfninja.randomnames.Gender

  final val Departments = Map(
    "arc" -> Department("School of Architecture", "arc", "S", Map(
      "arc101" -> Module("Introduction to Architecture", "INTROARC", "arc101"),
      "arc102" -> Module("Architectural Design 1", "ARCDES1", "arc102"),
      "arc103" -> Module("Introduction to Architectural History", "INTROARCH", "arc103"),
      "arc106" -> Module("Architectural Technology 1", "ARCTECH1", "arc106"),
      "arc115" -> Module("20th Century Architecture", "ARCTECH20", "arc115"),
      "arc129" -> Module("Environmental Design and Services", "ENVDESSERV", "arc129"),
      "arc201" -> Module("Architectural Technology 2", "ARCTECH2", "arc201"),
      "arc203" -> Module("Professional Practice and Management", "PPM", "arc203"),
      "arc204" -> Module("Principles and Theories of Architecture", "PTA", "arc204"),
      "arc210" -> Module("The Place of Houses", "PAH", "arc210"),
      "arc219" -> Module("Tectonic Practice", "TECPRA", "arc219"),
      "arc222" -> Module("Sustainable Principles", "SUVPRI", "arc222"),
      "arc3a1" -> Module("Integrating Technology", "INTGTECH", "arc3a1"),
      "arc330" -> Module("History of Modern Architecture", "HMTEC", "arc330"),
      "arc339" -> Module("Dissertation (Architecture)", "SISARC", "arc339")
    ), Map(
      "ac801" ->
        Route("Architecture", "ac801", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("arc101", "arc102", "arc103", "arc106", "arc115", "arc129", "arc201",
            "arc203", "arc204", "arc210", "arc219", "arc222", "arc3a1", "arc330", "arc339"),
          4200001, 4200100),
      "ac802" ->
        Route("Architecture with Intercalated Year", "ac802", DegreeType.Undergraduate, CourseType.UG, awardCode = "MBCHB", isResearch = false,
          Seq("arc101", "arc102", "arc103", "arc106", "arc115", "arc129", "arc201",
            "arc203", "arc204", "arc210", "arc219", "arc222", "arc3a1", "arc330", "arc339"),
          4200101, 4200130),
      "ac8p0" ->
        Route("Architecture (Research)", "ac8p0", DegreeType.Postgraduate, CourseType.PGR, awardCode = "PHD", isResearch = true, Seq(), 4200201, 4200300),
      "ac8p1" ->
        Route("Architecture (Taught)", "ac8p1", DegreeType.Postgraduate, CourseType.PGT, awardCode = "MA", isResearch = false,
          Seq("arc222", "arc3a1", "arc330"),
          4200301, 4200350)
    ), 5200001, 5200030),
    "hom" -> Department("History of Music", "hom", "A", Map(
      "hom101" -> Module("History of Musical Techniques", "HOM101", "hom101"),
      "hom102" -> Module("Introduction to Ethnomusicology", "HOM102", "hom102"),
      "hom103" -> Module("The Long Nineteenth Century", "HOM103", "hom103"),
      "hom106" -> Module("History of Composition", "HOM106", "hom106"),
      "hom115" -> Module("20th Century Music", "HOM115", "hom115"),
      "hom129" -> Module("Theory and Analysis", "HOM129", "hom129"),
      "hom201" -> Module("Russian and Soviet Music, 1890-1975", "HOM201", "hom201"),
      "hom203" -> Module("Studies in Popular Music", "HOM203", "hom203"),
      "hom204" -> Module("History of Opera", "HOM204", "hom204"),
      "hom210" -> Module("Writing Practices in Music", "HOM210", "hom210"),
      "hom219" -> Module("Popular Music and Theories of Mass Culture", "HOM222", "hom219"),
      "hom222" -> Module("Late 19th and Early 20th Century English Song", "HOM222", "hom222"),
      "hom3a1" -> Module("Britten's Chamber Operas", "HOM3A1", "hom3a1"),
      "hom330" -> Module("Influences of Hip-hop on Popular Culture", "HOM330", "hom330"),
      "hom339" -> Module("Dissertation (History of Music)", "HOM339", "hom339")
    ), Map(
      "hm801" ->
        Route("History of Music", "hm801", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("hom101", "hom102", "hom103", "hom106", "hom115", "hom129", "hom201",
            "hom203", "hom204", "hom210", "hom219", "hom222", "hom3a1", "hom330", "hom339"),
          4300001, 4300100),
      "hm802" ->
        Route("History of Music with Intercalated Year", "hm802", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("hom101", "hom102", "hom103", "hom106", "hom115", "hom129", "hom201",
            "hom203", "hom204", "hom210", "hom219", "hom222", "hom3a1", "hom330", "hom339"),
          4300101, 4300130),
      "hm8p0" ->
        Route("History of Music (Research)", "hm8p0", DegreeType.Postgraduate, CourseType.PGR, awardCode = "PHD", isResearch = true, Seq(), 4300201, 4300300),
      "hm8p1" ->
        Route("History of Music (Taught)", "hm8p1", DegreeType.Postgraduate, CourseType.PGT, awardCode = "MA", isResearch = false,
          Seq("hom222", "hom3a1", "hom330"),
          4300301, 4300350)
    ), 5300001, 5300030),
    "psp" -> Department("Public Speaking", "psp", "I", Map(
      "psp101" -> Module("Pronunciation and Enunciation", "PSP101", "psp101"),
      "psp102" -> Module("Professional Speaking", "PSP102", "psp102")
    ), Map(
      "xp301" ->
        Route("Public Speaking", "xp301", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("psp101", "psp102"),
          4400001, 4400100),
      "xp302" ->
        Route("Public Speaking with Intercalated Year", "xp302", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("psp101", "psp102"),
          4400101, 4400130),
      "xp3p0" ->
        Route("Public Speaking (Research)", "xp3p0", DegreeType.Postgraduate, CourseType.PGR, awardCode = "PHD", isResearch = true, Seq(), 4400201, 4400300),
      "xp3p1" ->
        Route("Public Speaking (Taught)", "xp3p1", DegreeType.Postgraduate, CourseType.PGT, awardCode = "MA", isResearch = false, Seq(), 4400301, 4400350)
    ), 5400001, 5400030),
    "trn" -> Department("Training Methods", "trn", "I", Map(
      "trn101" -> Module("Introduction to Tabula Training", "INT-TAB-TRNG", "trn101"),
      "trn102" -> Module("Advanced Sitebuilder Training", "ADV-SB-TRNG", "trn102")
    ), Map(
      "tr301" ->
        Route("Training Methods", "tr301", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("trn101", "trn102"),
          4500001, 4500100),
      "tr302" ->
        Route("Training Methods with Intercalated Year", "tr302", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("trn101", "trn102"),
          4500101, 4500130),
      "tr3p0" ->
        Route("Training Methods (Research)", "tr3p0", DegreeType.Postgraduate, CourseType.PGR, awardCode = "PHD", isResearch = true, Seq(), 4500201, 4500300),
      "tr3p1" ->
        Route("Training Methods (Taught)", "tr3p1", DegreeType.Postgraduate, CourseType.PGT, awardCode = "MA", isResearch = false, Seq(), 4500301, 4500350)
    ), 5500001, 5500030),
    "tss" -> Department("School of Tabula Sandbox Studies", "tss", "T", Map(
      "tss101" -> Module("Introduction to Permissions", "TSS101", "tss101"),
      "tss102" -> Module("Coursework Management 1", "TSS102", "tss102"),
      "tss103" -> Module("Introduction to Student Profiles", "TSS103", "tss103"),
      "tss106" -> Module("Small Group Teaching 1", "TSS106", "tss106"),
      "tss115" -> Module("Timetabling Students", "TSS115", "tss115"),
      "tss129" -> Module("Exam Management and Grids", "TSS129", "tss129"),
      "tss201" -> Module("Coursework Management 2", "TSS201", "tss201"),
      "tss203" -> Module("Management of Monitoring Point Schemes and Points", "TSS203", "tss203"),
      "tss204" -> Module("Principles of Student Relationships", "TSS204", "tss204"),
      "tss210" -> Module("Advanced Marks Management", "TSS210", "tss210"),
      "tss219" -> Module("Marking Descriptors", "TSS219", "tss219"),
      "tss222" -> Module("Sustainable Reports", "TSS222", "tss222"),
      "tss3a1" -> Module("Departmental Small Group Sets", "TSS3A1", "tss3a1"),
      "tss330" -> Module("History of Tabula Development", "TSS330", "tss330"),
      "tss339" -> Module("Dissertation (Sandbox Studies)", "TSS339", "tss339")
    ), Map(
      "ts801" ->
        Route("Sandbox Studies", "ts801", DegreeType.Undergraduate, CourseType.UG, awardCode = "BA", isResearch = false,
          Seq("tss101", "tss102", "tss103", "tss106", "tss115", "tss129", "tss201",
            "tss203", "tss204", "tss210", "tss219", "tss222", "tss3a1", "tss330", "tss339"),
          4600001, 4600100),
      "ts802" ->
        Route("Sandbox Studies with Intercalated Year", "ts802", DegreeType.Undergraduate, CourseType.UG, awardCode = "MBCHB", isResearch = false,
          Seq("tss101", "tss102", "tss103", "tss106", "tss115", "tss129", "tss201",
            "tss203", "tss204", "tss210", "tss219", "tss222", "tss3a1", "tss330", "tss339"),
          4600101, 4600130),
      "ts8p0" ->
        Route("Sandbox Studies (Research)", "ts8p0", DegreeType.Postgraduate, CourseType.PGR, awardCode = "PHD", isResearch = true, Seq(), 4600201, 4600300),
      "ts8p1" ->
        Route("Sandbox Studies (Taught)", "ts8p1", DegreeType.Postgraduate, CourseType.PGT, awardCode = "MA", isResearch = false,
          Seq("tss222", "tss3a1", "tss330"),
          4600301, 4600350)
    ), 5600001, 5600030)
  )

  final val IDG = Department("An Information and Digital Group", "IN", "", Map.empty, Map.empty, 5900001, 5900020)
  final val PredictableMembers = Seq(
    BasicMember("functest_admin", "WarwickADS", IDG, "Functest", "Admin", true, "no-reply@warwick.ac.uk", "University staff", "5900001"),
    BasicMember("functest_contributor", "WarwickADS", IDG, "Functest", "Contributor", true, "no-reply@warwick.ac.uk", "University staff", "5900002")
  )

  def randomName(id: Long, gender: domain.Gender): Name = {
    val nameGender = gender match {
      case domain.Gender.Male => male
      case domain.Gender.Female => female
      case _ => nonspecific
    }

    NameGenerator.generate(nameGender, id)
  }

  def route(id: Long): Route =
    Departments
      .flatMap { case (_, d) => d.routes }
      .find { case (_, r) => r.studentsStartId <= id && r.studentsEndId >= id }
      .map { case (_, r) => r }
      .get

  case class Department(
    name: String,
    code: String,
    facultyCode: String,
    modules: Map[String, Module],
    routes: Map[String, Route],
    staffStartId: Int,
    staffEndId: Int
  )

  case class Module(name: String, shortName: String, code: String)

  case class Route(
    name: String,
    code: String,
    degreeType: DegreeType,
    courseType: CourseType,
    awardCode: String,
    isResearch: Boolean,
    moduleCodes: Seq[String],
    studentsStartId: Int,
    studentsEndId: Int
  )

}
