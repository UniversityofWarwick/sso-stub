package services

import java.time.Instant

import com.google.inject.{ImplementedBy, Singleton}
import domain.{Gender, Member, MemberAuthorityResponse, MemberEduTypeAffiliation, SandboxData, WarwickItsClass}
import domain.SandboxData.Department

@ImplementedBy(classOf[FakeMemberServiceImpl])
trait FakeMemberService {
  def getStaff: Seq[Member]

  def getStudents: Seq[Member]

  def getResponseFor(member: Member): MemberAuthorityResponse
}

@Singleton
class FakeMemberServiceImpl extends FakeMemberService {
  override def getStaff: Seq[Member] = {
    val depts = SandboxData.Departments.values
    val mappedDepts: Iterable[Seq[(Department, Member)]] = depts.map(d => {
      val range: Seq[Int] = d.staffStartId to d.staffEndId
      range.map(ri => {
        val name = SandboxData.randomName(ri.longValue(), if (ri % 2 == 0) Gender.Male else Gender.Female)
        val userCode = "in-sso-stub-" + ri
        (d, domain.BasicMember(
          userCode,
          "WarwickADS",
          d,
          givenName = name.givenName,
          familyName = name.familyName,
          warwickPrimary = true,
          mail = "sso-stub-" + userCode + "@tempinbox.com",
          warwickTargetGroup = "University staff",
          universityId = ri.toString
        ))
      })
    })
    mappedDepts.flatten.map(t => t._2).toSeq ++ SandboxData.PredictableMembers
  }

  override def getResponseFor(member: Member): MemberAuthorityResponse = MemberAuthorityResponse(
    userCode = member.userCode,
    userSource = member.userSource,
    department = member.department,
    givenName = member.givenName,
    familyName = member.familyName,
    warwickPrimary = member.warwickPrimary,
    mail = member.mail,
    warwickTargetGroup = member.warwickTargetGroup,
    universityId = member.universityId,
    ssc = member.universityId,
    fedMember = true,
    pgt = "sometoken",
    athens = true,
    lastPasswordChange = Instant.now,
    memberEduTypeAffiliation = mapMemberToEduAffiliation(member),
    ipAddress = "127.0.0.1",
    itsClass = mapMemberToItsClass(member),
    title = member.warwickTargetGroup
  )

  private def mapMemberToItsClass(member: Member): WarwickItsClass = {
    if (member.warwickTargetGroup.contains("Undergraduate"))
      WarwickItsClass.UG
    else if (member.warwickTargetGroup.contains("Postgraduate (research) FT"))
      WarwickItsClass.PGR
    else
      WarwickItsClass.Staff
  }

  private def mapMemberToEduAffiliation(member: Member): MemberEduTypeAffiliation = {
    if (member.warwickTargetGroup.contains("Undergraduate"))
      MemberEduTypeAffiliation.Student
    else
      MemberEduTypeAffiliation.Staff
  }

  override def getStudents: Seq[Member] = {
    val depts = SandboxData.Departments.values
    val mappedDepts: Iterable[Seq[(Department, Member)]] = depts.map(d => {
      d.routes.map(route => {
        val start = route._2.studentsStartId
        val end = route._2.studentsEndId
        val isPg = route._2.isResearch
        val range: Seq[Int] = start to end
        range.map(ri => {
          val name = SandboxData.randomName(ri.longValue(), if (ri % 2 == 0) Gender.Male else Gender.Female)
          val userCode = "u" + ri
          (d, new domain.BasicMember(
            userCode,
            "WarwickADS",
            d,
            givenName = name.givenName,
            familyName = name.familyName,
            warwickPrimary = true,
            mail = "sso-stub-" + userCode + "@tempinbox.com",
            warwickTargetGroup = if (isPg) "Postgraduate (research) FT" else "Undergraduate - full-time",
            universityId = ri.toString
          ))
        })
      }).toSeq
    }.flatten)
    mappedDepts.flatten.map(t => t._2).toSeq
  }


}
