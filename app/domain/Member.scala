package domain

import java.time.Instant

import domain.SandboxData.Department

abstract class Member {
  def userCode: String

  def userSource: String

  def department: Department

  def givenName: String

  def familyName: String

  def warwickPrimary: Boolean

  def mail: String

  def warwickTargetGroup: String

  def universityId: String
}

case class BasicMember(userCode: String,
  userSource: String,
  department: Department,
  givenName: String,
  familyName: String,
  warwickPrimary: Boolean,
  mail: String,
  warwickTargetGroup: String,
  universityId: String) extends Member

case class MemberAuthorityResponse(userCode: String,
  userSource: String,
  department: Department,
  givenName: String,
  familyName: String,
  warwickPrimary: Boolean,
  mail: String,
  warwickTargetGroup: String,
  universityId: String,
  ssc: String,
  pgt: String,
  fedMember: Boolean,
  athens: Boolean,
  lastPasswordChange: Instant,
  memberEduTypeAffiliation: MemberEduTypeAffiliation,
  ipAddress: String,
  itsClass: WarwickItsClass,
  title: String // todo; do students have a title?
) extends Member

sealed abstract class MemberEduTypeAffiliation(val value: String)

object MemberEduTypeAffiliation {

  case object Faculty extends MemberEduTypeAffiliation("faculty")

  case object Student extends MemberEduTypeAffiliation("student")

  case object Staff extends MemberEduTypeAffiliation("staff")

  case object Alumni extends MemberEduTypeAffiliation("alum")

  case object Member extends MemberEduTypeAffiliation("member")

  case object Affiliate extends MemberEduTypeAffiliation("affiliate")

  case object LibraryWalkIn extends MemberEduTypeAffiliation("library-walk-in")

}

sealed abstract class WarwickItsClass(val value: String)

object WarwickItsClass {

  case object Staff extends WarwickItsClass("Staff")

  case object UG extends WarwickItsClass("UG")

  case object PGT extends WarwickItsClass("PG(T)")

  case object PGR extends WarwickItsClass("PG(R)")

  case object Alumni extends WarwickItsClass("Alumni")

  case object Applicant extends WarwickItsClass("Applicant")

}

object AttributeConverter {
  def isStaff(r: MemberAuthorityResponse): Boolean = r.itsClass == WarwickItsClass.Staff || r.itsClass == WarwickItsClass.PGR
  def isStudent(r: MemberAuthorityResponse): Boolean = r.itsClass != WarwickItsClass.Staff && r.itsClass != WarwickItsClass.PGR

  def toUserSearchAttributes(r: MemberAuthorityResponse): Map[String, String] = Map(
    "mail" -> r.mail,
    "student" -> isStudent(r).toString,
    "ou" -> r.department.name,
    "givenname" -> r.givenName,
    "warwickdeptcode" -> r.department.code,
    "staff" -> isStaff(r).toString,
    "cn" -> r.userCode,
    "deptshort" -> r.department.name,
    "warwickuniid" -> r.universityId,
    "passwordexpired" -> "false",
    "warwickprimary" -> "true",
    "sn" -> r.familyName,
    "logindisabled" -> "false",
    "department" -> r.department.name,
    "urn:websignon:usertype" -> r.memberEduTypeAffiliation.toString,
    "warwicktargetgroup" -> r.warwickTargetGroup
  )

  def toAttributes(r: MemberAuthorityResponse, oldMode: Boolean): Map[String, String] = {

    val attribs = Map[String, String](
      (if (oldMode) "email" else "mail") -> r.mail,
      "urn:websignon:ipaddress" -> r.ipAddress,
      "urn:websignon:passwordlastchanged" -> r.lastPasswordChange.toString, // Must be iso 8601!
      (if (oldMode) "token" else "urn:websignon:ssc") -> r.ssc,
      "warwicktargetgroup" -> r.warwickTargetGroup,
      "warwickitsclass" -> r.itsClass.value,
      "urn:websignon:loggedin" -> "true",
      (if (oldMode) "dept" else "ou") -> r.department.name,
      "deptshort" -> r.department.name,
      "urn:websignon:usersource" -> r.userSource,
      "staff" -> isStaff(r).toString,
      "student" -> isStudent(r).toString,
      (if (oldMode) "id" else "warwickuniid") -> r.universityId,
      (if (oldMode) "deptCode" else "warwickdeptcode") -> r.department.code,
      "warwickprimary" -> (if (r.warwickPrimary) "Yes" else "No"),
      (if (oldMode) "firstname" else "givenName") -> r.givenName,
      (if (oldMode) "lastname" else "sn") -> r.familyName,
      "title" -> r.title,
      "passwordexpired" -> "FALSE",
      "user" -> r.userCode
    )

    if (oldMode)
      attribs + ("name" -> (r.givenName + " " + r.familyName), "member" -> (isStaff(r) || isStudent(r)).toString)
    else {
      // We can assume everyone is either staff of student
      val dn = s"CN=${r.userCode},OU=${if (isStaff(r)) "Staff" else "Student"},OU=CU,OU=WARWICK,DC=ads,DC=warwick,DC=ac,DC=uk"
      attribs + ("cn" -> r.userCode, "dn" -> dn)
    }
  }
}
