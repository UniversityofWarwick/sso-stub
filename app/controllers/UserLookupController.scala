package controllers

import domain.{AttributeConverter, Member}
import helpers.FormDataHelpers._
import play.api.mvc.{Action, AnyContent}
import services.FakeMemberService

import javax.inject.{Inject, Singleton}
import scala.language.postfixOps

@Singleton
class UserLookupController @Inject()() extends BaseController {

  @Inject
  private[this] var fakeMemberService: FakeMemberService = _

  private val HandledAttributes = Seq("sn", "mail", "cn", "warwickuniid")
  private def AllUsers: Seq[Member] = fakeMemberService.getStaff ++ fakeMemberService.getStudents

  implicit class WildcardableAttributesHelper(terms: Seq[String]) {
    def hasMatchWith(candidate: String): Boolean = {
      val uncasedCandidate = candidate.toLowerCase
      terms.exists { term =>
        val uncasedTerm = term.toLowerCase
        uncasedCandidate == uncasedTerm ||
          (term.endsWith("*") && uncasedCandidate.startsWith(uncasedTerm.replaceFirst("\\*$", "")))
      }
    }
  }

  def userSearch(): Action[AnyContent] = Action { implicit request =>
    val formData: FormData = request.body.asFormUrlEncoded.getOrElse(request.queryString)
    val count = formData.getInt("numberOfResults", 100)
    val attributeFilters = HandledAttributes.map(k => k -> formData.getStrings(s"f_$k")).filter { case (_, v) => v.nonEmpty }

    if (attributeFilters.isEmpty || count == 0) {
      // fail fast
      Ok(views.xml.userSearch(Seq.empty))
    } else {
      val filteredUsers = AllUsers.filter { user =>
        attributeFilters.exists {
          case ("sn", value) =>
            value.hasMatchWith(user.familyName)

          case ("mail", value) =>
            value.hasMatchWith(user.mail)

          case ("cn", value) =>
            value.hasMatchWith(user.userCode)

          case ("warwickuniid", value) =>
            value.hasMatchWith(user.universityId)

          case (key, value) =>
            logger.info(s"userSearch request for unhandled attribute $key, with value $value")
            false
        }
      }

      val users = filteredUsers.map(member => AttributeConverter.toUserSearchAttributes(fakeMemberService.getResponseFor(member))).take(count)
      Ok(views.xml.userSearch(users))
    }
  }
}
