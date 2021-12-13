package controllers

import com.sun.org.apache.xml.internal.security.signature.XMLSignature
import domain.{AttributeConverter, Member}
import helpers.FormDataHelpers._
import org.apache.xml.security.c14n.Canonicalizer
import org.opensaml._
import org.w3c.dom.Element
import play.api.Configuration
import play.api.data.Form
import play.api.data.Forms._
import play.api.mvc.{Action, AnyContent, Cookie, DiscardingCookie}
import services.FakeMemberService
import sun.security.tools.keytool.CertAndKeyGen
import sun.security.x509.X500Name

import java.util.{Collections, Date}
import javax.inject.{Inject, Singleton}
import scala.jdk.CollectionConverters._
import scala.language.postfixOps
import scala.xml.NodeSeq

@Singleton
class IndexController @Inject()(
  config: Configuration
) extends BaseController {

  val DEFAULT_QNAME_NAMESPACE = "urn:mace:shibboleth:1.0"
  val DEFAULT_QNAME_TYPE = "AttributeValueType"

  @Inject
  private[this] var fakeMemberService: FakeMemberService = _

  private val domain = config.getOptional[String]("app.domain")
  private val path = config.getOptional[String]("app.cookies.path").getOrElse("/")
  private val secure = config.getOptional[Boolean]("app.cookies.secure").getOrElse(false)
  private val httpOnly = config.getOptional[Boolean]("app.cookies.httpOnly").getOrElse(true)
  private val sameSite = Cookie.SameSite.parse(config.getOptional[String]("app.cookies.sameSite").getOrElse(""))

  def home: Action[AnyContent] = Action { implicit request =>
    Ok(views.html.home(fakeMemberService.getStaff, fakeMemberService.getStudents))
  }

  def redirectToPath(path: String, status: Int = MOVED_PERMANENTLY): Action[AnyContent] = Action {
    Redirect(s"/${path.replaceFirst("^/", "")}", status)
  }

  def hs(shire: String, providerId: String, target: String): Action[AnyContent] = Action { implicit request =>
    Ok(views.html.hs(shire, providerId, target, fakeMemberService.getStaff ++ fakeMemberService.getStudents))
  }

  val issuerId: String = "urn:mace:eduserv.org.uk:athens:provider:warwick.ac.uk"

  // TODO: Use form case class here
  def generateAcs(shire: String, providerId: String, target: String): Action[AnyContent] = Action { implicit request =>
    val userData = chosenUserForm.bindFromRequest().get
    val nameID = new SAMLNameIdentifier(userData.uniId, "", "urn:websignon:uuid")
    val response = SAMLPOSTProfile.prepare(shire, issuerId, Seq(providerId).asJava, nameID, request.ipAddress, "urn:oasis:names:tc:SAML:1.0:am:unspecified", new Date, null)
    Ok(views.html.acsPost(encode(response), shire, target))
  }

  private def encode(samlResponse: SAMLResponse) = {
    val certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null)
    certGen.generate(1024)
    val cert = certGen.getSelfCertificate(
      new X500Name("CN=sso-stub, O=The University of Warwick, OU=IT Services, ST=West Midlands, C=GB"), (365 * 24 * 3600).toLong)
    samlResponse.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, certGen.getPrivateKey, Seq(cert).asJava)
    val base64 = samlResponse.toBase64
    new String(base64, "ASCII")
  }

  def slogin(providerId: String, target: String): Action[AnyContent] = Action { implicit request =>
    Ok(views.html.slogin(providerId, target, fakeMemberService.getStaff ++ fakeMemberService.getStudents))
  }

  def performOldMode(providerId: String, target: String): Action[AnyContent] = Action { implicit request =>
    val userData = chosenUserForm.bindFromRequest().get
    Redirect(target).withCookies(Cookie(name = "WarwickSSO", value = userData.uniId, domain = domain, path = path, secure = secure, httpOnly = httpOnly, sameSite = sameSite))
  }

  case class ChosenUser(uniId: String)

  val chosenUserForm: Form[ChosenUser] = Form(
    mapping(
      "uniId" -> text
    )(ChosenUser.apply)(ChosenUser.unapply)
  )

  def respondToAa(): Action[NodeSeq] = Action(parse.xml) { request =>
    val name = (request.body \\ "Envelope" \\ "Body" \\ "Request" \\ "AttributeQuery" \\ "Subject" \\ "NameIdentifier" headOption).map(_.text)
    val providerId = (request.body \\ "Envelope" \\ "Body" \\ "Request" \\ "AttributeQuery" \\ "@Resource" headOption).map(_.text)
    val reqId = (request.body \\ "Envelope" \\ "Body" \\ "Request" \\ "@RequestID" headOption).map(_.text)
    val member = (fakeMemberService.getStaff ++ fakeMemberService.getStudents).filter(m => m.universityId == name.get).head

    val attributes: Seq[SAMLAttribute] = AttributeConverter.toAttributes(fakeMemberService.getResponseFor(member), oldMode = false).toList map {
      case (name: String, value: String) =>
        new SAMLAttribute(
          name,
          "urn:mace:shibboleth:1.0:attributeNamespace:uri",
          new QName(DEFAULT_QNAME_NAMESPACE, DEFAULT_QNAME_TYPE),
          3600L,
          Seq(value).asJava
        )
    }

    val nameID = new SAMLNameIdentifier(name.get, "", "urn:websignon:uuid")
    val confirmationMethod: Seq[String] = Seq[String]("urn:oasis:names:tc:SAML:1.0:cm:bearer")

    val samlSubject: SAMLSubject = new SAMLSubject(nameID, confirmationMethod.toList.asJava, null.asInstanceOf[Element], null)

    val statement = new SAMLAttributeStatement(samlSubject, attributes.asJava)
    val condition = new SAMLAudienceRestrictionCondition(Seq(providerId.get).asJava)
    val notBefore = new Date
    val defaultTimeout = 60000
    val notOnOrAfter = new Date(notBefore.getTime + defaultTimeout)
    // is in seconds
    val sAssertion = new SAMLAssertion(issuerId, notBefore, notOnOrAfter, Collections.singleton(condition), null, Collections.singleton(statement))
    val samlResponse = new SAMLResponse(reqId.get, null, Collections.singleton(sAssertion), null)
    val document = samlResponse.toDOM().getOwnerDocument
    val soapEnvelope = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soap:Envelope")
    soapEnvelope.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:soap", "http://schemas.xmlsoap.org/soap/envelope/")
    soapEnvelope.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    soapEnvelope.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    document.appendChild(soapEnvelope)
    val soapBody = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soap:Body")
    soapEnvelope.appendChild(soapBody)
    soapBody.appendChild(samlResponse.toDOM)
    val canonicalizer = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

    Ok(scala.xml.XML.loadString(new String(canonicalizer.canonicalizeSubtree(soapEnvelope))))
  }

  private def sentryLookup(requestType: String, memberFilter: Member => Boolean) = {
    // wtf, Adam
    val members = (fakeMemberService.getStaff ++ fakeMemberService.getStudents).filter(memberFilter)

    if(members.isEmpty) {
      Ok("returnType=5" + requestType)
    }
    else {
      val response = fakeMemberService.getResponseFor(members.head)
      val attributes = AttributeConverter.toAttributes(response, oldMode = true)
      Ok("returnType=" + requestType + "\nid=" + members.head.universityId + "\n" + attributes.map(_.productIterator.mkString("=")).mkString("\n"))
    }
  }

  def respondToSentry(requestType: Int, user: Option[String]): Action[AnyContent] = Action { implicit request =>
    val formData: Option[FormData] = request.body.asFormUrlEncoded

    requestType match {
      case 1 if request.method == "POST" && formData.has("token") =>
        sentryLookup("1", _.universityId == formData.getString("token"))

      case 2 if request.method == "POST" && formData.has("user") && formData.has("pass") =>
        sentryLookup("2", _.userCode == formData.getString("user"))

      case 4 if request.method == "POST" && formData.has("user") =>
        sentryLookup("4", _.userCode == formData.getString("user"))

      case 4 if user.nonEmpty =>
        sentryLookup("4", _.userCode == user.get)

      case _ => BadRequest
    }
  }

  def logout(target: String): Action[AnyContent] = Action { implicit request =>
    val ssoCookieCandidateNames = Seq("WarwickSSO", "SSO-LTC") ++ request.cookies.collect { case c if c.name.contains("SSO-SSC") => c.name }
    val ssoCookieCandidates = ssoCookieCandidateNames.map(name => DiscardingCookie(name = name, domain = domain, path = path, secure = secure))
    Redirect(target).discardingCookies(ssoCookieCandidates: _*)
  }
}
