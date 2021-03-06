package domain

sealed abstract class Gender(val dbValue: String, val description: String)

object Gender {

  case object Male extends Gender("M", "Male")

  case object Female extends Gender("F", "Female")

  case object Other extends Gender("N", "Other")

  case object NonBinary extends Gender("B", "Non-Binary")

  case object Unspecified extends Gender("P", "Prefer not to say")

  def fromCode(code: String): Gender = code match {
    case Male.dbValue => Male
    case Female.dbValue => Female
    case Other.dbValue => Other
    case NonBinary.dbValue => NonBinary
    case Unspecified.dbValue => Unspecified
    case null => null
    case unrecognised => throw new IllegalArgumentException(unrecognised)
  }
}

