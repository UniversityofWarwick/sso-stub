package helpers

import play.api.data

object FormDataHelpers {
  private def toInt(s: String): Option[Int] = try { Some(s.toInt) } catch { case _: Exception => None }

  type FormData = Map[String, Seq[String]]
  implicit class FormDataHelper(data: FormData) {
    def has(key: String): Boolean =
      data.get(key).nonEmpty

    def getInt(key: String, default: Int = Int.MaxValue): Int =
      data.getOrElse(key, Seq.empty)
        .headOption
        .flatMap(toInt)
        .getOrElse(default)

    def getString(key: String, default: String = ""): String =
      data.getOrElse(key, Seq.empty)
        .headOption
        .getOrElse(default)

    def getStrings(key: String): Seq[String] =
      data.getOrElse(key, Seq.empty)
  }
  implicit class OptionalFormDataHelper(optData: Option[FormData]) {
    def get: FormData = optData.getOrElse(Map.empty)

    def has(key: String): Boolean =
      get(key).nonEmpty

    def getInt(key: String, default: Int = Int.MaxValue): Int =
      get.getInt(key, default)

    def getString(key: String, default: String = ""): String =
      get.getString(key, default)

    def getStrings(key: String): Seq[String] =
      get.getStrings(key)
  }
}
