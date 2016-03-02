package ece;

class Options(
  val salt: String,
  val recordSize: Option[Int] = Some(Utils.DefaultRecordSize),
  val key: Option[Array[Byte]] = None,
  val dh: Option[String] = None,
  val keyId: Option[String] = None
)
