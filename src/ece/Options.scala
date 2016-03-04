package ece;

class Options(
  val secret: Array[Byte],
  val salt: Array[Byte],
  val recordSize: Option[Int] = Some(Utils.DefaultRecordSize)
)
