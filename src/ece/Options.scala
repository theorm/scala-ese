package ece;

class Options(
  val secret: Array[Byte],
  val salt: Array[Byte],
  val recordSize: Int = Utils.DefaultRecordSize,
  val padSize: Int = Utils.DefaultPadSize
)
