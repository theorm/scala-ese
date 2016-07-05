package ece.firefox;

import ece.Utils

class Options(
  val secret: Array[Byte],
  val salt: Array[Byte],
  val recordSize: Int = Utils.DefaultRecordSize,
  val padSize: Int = Utils.DefaultPadSize,
  val context: Array[Byte] = Array.emptyByteArray
)
