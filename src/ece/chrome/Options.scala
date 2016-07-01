package ece.chrome;

import ece.Utils
import java.security.PublicKey

class Options(
  val sharedSecret: Array[Byte],
  val salt: Array[Byte],
  val senderPublicKey: PublicKey,
  val receiverPublicKey: PublicKey,
  val clientAuthToken: Array[Byte],
  val recordSize: Int = Utils.DefaultRecordSize,
  val padSize: Int = Utils.DefaultPadSize,
  val context: Array[Byte] = Array.emptyByteArray
)
