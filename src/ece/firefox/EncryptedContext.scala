package ece.firefox

class EncryptedContext(
  val cipherText: Array[Byte],
  val senderPubKeyBase64: String,
  val seedBase64: String
)
