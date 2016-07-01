package ece.chrome

// import ece.{Utils, EncryptedContext}
import ece.EncryptedContext
import scala.util.Try

object Codec {
  def encryptForReceiver(data: Array[Byte], receiverPubKeyBase64: String, receiverAuthBase64: String, saltBase64: Option[String]): Try[EncryptedContext] = {
    Try {
      new EncryptedContext(Array.emptyByteArray, "", "")
    }
  }
}
