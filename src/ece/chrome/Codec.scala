package ece.chrome

import ece.{Utils, EncryptedContext}
import scala.util.Try
import org.apache.commons.codec.binary.Base64
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}

object Codec {
  val PRKLengthBytes = 32
  val EncryptionKeyLength = 16
  val NonceLength = 12
  val PublicKeyLength = 65

  val AuthInfo = "Content-Encoding: auth".toCharArray().map(_.toByte) ++
    Array.fill(1)(0.toChar).map(_.toByte)

  /**
   * Returns an info record. See sections 3.2 and 3.3 of
   * {@link https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00}
   *
   * A rip-off of
   * https://github.com/GoogleChrome/web-push-encryption/blob/master/src/encrypt.js
   */
  def buildInfo(t: String, context: Array[Byte]): Array[Byte] = {
    // The start index for each element within the buffer is:
    // value               | length | start  |
    // ---------------------------------------
    // 'Content-Encoding: '|   18   | 0      |
    // type                |   l    | 18     |
    // nul byte            |   1    | 18 + l |
    // 'P-256'             |   5    | 19 + l |
    // info                |   135  | 24 + l |
    s"Content-Encoding: $t".toCharArray().map(_.toByte) ++
      Array.fill(1)(0.toChar).map(_.toByte) ++
      "P-256".toCharArray().map(_.toByte) ++
      context
  }

  /**
   * Creates a context for deriving encyption parameters.
   * See section 4.2 of
   * {@link https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00}
   *
   * A rip-off of
   * https://github.com/GoogleChrome/web-push-encryption/blob/master/src/encrypt.js
   */
  def createContext(receiverPublicKey: PublicKey, senderPublicKey: PublicKey): Array[Byte] = {
    // The context format is:
    // 0x00 || length(clientPublicKey) || clientPublicKey ||
    //         length(serverPublicKey) || serverPublicKey
    // The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.

    // The keys should always be 65 bytes each. The format of the keys is
    // described in section 4.3.6 of the (sadly not freely linkable) ANSI X9.62
    // specification.

    val receiverPK = Utils.getRawPublicKeyFromPublicKey(receiverPublicKey)
    val senderPK = Utils.getRawPublicKeyFromPublicKey(senderPublicKey)

    if (receiverPK.length != PublicKeyLength) {
      throw new Exception(s"Invalid client public key length: ${receiverPK.length}")
    }

    // This one should never happen, because it's our code that generates the key
    if (senderPK.length != PublicKeyLength) {
      throw new Error(s"Invalid server public key length: ${senderPK.length}")
    }

    val context =
      Array.fill(1)(0.toChar).map(_.toByte) ++
        Utils.toUnsignedTwoBytesArray(receiverPK.length) ++
        receiverPK ++
        Utils.toUnsignedTwoBytesArray(senderPK.length) ++
        senderPK

    context
  }

  def encryptRecord(secret: Array[Byte], salt: Array[Byte], counter: Int,
    data: Array[Byte], padSize: Int): Array[Byte] = {
    val iv: Array[Byte] = Utils.generateIV(salt, counter)
    // System.out.println(s"IV: ${Utils.asB64(iv)}")
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    val eks: SecretKeySpec = new SecretKeySpec(secret, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, eks, new GCMParameterSpec(Utils.AuthTagLength * 8, iv))

    val padding = Array.fill(padSize)(0.toByte)
    // System.out.println(s"PD: ${Utils.asB64(padding)}")
    val x = cipher.update(padding ++ data) ++ cipher.doFinal()
    // System.out.println(s"R: ${Utils.asB64(x)}")
    x
  }

  def encrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      // Derive a Pseudo-Random Key (prk) that can be used to further derive our
      // other encryption parameters. These derivations are described in
      // https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00
      val prk: Array[Byte] = Utils.hdkfExpand(
        opts.sharedSecret,
        AuthInfo, PRKLengthBytes,
        opts.clientAuthToken
      )

      val encryptionKey: Array[Byte] = Utils.hdkfExpand(
        prk,
        buildInfo("aesgcm", opts.context), EncryptionKeyLength,
        opts.salt
      )
      val nonce: Array[Byte] = Utils.hdkfExpand(
        prk,
        buildInfo("nonce", opts.context), NonceLength,
        opts.salt
      )

      val recordSize: Int = opts.recordSize - opts.padSize
      var counter: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

      for { i <- Array.range(0, data.length + opts.padSize, recordSize) } {
        result = result ++
          encryptRecord(encryptionKey, nonce, counter, data.slice(i, i + recordSize), opts.padSize)
        counter = counter + 1
      }

      result
    }
  }

  def encryptForReceiver(data: Array[Byte], receiverPubKeyBase64: String, receiverAuthBase64: String, saltBase64: Option[String]): Try[EncryptedContext] = {
    val receiverPublicKey = Utils.getPublicKeyFromBytes(Base64.decodeBase64(receiverPubKeyBase64))
    val senderPair = Utils.generateECDHKeyPair()
    val sharedSecret = Utils.getECDHSharedSecret(senderPair, receiverPublicKey)
    // get salt from parameter or generate new salt
    val salt = saltBase64.map(s => Base64.decodeBase64(s)).getOrElse(Utils.generateSalt())
    // generate "context"
    val context = createContext(receiverPublicKey, senderPair.getPublic())

    val opts = new Options(sharedSecret = sharedSecret, salt = salt,
      senderPublicKey = senderPair.getPublic(), receiverPublicKey = receiverPublicKey,
      clientAuthToken = Base64.decodeBase64(receiverAuthBase64), context = context)

    val encrypted: Try[Array[Byte]] = Codec.encrypt(data, opts)
    encrypted.map { e =>
      new EncryptedContext(
        e,
        Base64.encodeBase64URLSafeString(Utils.getRawPublicKeyFromKeyPair(senderPair)),
        Base64.encodeBase64URLSafeString(salt)
      )
    }
  }
}
