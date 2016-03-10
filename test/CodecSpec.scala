package project

import ece.{Codec, Options, Utils}
import java.security.SecureRandom
import ece.Options
import org.apache.commons.codec.binary.Base64

class EncryptSpec extends FixtureSpec {
  //  1. random public key
  val randomSecret: Array[Byte] = Array.ofDim(Utils.KeyLength)
  val rg = new SecureRandom()
  rg.nextBytes(randomSecret)

  // 2. ECDS key
  val keyPair = Utils.generateECDSKeyPair()
  val publicKey = keyPair.getPublic()

  val ecdsSharedSecretAndPublicKey = Utils.ecdhGetSharedSecretAndLocalKey(publicKey)
  val ecdsSharedSecret = ecdsSharedSecretAndPublicKey._1

  // 3. invalid length secret
  val invalidLength = 12
  val invalidLengthSecret: Array[Byte] = Array.ofDim(invalidLength)
  rg.nextBytes(invalidLengthSecret)

  val testData = "Foo Bar 123".toCharArray().map(_.toByte)

  def asHex(buf: Array[Byte]): String = {
    buf.map("%02X" format _).mkString
  }

  "Codec:" - {
    "cross" in {
      val answer = "vyNCCSm-ONzN5GIA-mvJ-mnGAqZb_VWpOUcqvuNV2wvT"
      val secret = Base64.decodeBase64(
        "BLsyIPbDn6bquEOwHaju2gj8kUVoflzTtPs_6fGoock_dwxi1BcgFtObPVnic4alcEucx8I6G8HmEZCJnAl36Zg"
      )
      val salt = Base64.decodeBase64("5hpuYfxDzG6nSs9-EQuaBg")
      val data = "I am the walrus".toCharArray().map(_.toByte)
      val opts = new Options(secret, salt)
      val encrypted = Codec.encrypt(data, opts)
      val e = Base64.encodeBase64URLSafeString(encrypted.get)
      assert(e == answer)
    }
    "Can encrypt and decrypt using random secret" in {
      val testEncryptOptions = new Options(randomSecret, Utils.generateSalt())
      val encrypted = Codec.encrypt(testData, testEncryptOptions).get
      val decrypted = Codec.decrypt(encrypted, testEncryptOptions).get
      assert(decrypted === testData)
    }
    "Can encrypt and decrypt using ECDS secret" in {
      val eopts = new Options(ecdsSharedSecret, Utils.generateSalt())
      val encrypted = Codec.encrypt(testData, eopts).get
      val decrypted = Codec.decrypt(encrypted, eopts).get
      assert(decrypted === testData)
    }
    "Fails to encrypt with small record size" in {
      val rs = 10
      val ps = 11
      val opts = new Options(invalidLengthSecret, Utils.generateSalt(),
        recordSize = rs, padSize = ps)
      val encrypted = Codec.encrypt(testData, opts)
      assert(encrypted.isFailure == true)
      assert(encrypted.failed.get.getMessage === "Record size is too small")
    }
  }
}
