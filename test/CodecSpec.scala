package project

import ece.{Codec, Options, Utils}
import java.security.SecureRandom

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
  System.out.println(s"XXX ${ecdsSharedSecret.length}")

  // 3. invalid length secret
  val invalidLength = 12
  val invalidLengthSecret: Array[Byte] = Array.ofDim(invalidLength)
  rg.nextBytes(invalidLengthSecret)

  val testData = "Foo Bar 123".toCharArray().map(_.toByte)

  "Codec:" - {
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
    "Fails to encrypt with secret of invalid length" in {
      val opts = new Options(invalidLengthSecret, Utils.generateSalt())
      val encrypted = Codec.encrypt(testData, opts)
      assert(encrypted.isFailure == true)
      assert(encrypted.failed.get.getMessage === "Secret length must be a multiple of 16")
    }
  }
}
