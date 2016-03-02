package project

import ece.{Encoder, Options, Utils}
import java.security.SecureRandom

class EncryptSpec extends FixtureSpec {
  val publicKey: Array[Byte] = Array.ofDim(Utils.KeyLength)
  val rg = new SecureRandom()
  rg.nextBytes(publicKey)

  //  val sharedSecretAndPublicKey = Utils.ecdhGetSharedSecretAndLocalKey(publicKey)
  //  val sharedSecret = sharedSecretAndPublicKey._1

  val testEncryptOptions = new Options(key = Some(publicKey), salt = Utils.generateSalt())
  val testData = "Foo Bar 123".toCharArray().map(_.toByte)

  "Test:" - {
    "Can decrypt encrypted" in {
      val encrypted = Encoder.encrypt(testData, testEncryptOptions).get
      val decrypted = Encoder.decrypt(encrypted, testEncryptOptions).get
      System.out.println(testData.map(_.toChar).length)
      System.out.println(encrypted.map(_.toChar).length)
      System.out.println(decrypted.map(_.toChar).length)
      assert(decrypted === testData)
    }
  }
}
