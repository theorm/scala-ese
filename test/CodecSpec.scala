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
  val keyPair = Utils.generateECDHKeyPair()
  val publicKey = keyPair.getPublic()

  val ecdsSharedSecretAndPublicKey = Utils.ecdhGetSharedSecretAndKeyPair(publicKey)
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
    "crossEncrypt" in {
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
    "crossDecrypt DH" in {
      val receiverPrivateKey = Base64.decodeBase64("68seZJthmq8SWoDOuyeMHyAjTYjpKBGdgQoN-mzZ5NQ=")
      val receiverPublicKey = Base64.decodeBase64(
        "BOo3TWjU9yQI0Lag-evm_JBcPLl8xRQD6bnOiJB359fP0fFo0J2KmmnFxtGyEcPVgqCkCRd9MnFlCZLOoBu7DrY="
      )
      val receiverKeyPair = Utils.constructECDHKeyPairFromKeys(
        receiverPublicKey, receiverPrivateKey
      )
      System.out.println(s"PUK1:                                                     ${asHex(receiverPublicKey)}")
      System.out.println(s"PUK2: ${asHex(receiverKeyPair.getPublic().getEncoded())}")
      System.out.println(s"PRK1:                                                                       ${asHex(receiverPrivateKey)}")
      System.out.println(s"PRK2: ${asHex(receiverKeyPair.getPrivate().getEncoded())}")

      //      assert(receiverKeyPair.getPrivate().getEncoded() == receiverPrivateKey)
      //      assert(receiverKeyPair.getPublic().getEncoded() == receiverPublicKey)

      // val senderPrivateKey = Base64.decodeBase64("wYza2jFsueGMg6AAlxm0_UhmBL_782YHUlCDeMq5Yvw=")
      val senderPublicKey = Base64.decodeBase64(
        "BP1LWtbxuJHy1zueo7OFGV4sOwfjU5ys_xoz136ks3FvRxDTPiW_40ZRMhAcR6EDvPajgpwGeZ9bMV3OX1ivzw0="
      )

      val encrypted = Base64.decodeBase64("FznvD2JYAa-OByaB1jPSE7M8CFCBIRf-Aaec_XUFtNHG")
      val salt = Base64.decodeBase64("VSvun_YGfd3EXHb6DMRBkw")
      val answerSecret = Base64.decodeBase64("1BJXJa_avAu7PNoGeAxe-up86DRKeB3Q55DQxxrsQog=")

      val secret = Utils.getECDHSharedSecret(
        receiverKeyPair,
        Utils.getPublicKeyFromBytes(senderPublicKey)
      )
      System.out.println(s"III: ${asHex(answerSecret)}")
      System.out.println(s"JJJ: ${asHex(secret)}")
      assert(secret == answerSecret)

      val opts = new Options(secret, salt)
      val decrypted: Array[Byte] = Codec.decrypt(encrypted, opts).get

      assert(new String(decrypted.map(_.toChar)) == "I am the walrus")
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
      assert(encrypted.failed.get.getMessage == "Record size is too small")
    }
  }
}
