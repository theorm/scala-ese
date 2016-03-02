package ece

import org.apache.commons.codec.binary.Base64
import scala.util.Random
import org.bouncycastle.jce.ECNamedCurveTable
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import org.bouncycastle.crypto.{BasicAgreement, CipherParameters}
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import scala.math.BigInt
import java.math.BigInteger
import org.bouncycastle.jce.spec.ECParameterSpec
import java.security.KeyPairGenerator
import java.security.KeyPair
import org.bouncycastle.crypto.params.KeyParameter
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.PublicKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import java.security.spec.ECPoint
import org.bouncycastle.jce.ECPointUtil
import java.security.spec.ECPublicKeySpec
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.security.MessageDigest
import org.bouncycastle.util.BigIntegers

object Utils {
  final val KeyLength: Int = 16;
  final val DefaultRecordSize: Int = 4096;
  final val NonceLength: Int = 12;
  final val AuthTagLength: Int = 16;

  Security.addProvider(new BouncyCastleProvider())

  /**
   * Returns salt as Base64 encoded string.
   */
  def generateSalt(): String = {
    val bytes: Array[Byte] = Array.ofDim(KeyLength);
    Random.nextBytes(bytes)
    new String(Base64.encodeBase64(bytes).map(_.toChar))
  }

  def getHmacHash(key: Array[Byte], input: Array[Byte]): Array[Byte] = {
    val mac = Mac.getInstance("HmacSHA256")
    val secret = new SecretKeySpec(key, "HmacSHA256")
    mac.init(secret)
    mac.doFinal(input)
  }

  def ecdhComputeSecret(keyOne: Array[Byte], keyTwo: Array[Byte]): Array[Byte] = {
    val keyOneAgreement: BasicAgreement = new ECDHBasicAgreement()
    keyOneAgreement.init(new KeyParameter(keyOne))
    keyOneAgreement.calculateAgreement(new KeyParameter(keyTwo)).toByteArray()
  }

  def generateNonce(base: Array[Byte], counter: Int): Array[Byte] = {
    val nonce: Array[Byte] = base.clone()
    val m = new BigInt(new BigInteger(nonce.takeRight(NonceLength / 2)))

    val x: BigInt = (m.pow(counter) & 0xffffff) +
      ((((m / 0x1000000) ^ (counter / 0x1000000)) & 0xffffff) * 0x1000000)

    Array.concat(nonce.slice(0, NonceLength / 2), x.toByteArray)
  }

  def ecdhGetSharedSecretAndLocalKey(publicKey: PublicKey): Tuple2[Array[Byte], Array[Byte]] = {
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("prime192v1")
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
    g.initialize(ecSpec);
    val pair: KeyPair = g.generateKeyPair()
    val localPublicKey: Array[Byte] = pair.getPublic().getEncoded()

    val keyOneAgreement: BasicAgreement = new ECDHBasicAgreement()
    keyOneAgreement.init(ECUtil.generatePrivateKeyParameter(pair.getPrivate()))
    val sharedSecret: BigInteger = keyOneAgreement.calculateAgreement(
      ECUtil.generatePublicKeyParameter(publicKey)
    )

    // make key fixed length : http://bit.ly/1Qmiu7K
    val sharedSecretArray = BigIntegers.asUnsignedByteArray(Utils.KeyLength * 2, sharedSecret)
    System.out.println(s"IIIIIIII ${sharedSecretArray.length}")
    new Tuple2(sharedSecretArray, localPublicKey)
  }

  def generatePublicAndPrivateKeys(): KeyPair = {
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("prime192v1")
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
    g.initialize(ecSpec);
    g.generateKeyPair()
  }

  def getPublicKeyFromBytes(pubKey: Array[Byte]): PublicKey = {
    val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1")
    val kf: KeyFactory = KeyFactory.getInstance("ECDSA", "BC")
    val params: ECNamedCurveSpec = new ECNamedCurveSpec(
      "prime256v1",
      spec.getCurve(), spec.getG(), spec.getN()
    )
    val point: ECPoint = ECPointUtil.decodePoint(params.getCurve(), pubKey)
    val pubKeySpec: ECPublicKeySpec = new ECPublicKeySpec(point, params)
    kf.generatePublic(pubKeySpec)
  }
}
