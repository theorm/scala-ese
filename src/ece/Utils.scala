package ece

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import scala.math.BigInt
import scala.math.BigInt.int2bigInt
import org.bouncycastle.crypto.BasicAgreement
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.util.BigIntegers
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.util.PublicKeyFactory

object Utils {
  final val KeyLength: Int = 16;
  final val DefaultRecordSize: Int = 4096;
  final val NonceLength: Int = 12;
  final val AuthTagLength: Int = 16;
  final val DefaultPadSize: Int = 2;

  Security.addProvider(new BouncyCastleProvider())

  /**
   * Returns salt as Base64 encoded string.
   */
  def generateSalt(): Array[Byte] = {
    val bytes: Array[Byte] = Array.ofDim(KeyLength);
    val sr = new SecureRandom()
    sr.nextBytes(bytes)
    bytes
  }

  def getHmacHash(key: Array[Byte], input: Array[Byte]): Array[Byte] = {
    val mac = Mac.getInstance("HmacSHA256")
    val secret = new SecretKeySpec(key, "HmacSHA256")
    mac.init(secret)
    mac.doFinal(input)
  }

  def generateIV(base: Array[Byte], counter: Int): Array[Byte] = {
    val nonce: Array[Byte] = base.clone()
    val magic = 4
    val m = new BigInt(new BigInteger(nonce.slice(magic, nonce.length)))
    val x = counter ^ m
    Array.concat(nonce.slice(0, magic), x.toByteArray)
  }

  /**
   * Given public key, generate another key pair and compute a shared
   * secret using Elliptic Curve Diffie Hellman method.
   */
  def ecdhGetSharedSecretAndLocalKey(publicKey: PublicKey): Tuple2[Array[Byte], PublicKey] = {
    val pair: KeyPair = generateECDSKeyPair()

    val keyOneAgreement: BasicAgreement = new ECDHBasicAgreement()
    keyOneAgreement.init(ECUtil.generatePrivateKeyParameter(pair.getPrivate()))
    val sharedSecret: BigInteger = keyOneAgreement.calculateAgreement(
      ECUtil.generatePublicKeyParameter(publicKey)
    )

    // make key fixed length : http://bit.ly/1Qmiu7K
    val sharedSecretArray = BigIntegers.asUnsignedByteArray(Utils.KeyLength * 2, sharedSecret)
    new Tuple2(sharedSecretArray, pair.getPublic())
  }

  def generateECDSKeyPair(): KeyPair = {
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

  def asHex(buf: Array[Byte]): String = {
    buf.map("%02X" format _).mkString
  }
}
