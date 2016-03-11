package ece

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.spec.ECPoint
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
import org.bouncycastle.util.BigIntegers
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.util.PublicKeyFactory
import java.security.PrivateKey
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.EncodedKeySpec

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
  def ecdhGetSharedSecretAndKeyPair(publicKey: PublicKey): Tuple2[Array[Byte], KeyPair] = {
    val pair: KeyPair = generateECDHKeyPair()
    val sharedSecretArray = getECDHSharedSecret(pair, publicKey)
    new Tuple2(sharedSecretArray, pair)
  }

  def getECDHSharedSecret(keyPair: KeyPair, pubKey: PublicKey): Array[Byte] = {
    val agreement: BasicAgreement = new ECDHBasicAgreement()
    agreement.init(ECUtil.generatePrivateKeyParameter(keyPair.getPrivate()))
    val sharedSecret: BigInteger = agreement.calculateAgreement(
      ECUtil.generatePublicKeyParameter(pubKey)
    )
    // make key fixed length : http://bit.ly/1Qmiu7K
    BigIntegers.asUnsignedByteArray(Utils.KeyLength * 2, sharedSecret)
  }

  def generateECDHKeyPair(): KeyPair = {
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1")
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);
    g.generateKeyPair()
  }

  def constructECDHKeyPairFromKeys(pubKey: Array[Byte], privKey: Array[Byte]): KeyPair = {
    val spec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1")
    val kf: KeyFactory = KeyFactory.getInstance("ECDH", "BC")
    val pubKeySpec: ECPublicKeySpec = new ECPublicKeySpec(
      spec.getCurve().decodePoint(pubKey), spec
    )
    val privKeySpec: ECPrivateKeySpec = new ECPrivateKeySpec(
      new BigInteger(privKey), spec
    )

    val puk: PublicKey = kf.generatePublic(pubKeySpec)
    val prk: PrivateKey = kf.generatePrivate(privKeySpec)
    new KeyPair(puk, prk)
  }

  def getPublicKeyFromBytes(pubKey: Array[Byte]): PublicKey = {
    val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1")
    val kf: KeyFactory = KeyFactory.getInstance("ECDH", "BC")
    val pubKeySpec: ECPublicKeySpec = new ECPublicKeySpec(
      spec.getCurve().decodePoint(pubKey), spec
    )
    kf.generatePublic(pubKeySpec)
  }

  def asHex(buf: Array[Byte]): String = {
    buf.map("%02X" format _).mkString
  }
}
