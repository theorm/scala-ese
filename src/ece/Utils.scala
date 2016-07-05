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
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.DHParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.apache.commons.codec.binary.Base64
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.HKDFParameters

object Utils {
  final val KeyLength: Int = 16;
  final val DefaultRecordSize: Int = 4096;
  final val NonceLength: Int = 12;
  final val AuthTagLength: Int = 16;
  final val DefaultPadSize: Int = 2;

  Security.addProvider(new BouncyCastleProvider())

  def hdkfExpand(prk: Array[Byte], header: Array[Byte], length: Int, salt: Array[Byte]): Array[Byte] = {
    val hkdf: HKDFBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(prk, salt, header))

    val output: Array[Byte] = Array.fill(length)(0.toByte)
    hkdf.generateBytes(output, 0, length)
    output
  }

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
    val ecdhPrivateKeyParameters: ECPrivateKeyParameters = PrivateKeyFactory.createKey(
      keyPair.getPrivate().getEncoded()
    ).asInstanceOf[ECPrivateKeyParameters];

    val clientPublicKey: ECPublicKeyParameters = PublicKeyFactory.createKey(
      pubKey.getEncoded()
    ).asInstanceOf[ECPublicKeyParameters]

    val agree: BasicAgreement = new ECDHBasicAgreement();
    agree.init(ecdhPrivateKeyParameters);
    val secret: Array[Byte] = agree.calculateAgreement(clientPublicKey).toByteArray();
    BigIntegers.asUnsignedByteArray(Utils.KeyLength * 2, new BigInteger(secret))
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

  /**
   * http://stackoverflow.com/questions/19323178/how-to-do-diffie-hellman-key-generation-and-retrieve-raw-key-bytes-in-java
   */
  def getXYPGFromKeyPair(pair: KeyPair): Tuple4[Array[Byte], Array[Byte], Array[Byte], Array[Byte]] = {
    val x = pair.getPrivate().asInstanceOf[DHPrivateKey].getX().toByteArray()
    val y = pair.getPublic().asInstanceOf[DHPublicKey].getY().toByteArray()
    val params = pair.getPublic().asInstanceOf[DHPublicKey].getParams()
    val p = params.getP().toByteArray()
    val g = params.getG().toByteArray()
    Tuple4(x, y, p, g)
  }

  def getRawPublicKeyFromKeyPair(pair: KeyPair): Array[Byte] = {
    val publicKey: ECPublicKeyParameters = PublicKeyFactory.createKey(
      pair.getPublic().getEncoded()
    ).asInstanceOf[ECPublicKeyParameters]
    publicKey.getQ().getEncoded(false)
  }

  def getRawPublicKeyFromPublicKey(pk: PublicKey): Array[Byte] = {
    val publicKey: ECPublicKeyParameters = PublicKeyFactory.createKey(
      pk.getEncoded()
    ).asInstanceOf[ECPublicKeyParameters]
    publicKey.getQ().getEncoded(false)
  }

  def getRawPrivateKeyFromKeyPair(pair: KeyPair): Array[Byte] = {
    val ecdhPrivateKeyParameters: ECPrivateKeyParameters = PrivateKeyFactory.createKey(
      pair.getPrivate().getEncoded()
    ).asInstanceOf[ECPrivateKeyParameters];
    BigIntegers.asUnsignedByteArray(Utils.KeyLength * 2, ecdhPrivateKeyParameters.getD())
  }

  def lengthPrefix(data: Array[Byte]): Array[Byte] = {
    val lengthArray: Array[Byte] = Array.fill(1)(0.toByte) ++ data.length.toByteArray
    lengthArray ++ data
  }

  def getDHContext(receiverPublicKey: Array[Byte], senderPublicKey: Array[Byte]): Array[Byte] = {
    // System.out.println(s"XYZ: ${asHex(lengthPrefix(receiverPublicKey))}")
    "P-256".toCharArray().map(_.toByte) ++
      Array.fill(1)(0.toChar).map(_.toByte) ++
      lengthPrefix(receiverPublicKey) ++
      lengthPrefix(senderPublicKey)
  }

  def asB64(data: Array[Byte]): String = {
    Base64.encodeBase64URLSafeString(data)
  }

  def urlsafeB64(input: String): String = {
    Base64.encodeBase64URLSafeString(
      Base64.decodeBase64(input)
    )
  }

  def toUnsignedTwoBytesArray(number: Int): Array[Byte] = {
    BigIntegers.asUnsignedByteArray(2, BigInteger.valueOf(number))
  }

}
