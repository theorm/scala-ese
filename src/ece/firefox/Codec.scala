package ece.firefox;

import org.apache.commons.codec.binary.Base64
import scala.util.Try
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import java.security.AlgorithmParameters
import java.security.spec.AlgorithmParameterSpec
import scala.collection.mutable.HashMap
import scala.collection.mutable.Map
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.HKDFParameters
import java.math.BigInteger
import javax.crypto.Mac
import javax.crypto.SecretKey
import ece.Utils

object Codec {
  def hdkfExpand(prk: Array[Byte], header: Array[Byte], length: Int, salt: Array[Byte]): Array[Byte] = {
    val hkdf: HKDFBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(prk, salt, header))

    val output: Array[Byte] = Array.fill(length)(0.toByte)
    hkdf.generateBytes(output, 0, length)
    output
  }

  def decryptRecord(secret: Array[Byte], salt: Array[Byte], counter: Int,
    data: Array[Byte], padSize: Int): Array[Byte] = {
    val iv: Array[Byte] = Utils.generateIV(salt, counter)
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.DECRYPT_MODE,
      new SecretKeySpec(secret, "AES"),
      new GCMParameterSpec(Utils.AuthTagLength * 8, iv)
    )
    val result: Array[Byte] = cipher.update(data) ++ cipher.doFinal()

    val pad = new BigInt(new BigInteger(result.slice(0, padSize)))

    if (pad + padSize > result.length) {
      throw new Exception("padding exceeds block size")
    }
    val padCheck = Array.fill(pad.toInt)(0.toByte)

    if (padCheck.deep != result.slice(padSize, padSize + pad.toInt).deep) {
      throw new Exception("Invalid padding")
    }
    result.slice(padSize + pad.toInt, result.length);
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
      if (opts.recordSize < opts.padSize) {
        throw new Exception("Record size is too small")
      }

      val secret: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("aesgcm128", opts.context), Utils.KeyLength,
        opts.salt
      )
      val salt: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("nonce", opts.context), Utils.NonceLength,
        opts.salt
      )
      //      System.out.println(s"DERIVED SECRET: \n info: ${Utils.asHex(buildInfo("aesgcm128", opts.context))}" ++
      //        s"\n key: ${Utils.asB64(secret)}\n context: ${Utils.asHex(opts.context)}")
      //      System.out.println(s"DERIVED SECRET: \n info: ${Utils.asHex(buildInfo("nonce", opts.context))}" ++
      //        s"\n key: ${Utils.asB64(salt)}\n context: ${Utils.asHex(opts.context)}")

      // System.out.println(s"K: ${Utils.asB64(secret)} N: ${Utils.asB64(salt)}")

      val recordSize: Int = opts.recordSize - opts.padSize
      var counter: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

      for { i <- Array.range(0, data.length + opts.padSize, recordSize) } {
        result = result ++
          encryptRecord(secret, salt, counter, data.slice(i, i + recordSize), opts.padSize)
        counter = counter + 1
      }

      result
    }
  }

  /**
   * XXX Gotcha:
   * There are two versions of the reference library: 0.2.0 and the latest one.
   * Version 0.2.0 works with Mozilla push service, but the most recent one does not.
   * The main difference that seems to break encryption is a padding byte in 'info'.
   * To make it work, it is commented out. This most likely will change in future.
   * V 0.2.0: https://github.com/martinthomson/encrypted-content-encoding/blob/683234accf49bf86179581b3098c3f0d6911b663/nodejs/ece.js#L65
   * Latest: https://github.com/martinthomson/encrypted-content-encoding/blob/master/nodejs/ece.js#L58
   */
  def buildInfo(t: String, context: Array[Byte]): Array[Byte] = {
    s"Content-Encoding: $t".toCharArray().map(_.toByte) ++
      // XXX - in new version there should be a byte long padding
      //      Array.fill(1)(0.toChar).map(_.toByte) ++
      context
  }

  def decrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      if (opts.recordSize < opts.padSize) {
        throw new Exception("Record size is too small")
      }

      val secret: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("aesgcm128", opts.context), Utils.KeyLength,
        opts.salt
      )
      val salt: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("nonce", opts.context), Utils.NonceLength,
        opts.salt
      )

      val recordSize: Int = opts.recordSize + Utils.AuthTagLength
      if (data.length % recordSize == 0) {
        throw new Exception("Message truncated")
      }

      var counter: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

      for { i <- Array.range(0, data.length, recordSize) } {
        result = result ++
          decryptRecord(secret, salt, counter, data.slice(i, i + recordSize), opts.padSize)
        counter = counter + 1
      }

      result
    }
  }

  def encryptForReceiver(data: Array[Byte], receiverPubKeyBase64: String): Try[EncryptedContext] = {
    val receiverPublicKey = Utils.getPublicKeyFromBytes(Base64.decodeBase64(receiverPubKeyBase64))
    val senderPair = Utils.generateECDHKeyPair()
    val sharedSecret = Utils.getECDHSharedSecret(senderPair, receiverPublicKey)

    val salt = Utils.generateSalt()
    val opts = new Options(secret = sharedSecret, salt = salt, padSize = 1)

    val encrypted: Try[Array[Byte]] = Codec.encrypt(data, opts)
    encrypted.map { e =>
      new EncryptedContext(e, Base64.encodeBase64URLSafeString(Utils.getRawPublicKeyFromKeyPair(senderPair)),
        Base64.encodeBase64URLSafeString(salt))
    }
  }
}
