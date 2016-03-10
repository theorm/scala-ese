package ece;

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

object Codec {
  def hdkfExpand(prk: Array[Byte], header: String, length: Int, salt: Array[Byte]): Array[Byte] = {
    val hkdf: HKDFBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(prk, salt, header.getBytes()))

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
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    val eks: SecretKeySpec = new SecretKeySpec(secret, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, eks, new GCMParameterSpec(Utils.AuthTagLength * 8, iv))

    val padding = Array.fill(padSize)(0.toByte)

    cipher.update(padding ++ data) ++ cipher.doFinal()
  }

  def encrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      if (opts.recordSize < opts.padSize) {
        throw new Exception("Record size is too small")
      }

      val secret: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("aesgcm128", ""), Utils.KeyLength,
        opts.salt
      )
      val salt: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("nonce", ""), Utils.NonceLength,
        opts.salt
      )
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

  def buildInfo(t: String, context: String): String = {
    s"Content-Encoding: $t" ++ 0.toChar.toString() ++ context
  }

  def decrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      if (opts.recordSize < opts.padSize) {
        throw new Exception("Record size is too small")
      }

      val secret: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("aesgcm128", ""), Utils.KeyLength,
        opts.salt
      )
      val salt: Array[Byte] = hdkfExpand(
        opts.secret,
        buildInfo("nonce", ""), Utils.NonceLength,
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
}
