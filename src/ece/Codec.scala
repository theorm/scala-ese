package ece;

import org.apache.commons.codec.binary.Base64

import scala.util.Try

import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import java.security.AlgorithmParameters
import java.security.spec.AlgorithmParameterSpec

import scala.collection.mutable.HashMap
import scala.collection.mutable.Map

object Codec {
  val savedKeys: Map[String, Array[Byte]] = new HashMap[String, Array[Byte]]()

  def hdkfExtract(salt: Array[Byte], secret: Array[Byte]): Array[Byte] = {
    Utils.getHmacHash(salt, secret)
  }

  def hdkfExpand(prk: Array[Byte], header: String, length: Int): Array[Byte] = {
    var output: Array[Byte] = Array.ofDim(0)
    var t: Array[Byte] = Array.ofDim(0)
    val info = header.toCharArray().map(_.toByte)
    val cbuf: Array[Byte] = Array.ofDim(1)
    var counter: Int = 0;

    while (output.length < 1) {
      counter += 1
      cbuf.update(0, counter.toByte)
      t = Utils.getHmacHash(prk, Array.concat(t, info, cbuf))
      output = output ++ t
    }

    output.take(length)
  }

  def decryptRecord(secret: Array[Byte], salt: Array[Byte], counter: Int,
    data: Array[Byte]): Array[Byte] = {
    val iv: Array[Byte] = Utils.generateIV(salt, counter)
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.DECRYPT_MODE,
      new SecretKeySpec(secret, "AES"),
      new GCMParameterSpec(Utils.AuthTagLength * 8, iv)
    )
    val result: Array[Byte] = cipher.update(data) ++ cipher.doFinal()

    val pad = result(0).toInt;
    if (pad + 1 > result.length) {
      throw new Exception("padding exceeds block size")
    }
    val padCheck = Array.fill(pad)(0.toByte)
    if (padCheck.deep != result.slice(1, 1 + pad).deep) {
      throw new Exception(
        s"Invalid padding: ${padCheck.deep} != ${result.slice(1, 1 + pad).deep}"
      )
    }
    result.slice(1 + pad, result.length);
  }

  def encryptRecord(secret: Array[Byte], salt: Array[Byte], counter: Int,
    data: Array[Byte]): Array[Byte] = {
    val iv: Array[Byte] = Utils.generateIV(salt, counter)
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    val eks: SecretKeySpec = new SecretKeySpec(secret, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, eks, new GCMParameterSpec(Utils.AuthTagLength * 8, iv))

    val padding = Array.fill(1)(0.toByte)
    val epadding = cipher.update(padding)
    val ebuffer = cipher.update(data)
    val efinal = cipher.doFinal()
    epadding ++ ebuffer ++ efinal
  }

  def encrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      val secret: Array[Byte] = opts.secret
      val salt: Array[Byte] = opts.salt
      val recordSize: Int = opts.recordSize.get
      var i: Int = 0
      var start: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

      if (secret.length.toDouble % Utils.KeyLength.toDouble != 0) {
        throw new Exception(s"Secret length must be a multiple of ${Utils.KeyLength}")
      }

      System.out.println(s"Secret L ${secret.length}")

      while (start <= data.length) {
        val end: Int = Math.min(start + recordSize - 1, data.length)
        val block: Array[Byte] = encryptRecord(secret, salt, i, data.slice(start, end))
        result ++= block
        start += recordSize - 1
        i += 1
      }

      result
    }
  }

  def decrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      val secret: Array[Byte] = opts.secret
      val salt: Array[Byte] = opts.salt
      val recordSize: Int = opts.recordSize.get
      var i: Int = 0
      var start: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

      if (secret.length.toDouble % Utils.KeyLength.toDouble != 0) {
        throw new Exception(s"Secret length must be a multiple of ${Utils.KeyLength}")
      }

      while (start < data.length) {
        var end = start + recordSize + Utils.AuthTagLength
        if (end == data.length) {
          throw new Exception("Truncated payload")
        }

        end = Math.min(end, data.length)
        if ((end - start) <= Utils.AuthTagLength) {
          throw new Error(
            s"Invalid block: too small at $i: ${end - start} <= ${Utils.AuthTagLength}"
          );
        }
        val block = decryptRecord(secret, salt, i, data.slice(start, end))
        result ++= block
        start = end
        i += 1
      }

      result
    }
  }
}
