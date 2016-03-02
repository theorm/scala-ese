package ece;

import org.apache.commons.codec.binary.Base64

import scala.util.Try

import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import java.security.AlgorithmParameters
import java.security.spec.AlgorithmParameterSpec

import scala.collection.mutable.HashMap
import scala.collection.mutable.Map

class Key(val key: Array[Byte], val nonce: Array[Byte])

object Encoder {
  val savedKeys: Map[String, Array[Byte]] = new HashMap[String, Array[Byte]]()

  def computeSecret(secret: Array[Byte], share: Array[Byte]): Array[Byte] = {
    Utils.ecdhComputeSecret(secret, share)
  }

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
      output = Array.concat(output, t)
    }

    output.take(length)
  }

  private def extractKey(opts: Options): Try[Key] = {
    Try {
      val secret: Array[Byte] = opts.key match {
        case None => {
          opts.dh match {
            case None => {
              opts.keyId match {
                case None => throw new Exception(
                  "Options must have either 'key' or 'keyId' or 'dh'"
                )
                case keyId: Any => savedKeys.get(keyId.get).get
              }
            }
            case dh: Any => {
              val share = Base64.decodeBase64(dh.get)
              val s = savedKeys.get(opts.keyId.get).get
              computeSecret(s, share)
            }
          }
        }
        // if key is present - check the length
        case key: Some[Array[Byte]] => {
          key.get match {
            case s: Any if s.length == Utils.KeyLength => s
            case _ => throw new Exception(s"Key length must be ${Utils.KeyLength}")
          }
        }
      }

      val salt = Base64.decodeBase64(opts.salt) match {
        case salt: Any if salt.length == Utils.KeyLength => salt
        case _ => throw new Exception(s"Salt length must be ${Utils.KeyLength}")
      }

      val prk = hdkfExtract(salt, secret)

      new Key(
        hdkfExpand(prk, "Content-Encoding: aesgcm128", Utils.KeyLength),
        hdkfExpand(prk, "Content-Encoding: nonce", Utils.NonceLength)
      )
    }
  }

  def decryptRecord(key: Key, counter: Int, data: Array[Byte]): Array[Byte] = {
    val nonce: Array[Byte] = Utils.generateNonce(key.nonce, counter)
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
      Cipher.DECRYPT_MODE,
      new SecretKeySpec(key.key, "AES"),
      new GCMParameterSpec(Utils.AuthTagLength * 8, nonce)
    )
    val result: Array[Byte] = Array.concat(cipher.update(data), cipher.doFinal())

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

  def encryptRecord(key: Key, counter: Int, data: Array[Byte]): Array[Byte] = {
    val nonce: Array[Byte] = Utils.generateNonce(key.nonce, counter)
    val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding");
    val eks: SecretKeySpec = new SecretKeySpec(key.key, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, eks, new GCMParameterSpec(Utils.AuthTagLength * 8, nonce))

    val padding = Array.fill(1)(0.toByte)
    val epadding = cipher.update(padding)
    val ebuffer = cipher.update(data)
    val efinal = cipher.doFinal()
    Array.concat(epadding, ebuffer, efinal)
  }

  def encrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      val key: Key = extractKey(opts).get
      val recordSize: Int = opts.recordSize.get
      var i: Int = 0
      var start: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

      while (start <= data.length) {
        val end: Int = Math.min(start + recordSize - 1, data.length)
        val block: Array[Byte] = encryptRecord(key, i, data.slice(start, end))
        result = Array.concat(result, block)
        start += recordSize - 1
        i += 1
      }

      result
    }
  }

  def decrypt(data: Array[Byte], opts: Options): Try[Array[Byte]] = {
    Try {
      val key: Key = extractKey(opts).get
      val recordSize: Int = opts.recordSize.get
      var i: Int = 0
      var start: Int = 0
      var result: Array[Byte] = Array.ofDim(0)

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
        val block = decryptRecord(key, i, data.slice(start, end))
        result = Array.concat(result, block)
        start = end
        i += 1
      }

      result
    }
  }
}
