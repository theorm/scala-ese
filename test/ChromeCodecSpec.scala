package project

import ece.chrome.{Codec, Options}
import ece.Utils
import org.apache.commons.codec.binary.Base64
import scala.util.{Success, Failure}

class ChromeEncryptSpec extends FixtureSpec {
  val ServerPublicKey = "BOg5KfYiBdDDRF12Ri17y3v+POPr8X0nVP2jDjowPVI/DMKU1aQ3OLdPH1iaakvR9/PHq6tNCzJH35v/JUz2crY="
  val ServerPrivateKey = "uDNsfsz91y2ywQeOHljVoiUg3j5RGrDVAswRqjP3v90="

  val ClientPublicKey = "BCIWgsnyXDv1VkhqL2P7YRBvdeuDnlwAPT2guNhdIoW3IP7GmHh1SMKPLxRf7x8vJy6ZFK3ol2ohgn_-0yP7QQA="
  val ClientAuth = "8eDyX_uCN0XRhSbY5hs7Hg=="

  val InvalidClientPublicKey = "6ZFK3ol2ohgn_-0yP7QQA="
  val InvalidClientAuth = "uCN0XRhSbY5hs7Hg=="

  val ExampleSalt = "AAAAAAAAAAAAAAAAAAAAAA=="

  val ExampleInput = "Hello, World."
  val ExampleOutput = "CE2OS6BxfXsC2YbTdfkeWLlt4AKWbHZ3Fe53n5/4Yg==";

  val SaltLength = 16;
  val ServerPublicKeyLength = 65;

  val TooLargeInputSize = 4081;

  "Chrome Codec" - {
    "Encoder tests from Javascript reference implementation" - {
      "Should produce expected output" in {
        val payload = ExampleInput.getBytes
        val testSenderKeyPair = Utils.constructECDHKeyPairFromKeys(
          Base64.decodeBase64(ServerPublicKey),
          Base64.decodeBase64(ServerPrivateKey)
        )
        val result = Codec.encryptForReceiver(payload, ClientPublicKey, ClientAuth, Some(ExampleSalt), Some(testSenderKeyPair))

        result match {
          case Success(encryptedContext) => {
            val encryptedPayload = Base64.encodeBase64URLSafeString(encryptedContext.cipherText)
            assert(encryptedPayload == Utils.urlsafeB64(ExampleOutput))
            assert(encryptedContext.senderPubKeyBase64 == Utils.urlsafeB64(ServerPublicKey))
            assert(encryptedContext.seedBase64 == Utils.urlsafeB64(ExampleSalt))
          }
          case Failure(t) => fail(t)
        }
      }

      "Should produce salt and sender public key of the right sizes" in {
        val payload = ExampleInput.getBytes
        val result = Codec.encryptForReceiver(payload, ClientPublicKey, ClientAuth)

        result match {
          case Success(encryptedContext) => {
            assert(Base64.decodeBase64(encryptedContext.seedBase64).length == SaltLength)
            assert(Base64.decodeBase64(encryptedContext.senderPubKeyBase64).length == ServerPublicKeyLength)
          }
          case Failure(t) => fail(t)
        }
      }

      "Should return an error due to an invalid auth token" in {
        val payload = ExampleInput.getBytes
        val result = Codec.encryptForReceiver(payload, ClientPublicKey, InvalidClientAuth)

        result match {
          case Success(_) => fail(new Exception("Should fail"))
          case Failure(t) => {
            assert(t.getMessage == "Subscription's Auth token is not 16 bytes.")
          }
        }
      }

      "Should return an error due to an invalid client public key" in {
        val payload = ExampleInput.getBytes
        val result = Codec.encryptForReceiver(payload, InvalidClientPublicKey, ClientAuth)

        result match {
          case Success(_) => fail(new Exception("Should fail"))
          case Failure(t) => {
            assert(t.getMessage == "Subscription's client key (p256dh) is invalid.")
          }
        }
      }

      "Should return an error when the input is too large" in {
        val payload = Array.fill(TooLargeInputSize)(0.toChar).map(_.toByte)
        val result = Codec.encryptForReceiver(payload, ClientPublicKey, ClientAuth)

        result match {
          case Success(_) => fail(new Exception("Should fail"))
          case Failure(t) => {
            assert(t.getMessage == "Payload is too large. The max number of bytes is 4078.")
          }
        }
      }
    }
  }
}
