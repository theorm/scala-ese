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

  val ExampleSalt = "AAAAAAAAAAAAAAAAAAAAAA=="

  val ExampleInput = "Hello, World."
  val ExampleOutput = "CE2OS6BxfXsC2YbTdfkeWLlt4AKWbHZ3Fe53n5/4Yg==";

  "Chrome Codec" - {
    "Javascript reference implementation: Scala encrypt" in {
      val payload = ExampleInput.getBytes
      val result = Codec.encryptForReceiver(payload, ClientPublicKey, ClientAuth, Some(ExampleSalt))

      result match {
        case Success(encryptedContext) => {
          val encryptedPayload = Base64.encodeBase64URLSafeString(encryptedContext.cipherText)
          assert(encryptedPayload == ExampleOutput)
        }
        case Failure(t) => fail(t)
      }
    }
  }
}
