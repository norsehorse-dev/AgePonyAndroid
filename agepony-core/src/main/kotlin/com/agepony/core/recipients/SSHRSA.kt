package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.crypto.RSAOAEP
import com.agepony.core.crypto.SHA256
import com.agepony.core.ssh.OpenSSHPrivateKey
import com.agepony.core.ssh.OpenSSHPublicKey
import com.agepony.core.ssh.SSHMPInt
import com.agepony.core.ssh.SSHWire
import java.io.ByteArrayOutputStream
import java.math.BigInteger

private const val SSH_RSA_STANZA_TYPE = "ssh-rsa"
private const val SSH_RSA_LABEL = "age-encryption.org/v1/ssh-rsa"
private const val SSH_RSA_KEYTYPE = "ssh-rsa"
private const val RECIPIENT_TAG_LEN = 4

private fun buildSSHRSAWireBlob(modulus: BigInteger, exponent: BigInteger): ByteArray {
    val out = ByteArrayOutputStream()
    SSHWire.writeString(out, SSH_RSA_KEYTYPE.toByteArray(Charsets.US_ASCII))
    SSHMPInt.write(out, exponent)
    SSHMPInt.write(out, modulus)
    return out.toByteArray()
}

class SSHRSARecipient(val modulus: BigInteger, val exponent: BigInteger) : AgeRecipient {
    private val sshWireBlob: ByteArray
    private val recipientTag: ByteArray

    init {
        require(modulus.signum() > 0) { "RSA modulus must be positive" }
        require(exponent.signum() > 0) { "RSA exponent must be positive" }
        sshWireBlob = buildSSHRSAWireBlob(modulus, exponent)
        recipientTag = SHA256.digest(sshWireBlob).copyOfRange(0, RECIPIENT_TAG_LEN)
    }

    constructor(parsed: OpenSSHPublicKey.RSA) : this(parsed.modulus, parsed.exponent)

    override fun wrap(fileKey: ByteArray): Stanza {
        val body = RSAOAEP.encrypt(
            modulus,
            exponent,
            SSH_RSA_LABEL.toByteArray(Charsets.US_ASCII),
            fileKey
        )
        return Stanza(
            SSH_RSA_STANZA_TYPE,
            listOf(Stanza.base64NoPad(recipientTag)),
            body
        )
    }

    companion object {
        fun fromOpenSSHString(line: String): SSHRSARecipient {
            val parsed = OpenSSHPublicKey.parse(line)
            require(parsed is OpenSSHPublicKey.RSA) {
                "expected ssh-rsa, got '${parsed.keyType}'"
            }
            return SSHRSARecipient(parsed)
        }
    }
}

class SSHRSAIdentity(
    val n: BigInteger,
    val e: BigInteger,
    val d: BigInteger,
    val p: BigInteger,
    val q: BigInteger,
    val iqmp: BigInteger,
) : AgeIdentity {
    private val sshWireBlob: ByteArray
    private val recipientTag: ByteArray

    init {
        require(n.signum() > 0) { "RSA modulus must be positive" }
        require(e.signum() > 0) { "RSA public exponent must be positive" }
        require(d.signum() > 0) { "RSA private exponent must be positive" }
        require(p.signum() > 0 && q.signum() > 0) { "RSA primes must be positive" }
        require(iqmp.signum() > 0) { "RSA iqmp must be positive" }
        sshWireBlob = buildSSHRSAWireBlob(n, e)
        recipientTag = SHA256.digest(sshWireBlob).copyOfRange(0, RECIPIENT_TAG_LEN)
    }

    constructor(parsed: OpenSSHPrivateKey.RSA) : this(
        parsed.n, parsed.e, parsed.d, parsed.p, parsed.q, parsed.iqmp
    )

    override fun unwrap(stanza: Stanza): ByteArray? {
        if (stanza.type != SSH_RSA_STANZA_TYPE) return null
        if (stanza.args.size != 1) return null

        val tag = try { Stanza.base64Decode(stanza.args[0]) } catch (_: Exception) { return null }
        if (tag.size != RECIPIENT_TAG_LEN) return null
        if (!tag.contentEquals(recipientTag)) return null

        return try {
            RSAOAEP.decrypt(
                n, e, d, p, q, iqmp,
                SSH_RSA_LABEL.toByteArray(Charsets.US_ASCII),
                stanza.body
            )
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        /**
         * Parse a `-----BEGIN OPENSSH PRIVATE KEY-----` PEM into an Identity.
         * If the PEM is passphrase-encrypted, supply `passphrase`. Throws on wrong/missing
         * passphrase.
         */
        fun fromPEM(pem: String, passphrase: String? = null): SSHRSAIdentity {
            val parsed = OpenSSHPrivateKey.parse(pem, passphrase)
            require(parsed is OpenSSHPrivateKey.RSA) {
                "expected ssh-rsa, got '${parsed.keyType}'"
            }
            return SSHRSAIdentity(parsed)
        }
    }
}
