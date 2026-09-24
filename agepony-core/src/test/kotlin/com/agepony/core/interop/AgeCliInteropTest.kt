package com.agepony.core.interop

import com.agepony.core.Age
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.TagRecipientTest
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.signing.SSHSigVerifier
import com.agepony.core.signing.SSHSigner
import com.agepony.core.signing.SignatureStanza
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import java.security.SecureRandom

/**
 * Live round trips against the reference `age` CLI. Skipped when `age` is not on PATH, and the
 * post-quantum and tag cases are skipped below age 1.3.0 (the first release with them).
 *
 * Point AGE_BIN at a specific binary to test a build that is not on PATH.
 */
class AgeCliInteropTest {

    private val plaintext = "AgePony <> age CLI interop. If you can read this, it worked.".toByteArray()

    private fun ed25519(): Pair<ByteArray, ByteArray> {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        return (kp.private as Ed25519PrivateKeyParameters).encoded to
            (kp.public as Ed25519PublicKeyParameters).encoded
    }

    @Test
    fun plainAgeDecryptsASignedFileToTheBarePayload() {
        val age = AgeCli.find(); assumeTrue(age != null, "age not on PATH")
        val (priv, pub) = ed25519()
        val sig = SSHSigner.signEd25519(priv, pub, plaintext)
        val id = X25519Identity.generate()
        val ct = Age.encrypt(plaintext, listOf(X25519Recipient(id.publicKey))) { fk ->
            listOf(SignatureStanza.build(fk, sig))
        }
        val out = age!!.decrypt(ct, id.toBech32())
        assertArrayEquals(plaintext, out, "plain age must return the original bytes, no wrapper")

        val back = Age.decryptAndRecoverSignature(ct, listOf(id))
        assertTrue(SSHSigVerifier.isValid(back.signatureArmored!!.toByteArray(), back.plaintext))
    }

    @Test
    fun ageDecryptsAgePonyPostQuantumFiles() {
        val age = AgeCli.find(); assumeTrue(age != null && age.atLeast(1, 3), "needs age >= 1.3.0")
        val id = HybridIdentity.generate()
        val ct = Age.encrypt(plaintext, listOf(id.recipient()))
        assertArrayEquals(plaintext, age!!.decrypt(ct, id.toBech32()))
    }

    @Test
    fun agePonyDecryptsAgePostQuantumFiles() {
        val age = AgeCli.find(); assumeTrue(age != null && age.atLeast(1, 3), "needs age >= 1.3.0")
        val (identity, recipient) = age!!.keygen(pq = true)
        assertTrue(recipient.startsWith("age1pq1"))
        val ct = age.encrypt(plaintext, recipient)
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(HybridIdentity(identity))))
        assertArrayEquals(
            plaintext,
            Age.decrypt(Age.encrypt(plaintext, listOf(HybridRecipient(recipient))), listOf(HybridIdentity(identity)))
        )
    }
    @Test
    fun agePonyDecryptsAgeTagFiles() {
        val age = AgeCli.find(); assumeTrue(age != null && age.atLeast(1, 3), "needs age >= 1.3.0")
        val kat = TagRecipientTest()
        for (id in listOf(kat.tagtestClassicIdentity(), kat.tagtestHybridIdentity())) {
            val ct = age!!.encrypt(plaintext, id.recipient.toBech32())
            assertArrayEquals(plaintext, Age.decrypt(ct, listOf(id)), id.recipient.stanzaType)
        }
    }

    @Test
    fun ageTagtestPluginDecryptsAgePonyTagFiles() {
        val age = AgeCli.find(); assumeTrue(age != null && age.atLeast(1, 3), "needs age >= 1.3.0")
        assumeTrue(age!!.hasPlugin("tagtest"), "age-plugin-tagtest not next to age or on PATH")
        val kat = TagRecipientTest()
        for (id in listOf(kat.tagtestClassicIdentity(), kat.tagtestHybridIdentity())) {
            val ct = Age.encrypt(plaintext, listOf(id.recipient))
            assertArrayEquals(plaintext, age.decryptWithPlugin(ct, "tagtest"), id.recipient.stanzaType)
        }
    }
}

/** Thin wrapper over a reference age binary for interop tests. */
class AgeCli private constructor(private val bin: String, val version: List<Int>) {

    fun atLeast(major: Int, minor: Int): Boolean =
        version.size >= 2 && (version[0] > major || (version[0] == major && version[1] >= minor))

    fun decrypt(ciphertext: ByteArray, identity: String): ByteArray {
        val idFile = tmp("id", identity + "\n")
        return run(listOf(bin, "-d", "-i", idFile.path), ciphertext)
    }

    fun decryptWithPlugin(ciphertext: ByteArray, plugin: String): ByteArray =
        run(listOf(bin, "-d", "-j", plugin), ciphertext)

    fun hasPlugin(name: String): Boolean {
        val file = "age-plugin-$name"
        val dirs = listOfNotNull(File(bin).absoluteFile.parentFile) +
            (System.getenv("PATH") ?: "").split(File.pathSeparator).map(::File)
        return dirs.any { File(it, file).canExecute() }
    }

    fun encrypt(plaintext: ByteArray, vararg recipients: String): ByteArray =
        run(listOf(bin) + recipients.flatMap { listOf("-r", it) }, plaintext)

    /** Returns (secret identity line, recipient). */
    fun keygen(pq: Boolean = false): Pair<String, String> {
        val out = String(run(listOf(keygenBin()) + if (pq) listOf("-pq") else emptyList(), ByteArray(0)))
        val secret = out.lines().first { it.startsWith("AGE-SECRET-KEY-") }
        val pub = String(run(listOf(keygenBin(), "-y"), (secret + "\n").toByteArray())).trim()
        return secret to pub
    }

    private fun keygenBin(): String {
        val sibling = File(File(bin).parentFile ?: File("."), "age-keygen")
        return if (sibling.canExecute()) sibling.path else "age-keygen"
    }

    private fun tmp(prefix: String, content: String): File =
        Files.createTempFile("agepony-$prefix", ".txt").toFile().apply { writeText(content); deleteOnExit() }

    private fun run(cmd: List<String>, stdin: ByteArray): ByteArray {
        val pb = ProcessBuilder(cmd)
        File(bin).absoluteFile.parentFile?.let { dir ->
            pb.environment()["PATH"] = dir.path + File.pathSeparator + (System.getenv("PATH") ?: "")
        }
        val p = pb.start()
        p.outputStream.use { it.write(stdin) }
        val out = p.inputStream.readBytes()
        val err = p.errorStream.readBytes()
        check(p.waitFor() == 0) { "${cmd.joinToString(" ")} failed: ${String(err)}" }
        return out
    }

    companion object {
        fun find(): AgeCli? {
            val bin = System.getenv("AGE_BIN") ?: "age"
            return try {
                val p = ProcessBuilder(bin, "--version").redirectErrorStream(true).start()
                val v = String(p.inputStream.readBytes()).trim()
                if (p.waitFor() != 0) return null
                val nums = Regex("""v?(\d+)\.(\d+)\.(\d+)""").find(v)?.groupValues?.drop(1)?.map { it.toInt() }
                AgeCli(bin, nums ?: emptyList())
            } catch (e: Exception) {
                null
            }
        }
    }
}
