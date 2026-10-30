package com.agepony.app

import android.app.Activity
import android.content.Intent
import android.util.Base64
import com.agepony.app.ui.AgeTab
import com.agepony.app.vault.DefaultKeyNames
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.KeystoreMasterKey
import com.agepony.app.vault.LockMode
import com.agepony.app.vault.RecipientImport
import com.agepony.app.vault.SharedVault
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.StoredNote
import com.agepony.app.vault.StoredRecipient
import com.agepony.app.vault.Vault
import com.agepony.app.vault.VaultCrypto
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import java.util.UUID

/**
 * Store screenshots, debug builds only. tools/play-screenshots.sh drives it over adb on an
 * emulator:
 *
 *   am start -n com.agepony.app/.MainActivity --ez demo_seed true --es demo_lang de --es demo_screen files
 *
 * demo_seed wipes the vault and makes a new one with no lock, screenshots allowed and the tour
 * done, holding keys, recipients and notes named in demo_lang. demo_screen picks the tab. The
 * app language itself is set by the script (cmd locale set-app-locales). No real names.
 */
object Demo {

    private class Texts(
        val personal: String, val laptop: String, val archive: String,
        val backup: String, val office: String, val friend: String,
        val wifi: String, val recovery: String,
    )

    private val texts = mapOf(
        "en" to Texts("Personal", "Work laptop", "Long-term archive",
            "Offline backup key", "Office server", "Shared with family",
            "Home Wi-Fi", "Recovery codes"),
        "de" to Texts("Persönlich", "Arbeitslaptop", "Langzeitarchiv",
            "Offline-Backup-Schlüssel", "Büroserver", "Mit der Familie geteilt",
            "WLAN zu Hause", "Wiederherstellungscodes"),
        "es" to Texts("Personal", "Portátil del trabajo", "Archivo a largo plazo",
            "Clave de respaldo sin conexión", "Servidor de la oficina", "Compartido con la familia",
            "Wi-Fi de casa", "Códigos de recuperación"),
        "fr" to Texts("Personnel", "Portable du travail", "Archives à long terme",
            "Clé de secours hors ligne", "Serveur du bureau", "Partagé avec la famille",
            "Wi-Fi de la maison", "Codes de récupération"),
        "pt-BR" to Texts("Pessoal", "Notebook do trabalho", "Arquivo de longo prazo",
            "Chave de backup offline", "Servidor do escritório", "Compartilhado com a família",
            "Wi-Fi de casa", "Códigos de recuperação"),
        "ru" to Texts("Личный", "Рабочий ноутбук", "Долгосрочный архив",
            "Офлайн-ключ для резервной копии", "Офисный сервер", "Общий с семьёй",
            "Домашний Wi-Fi", "Коды восстановления"),
        "zh-Hans" to Texts("个人", "工作笔记本", "长期存档",
            "离线备份密钥", "办公室服务器", "家人共享",
            "家里的 Wi-Fi", "恢复代码"),
    )

    fun handle(activity: Activity, intent: Intent?) {
        val screen = intent?.getStringExtra("demo_screen") ?: return
        val vault = SharedVault.get(activity)
        if (intent.getBooleanExtra("demo_seed", false)) {
            seed(activity, vault, texts[intent.getStringExtra("demo_lang")] ?: texts.getValue("en"))
            intent.removeExtra("demo_seed")
        }
        vault.lastTab = when (screen) {
            "identities" -> AgeTab.IDENTITIES
            "text" -> AgeTab.TEXT
            "notes" -> AgeTab.NOTES
            "settings" -> AgeTab.SETTINGS
            else -> AgeTab.FILES
        }.name
    }

    private fun seed(activity: Activity, vault: Vault, t: Texts) {
        vault.reset()
        runCatching { KeystoreMasterKey.delete() }
        runCatching { KeystoreMasterKey.deletePlain() }

        KeystoreMasterKey.generatePlain()
        val cipher = KeystoreMasterKey.wrapCipherPlain()
        val vk = VaultCrypto.randomKey()
        vault.writePlainKeyBlob(cipher.iv + cipher.doFinal(vk))
        vault.lockMode = LockMode.OFF
        vault.bootstrap(vk)
        vk.fill(0)
        vault.hasCompletedOnboarding = true
        vault.allowScreenshots = true
        vault.reviewPromptShown = true

        val now = System.currentTimeMillis()
        fun b64(b: ByteArray) = java.util.Base64.getEncoder().encodeToString(b)

        val x = X25519Identity.generate()
        vault.addIdentity(StoredIdentity(UUID.randomUUID().toString(), t.personal, StoredIdentityType.X25519,
            b64(x.publicKey), b64(x.privateKey), createdAt = now))
        val pq = HybridIdentity.generate()
        vault.addIdentity(StoredIdentity(UUID.randomUUID().toString(), t.archive, StoredIdentityType.MLKEM768X25519,
            b64(pq.publicKey), b64(pq.seed), createdAt = now), activate = false)
        val ssh = SSHEd25519Identity.generate()
        vault.addIdentity(StoredIdentity(UUID.randomUUID().toString(), t.laptop, StoredIdentityType.SSH_ED25519,
            b64(ssh.edPublicKey), b64(ssh.edSeed), createdAt = now), activate = false)

        val names = DefaultKeyNames.from(activity)
        listOf(
            t.backup to X25519Recipient(X25519Identity.generate().publicKey).toBech32(),
            t.office to HybridRecipient(HybridIdentity.generate().publicKey).toBech32(),
            t.friend to X25519Recipient(X25519Identity.generate().publicKey).toBech32(),
        ).forEach { (name, line) ->
            val c = RecipientImport.parsePastedText(line, names)
            vault.addRecipient(StoredRecipient(UUID.randomUUID().toString(), name, c.type, c.publicKeyB64,
                c.sshComment, c.source, c.sourceMetadata, now))
        }

        listOf(t.wifi, t.recovery).forEach { title ->
            val body = FileEncryptor.encrypt("demo".toByteArray(), emptyList(), "demo passphrase", armor = false)
            vault.addNote(StoredNote(UUID.randomUUID().toString(), title,
                Base64.encodeToString(body, Base64.NO_WRAP), now, now))
        }
    }
}
