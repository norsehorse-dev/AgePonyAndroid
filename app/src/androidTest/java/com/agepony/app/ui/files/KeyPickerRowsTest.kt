package com.agepony.app.ui.files

import androidx.compose.foundation.layout.Column
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.agepony.app.ui.components.CheckRow
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.core.recipients.X25519Identity
import org.junit.Assert.assertNotEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 5.1.0 item 3: two identities with the same name and type render as two different rows in the
 * encrypt-to-self picker, and as two different lines in a menu picker.
 */
@RunWith(AndroidJUnit4::class)
class KeyPickerRowsTest {
    @get:Rule
    val compose = createComposeRule()

    private fun b64e(b: ByteArray): String = java.util.Base64.getEncoder().encodeToString(b)

    private fun x25519(): StoredIdentity {
        val id = X25519Identity.generate()
        return StoredIdentity(
            id = b64e(id.publicKey), name = "Work", type = StoredIdentityType.X25519,
            publicKeyB64 = b64e(id.publicKey), privateKeyB64 = b64e(id.privateKey), createdAt = 0L,
        )
    }

    @Test
    fun sameNamedIdentitiesRenderDifferentRows() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val a = x25519()
        val b = x25519()
        val rowA = KeyPickerText.subtitle(context, a)
        val rowB = KeyPickerText.subtitle(context, b)
        assertNotEquals(rowA, rowB)
        assertNotEquals(KeyPickerText.menuLine(context, a), KeyPickerText.menuLine(context, b))

        // The rows exactly as RecipientPicker draws them.
        compose.setContent {
            Column {
                CheckRow(title = a.name, checked = false, onCheckedChange = {}, subtitle = rowA)
                CheckRow(title = b.name, checked = false, onCheckedChange = {}, subtitle = rowB)
            }
        }
        compose.onNodeWithText(rowA).assertIsDisplayed()
        compose.onNodeWithText(rowB).assertIsDisplayed()
    }
}
