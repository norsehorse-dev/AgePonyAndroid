package com.agepony.app.ui.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.NavRow
import com.agepony.app.ui.components.PrimaryAction
import com.agepony.app.ui.components.ScreenPadding
import com.agepony.app.ui.components.SecondaryAction
import com.agepony.app.ui.components.SectionFooter
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.sign.SignFileFlow
import com.agepony.app.ui.sign.SignersScreen
import com.agepony.app.ui.sign.VerifyFileFlow
import com.agepony.app.vault.Vault

//
// Files tab landing. Encrypt, decrypt, inspect and upgrade files, plus the
// signing rows that used to be the Sign tab (folded in for 5.1.0, as on iOS).
// Each row opens its existing flow; the flow's app bar back arrow and the
// system back gesture return here.
//

private enum class FilesMode { HOME, ENCRYPT, DECRYPT, INSPECT, MIGRATE, SIGN_FILE, VERIFY_FILE, SIGNERS }

@Composable
fun FilesScreen(vault: Vault, modifier: Modifier = Modifier) {
    var mode by rememberSaveable { mutableStateOf(FilesMode.HOME) }
    val home = { mode = FilesMode.HOME }

    when (mode) {
        FilesMode.HOME -> AgeScreen(title = stringResource(R.string.files_title), modifier = modifier) { padding ->
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState()),
            ) {
                Column(
                    Modifier.padding(horizontal = ScreenPadding, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    PrimaryAction(
                        stringResource(R.string.files_encrypt),
                        onClick = { mode = FilesMode.ENCRYPT },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                        icon = Icons.Filled.Lock,
                    )
                    SecondaryAction(
                        stringResource(R.string.files_decrypt),
                        onClick = { mode = FilesMode.DECRYPT },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                        icon = ImageVector.vectorResource(R.drawable.ic_lock_open),
                    )
                }

                SectionHeader(
                    stringResource(R.string.files_section_signatures),
                    Modifier.padding(start = ScreenPadding, end = ScreenPadding, top = 16.dp, bottom = 8.dp),
                )
                NavRow(stringResource(R.string.files_sign), onClick = { mode = FilesMode.SIGN_FILE }, icon = Icons.Filled.Create)
                ListDivider(Modifier.padding(start = ScreenPadding))
                NavRow(stringResource(R.string.files_verify), onClick = { mode = FilesMode.VERIFY_FILE }, icon = Icons.Filled.CheckCircle)
                ListDivider(Modifier.padding(start = ScreenPadding))
                NavRow(stringResource(R.string.files_signers), onClick = { mode = FilesMode.SIGNERS }, icon = Icons.Filled.Person)
                SectionFooter(
                    stringResource(R.string.files_signatures_footer),
                    Modifier.padding(horizontal = ScreenPadding, vertical = 8.dp),
                )

                SectionHeader(
                    stringResource(R.string.files_section_tools),
                    Modifier.padding(start = ScreenPadding, end = ScreenPadding, top = 16.dp, bottom = 8.dp),
                )
                NavRow(stringResource(R.string.files_inspect), onClick = { mode = FilesMode.INSPECT }, icon = Icons.Filled.Search)
                ListDivider(Modifier.padding(start = ScreenPadding))
                NavRow(stringResource(R.string.files_migrate), onClick = { mode = FilesMode.MIGRATE }, icon = Icons.Filled.Refresh)
                SectionFooter(
                    stringResource(R.string.files_tools_footer),
                    Modifier.padding(start = ScreenPadding, end = ScreenPadding, top = 8.dp, bottom = 24.dp),
                )
            }
        }

        FilesMode.ENCRYPT -> EncryptFlow(vault = vault, modifier = modifier, onClose = home)

        FilesMode.DECRYPT -> DecryptFlow(vault = vault, modifier = modifier, onClose = home)

        FilesMode.INSPECT -> InspectFlow(vault = vault, modifier = modifier, onClose = home)

        FilesMode.MIGRATE -> MigrateFlow(vault = vault, modifier = modifier, onClose = home)

        FilesMode.SIGN_FILE -> SignFileFlow(vault = vault, modifier = modifier, onClose = home)

        FilesMode.VERIFY_FILE -> VerifyFileFlow(vault = vault, modifier = modifier, onClose = home)

        FilesMode.SIGNERS -> SignersScreen(vault = vault, modifier = modifier, onClose = home)
    }
}
