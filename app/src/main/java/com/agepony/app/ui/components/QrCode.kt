package com.agepony.app.ui.components

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

//
// Renders a string as a QR code, for sharing a public recipient by scan instead of
// copy/paste. ZXing is already in the app for the scanner side (ui/scan/QrScanner.kt);
// this is the encode direction. age recipients are short, so a single QR holds one
// comfortably, with no chunking like RSA/PGP keys would force.
//
@Composable
fun QrImage(
    content: String,
    modifier: Modifier = Modifier,
    size: Dp = 220.dp,
) {
    val bitmap = remember(content) { qrBitmap(content, 640) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "QR code for this recipient",
            contentScale = ContentScale.Fit,
            modifier = modifier.size(size),
        )
    }
}

private fun qrBitmap(content: String, px: Int): Bitmap? = try {
    val hints = mapOf(
        EncodeHintType.MARGIN to 1,
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
    )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, px, px, hints)
    val w = matrix.width
    val h = matrix.height
    val pixels = IntArray(w * h)
    for (y in 0 until h) {
        val row = y * w
        for (x in 0 until w) {
            pixels[row + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
        }
    }
    Bitmap.createBitmap(w, h, Bitmap.Config.RGB_565).apply {
        setPixels(pixels, 0, w, 0, 0, w, h)
    }
} catch (e: Exception) {
    null
}
