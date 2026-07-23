package com.agepony.app.review

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri

//
// FOSS (F-Droid) flavor of ReviewPrompt (compiled only into the `foss` build flavor).
//
// The F-Droid build ships no Google Play dependencies, so the programmatic in-app
// review nudge is a no-op, and the explicit "Rate AgePony" action opens the app's
// F-Droid listing instead of the Play Store. Same public API as the `play` flavor's
// version under src/play, so shared code in src/main compiles against either.
//
object ReviewPrompt {

    /** No-op: the FOSS build ships no proprietary in-app review library. */
    fun request(activity: Activity) {
        // intentionally empty
    }

    /** Open the app's F-Droid listing. */
    fun openRating(context: Context) {
        val id = context.packageName
        runCatching {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse("https://f-droid.org/packages/$id/"))
            )
        }
    }
}
