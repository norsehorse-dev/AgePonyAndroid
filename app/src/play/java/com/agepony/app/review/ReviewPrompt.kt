package com.agepony.app.review

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import com.google.android.play.core.review.ReviewManagerFactory

//
// Google Play flavor of ReviewPrompt (compiled only into the `play` build flavor).
//
// - `request` wraps the Play In-App Review API: the contextual, quota-limited nudge
//   Google surfaces at most a few times per user, triggered programmatically after
//   repeat use (never from a button, per Google's guidance).
// - `openRating` is the explicit "Rate AgePony" action; it opens the Play Store listing.
//
// The `foss` (F-Droid) flavor provides a Play-free equivalent under src/foss so the
// F-Droid build carries no Google dependencies.
//
object ReviewPrompt {

    /**
     * Request and launch the in-app review flow. Safe to call unconditionally and
     * fire-and-forget; gating (launch count, once-only) is the caller's job. Any
     * failure or unavailable review surface is silently ignored.
     */
    fun request(activity: Activity) {
        runCatching {
            val manager = ReviewManagerFactory.create(activity)
            manager.requestReviewFlow().addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    runCatching { manager.launchReviewFlow(activity, task.result) }
                }
            }
        }
    }

    /** Open the app's Play Store listing (Play app first, then the web listing). */
    fun openRating(context: Context) {
        val id = context.packageName
        val market = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$id"))
        if (runCatching { context.startActivity(market) }.isFailure) {
            runCatching {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$id"))
                )
            }
        }
    }
}
