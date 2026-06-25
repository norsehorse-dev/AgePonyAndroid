package com.agepony.app.review

import android.app.Activity
import com.google.android.play.core.review.ReviewManagerFactory

//
// Thin wrapper around the Play In-App Review API (Phase 2f). This is the
// engagement "nudge" the testers asked for: a contextual, quota-limited prompt
// that Google surfaces at most a few times per user. Per Google's guidance it is
// triggered programmatically (after repeat use), NOT from a button — the explicit
// "Rate AgePony" button in Settings opens the Play Store listing instead.
//
// Uses the stable Task-based flow (requestReviewFlow / launchReviewFlow) from
// com.google.android.play:review. The whole thing is best-effort: Play may show
// nothing (quota, sideloaded build, no Play Store), and every step is wrapped so
// a missing review surface never disrupts the app. The iOS counterpart is
// SKStoreReviewController.requestReview(in:), gated on the same launch counter.
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
}
