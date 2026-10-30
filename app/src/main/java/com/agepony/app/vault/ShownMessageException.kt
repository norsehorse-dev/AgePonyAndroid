package com.agepony.app.vault

/**
 * A failure whose message is already a finished sentence from resources, in the user's language.
 * The error mapper shows [shown] as it is; nothing else's message ever reaches the screen
 * (5.1.0, UI plan U5).
 */
class ShownMessageException(val shown: String) : Exception(shown)
