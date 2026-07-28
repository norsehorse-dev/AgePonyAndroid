package com.agepony.core.crypto

import java.security.SecureRandom

/**
 * Diceware passphrase generation.
 *
 * A passphrase is a number of words drawn uniformly and independently from a word list, so its
 * strength is exactly `wordCount * log2(listSize)` and does not depend on the words themselves.
 * With the EFF long list (7776 words) each word is worth 12.925 bits, so six words is 77.5 bits.
 *
 * This object holds no list of its own: the caller supplies the words, which keeps `agepony-core`
 * free of resources and lets the app own where the list came from.
 */
object Diceware {
    const val DEFAULT_WORD_COUNT = 6
    const val MIN_WORD_COUNT = 4
    const val MAX_WORD_COUNT = 12
    const val DEFAULT_SEPARATOR = "-"

    /** Size of the EFF long wordlist, for callers that want to check they loaded the real thing. */
    const val EFF_LONG_LIST_SIZE = 7776

    class DicewareException(message: String) : Exception(message)

    /** Bits of entropy in a passphrase of [wordCount] words drawn from a list of [listSize]. */
    fun entropyBits(listSize: Int, wordCount: Int): Double {
        if (listSize < 2 || wordCount < 1) return 0.0
        return wordCount * (Math.log(listSize.toDouble()) / Math.log(2.0))
    }

    /**
     * Draw [wordCount] words from [words], uniformly and with replacement.
     *
     * Uses `SecureRandom.nextInt(bound)`, which is rejection-sampled and therefore unbiased; the
     * obvious `nextInt() % size` would quietly favour the front of the list and cost entropy.
     * Words may repeat, which is what makes the strength calculation exact.
     */
    fun generate(
        words: List<String>,
        wordCount: Int = DEFAULT_WORD_COUNT,
        separator: String = DEFAULT_SEPARATOR,
        rng: SecureRandom = SecureRandom(),
    ): String {
        if (words.size < 2) throw DicewareException("word list is too small to generate a passphrase")
        val count = wordCount.coerceIn(MIN_WORD_COUNT, MAX_WORD_COUNT)
        return (0 until count).joinToString(separator) { words[rng.nextInt(words.size)] }
    }

    /**
     * Read a word list in EFF format: one entry per line, either `11111<tab>abacus` or just the
     * word. Blank lines and `#` comments are skipped, and anything that is not a plain lowercase
     * a-z word is rejected rather than silently skipped, so a mangled or truncated file is caught
     * at load time instead of quietly shrinking the keyspace.
     */
    fun parseWordlist(text: String): List<String> {
        val words = ArrayList<String>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val word = line.substringAfterLast('\t').substringAfterLast(' ').trim()
            if (word.isEmpty() || !word.all { it in 'a'..'z' }) {
                throw DicewareException("word list contains an unusable entry: '$line'")
            }
            words.add(word)
        }
        if (words.size < 2) throw DicewareException("word list is empty")
        return words
    }
}
