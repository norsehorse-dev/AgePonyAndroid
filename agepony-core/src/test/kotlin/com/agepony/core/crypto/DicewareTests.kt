package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import kotlin.math.abs

class DicewareTests {

    /** A stand-in list; the real one is the app's EFF resource. */
    private val words = (0 until 7776).map { "w$it" }

    @Test
    fun generate_drawsTheRequestedNumberOfWordsFromTheList() {
        val phrase = Diceware.generate(words, wordCount = 6)
        val parts = phrase.split("-")
        assertEquals(6, parts.size)
        assertTrue(parts.all { it in words }, phrase)
    }

    @Test
    fun generate_honoursSeparatorAndClampsCount() {
        assertEquals(8, Diceware.generate(words, wordCount = 8, separator = " ").split(" ").size)
        assertEquals(Diceware.MIN_WORD_COUNT, Diceware.generate(words, wordCount = 1).split("-").size)
        assertEquals(Diceware.MAX_WORD_COUNT, Diceware.generate(words, wordCount = 99).split("-").size)
    }

    @Test
    fun generate_rejectsAUselessList() {
        assertThrows(Diceware.DicewareException::class.java) { Diceware.generate(emptyList()) }
        assertThrows(Diceware.DicewareException::class.java) { Diceware.generate(listOf("only")) }
    }

    @Test
    fun generate_doesNotRepeatItself() {
        val a = Diceware.generate(words)
        val b = Diceware.generate(words)
        assertNotEquals(a, b) // 77 bits apart; a collision here means the rng is not being used
    }

    /**
     * The strength claim depends on every word being equally likely. A modulo-based pick would
     * skew towards the front of the list; this checks the draw is spread across it.
     */
    @Test
    fun generate_drawsAcrossTheWholeList() {
        val counted = IntArray(4)
        val quarter = words.size / 4
        val rng = SecureRandom()
        repeat(4000) {
            val word = Diceware.generate(words, wordCount = 4, rng = rng).split("-").first()
            val index = words.indexOf(word)
            counted[minOf(index / quarter, 3)]++
        }
        for (q in counted) {
            assertTrue(abs(q - 1000) < 200, "quartile counts skewed: ${counted.toList()}")
        }
    }

    @Test
    fun entropyBits_matchesTheStandardFigures() {
        assertTrue(abs(Diceware.entropyBits(7776, 6) - 77.5) < 0.1)
        assertTrue(abs(Diceware.entropyBits(7776, 1) - 12.925) < 0.01)
        assertTrue(abs(Diceware.entropyBits(1296, 6) - 62.0) < 0.1)
        assertEquals(0.0, Diceware.entropyBits(1, 6))
    }

    @Test
    fun parseWordlist_readsEffFormatAndPlainWords() {
        val eff = "11111\tabacus\n11112\tabdomen\n11113\tabide\n"
        assertEquals(listOf("abacus", "abdomen", "abide"), Diceware.parseWordlist(eff))

        val plain = "# a comment\n\nabacus\nabdomen\n"
        assertEquals(listOf("abacus", "abdomen"), Diceware.parseWordlist(plain))

        val spaced = "11111 abacus\n11112 abdomen\n"
        assertEquals(listOf("abacus", "abdomen"), Diceware.parseWordlist(spaced))
    }

    @Test
    fun parseWordlist_refusesAMangledList() {
        // Silently skipping bad lines would shrink the keyspace without anyone noticing.
        assertThrows(Diceware.DicewareException::class.java) {
            Diceware.parseWordlist("11111\tabacus\n11112\tABDOMEN\n")
        }
        assertThrows(Diceware.DicewareException::class.java) {
            Diceware.parseWordlist("11111\tab-domen\n")
        }
        assertThrows(Diceware.DicewareException::class.java) { Diceware.parseWordlist("") }
    }
}
