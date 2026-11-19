package com.arc.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CatalogTest {
    private val json = """
        [{"name":"香港","nodes":[{"name":"HK | 01","proto":"AnyTLS"},{"name":"JP","proto":"Trojan"}]},
         {"name":"X|R","nodes":[{"name":"A1","proto":"AnyTLS"}]}]
    """.trimIndent()

    @Test
    fun parsesNamesWithPipes() {
        val regions = parseCatalog(json)
        assertEquals(
            listOf(
                Region("香港", listOf(NodeInfo("HK | 01", "AnyTLS"), NodeInfo("JP", "Trojan"))),
                Region("X|R", listOf(NodeInfo("A1", "AnyTLS"))),
            ),
            regions,
        )
    }

    @Test
    fun emptyCatalog() {
        assertEquals(emptyList<Region>(), parseCatalog("[]"))
    }

    @Test(expected = org.json.JSONException::class)
    fun rejectsMissingField() {
        parseCatalog("""[{"name":"A"}]""")
    }

    private fun regions(vararg sizes: Pair<String, Int>) =
        sizes.map { (n, c) -> Region(n, List(c) { NodeInfo("n$it", "AnyTLS") }) }

    @Test
    fun fingerprintMatchesLegacyFormat() {
        assertEquals("A:2|B:1", catalogFingerprint(regions("A" to 2, "B" to 1)))
    }

    @Test
    fun unchangedCatalogKeepsAndClampsSlots() {
        val r = regions("A" to 3, "B" to 2)
        val saved = mapOf(0 to 2, 1 to 9)
        val (slots, reset) = restoreSlots(r, "A:3|B:2") { saved[it] }
        assertArrayEquals(intArrayOf(2, 1), slots)
        assertArrayEquals(booleanArrayOf(false, false), reset)
    }

    @Test
    fun changedRegionResets() {
        val r = regions("A" to 3, "B" to 4)
        val (slots, reset) = restoreSlots(r, "A:3|B:2") { 1 }
        assertArrayEquals(intArrayOf(1, 0), slots)
        assertArrayEquals(booleanArrayOf(false, true), reset)
    }

    @Test
    fun firstRunResetsEverything() {
        val (slots, reset) = restoreSlots(regions("A" to 3), null) { null }
        assertArrayEquals(intArrayOf(0), slots)
        assertArrayEquals(booleanArrayOf(true), reset)
    }
}
