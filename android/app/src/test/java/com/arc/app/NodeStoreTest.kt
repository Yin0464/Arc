package com.arc.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

class NodeStoreTest {
    @Test
    fun checkedRejectsEmpty() {
        try {
            NodeStore.checked(ByteArray(0))
            throw AssertionError("empty accepted")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun opensBundledAsset() {
        // The packaged table when build.sh has staged one, else the synthetic fixture.
        val asset = listOf("build/generated/arc/assets/nodes.json", "../../core/internal/store/testdata/nodes.json")
            .map(::File).firstOrNull { it.isFile }
        assumeTrue("no node table", asset != null)
        val root = org.json.JSONObject(String(NodeStore.checked(asset!!.readBytes())))
        assertTrue("codegen output must not carry a timestamp", !root.has("generated"))
        val regions = root.getJSONArray("regions")
        val names = List(regions.length()) { regions.getJSONObject(it).getString("name") }
        assertEquals(listOf("香港", "日本", "台湾", "新加坡", "其他"), names)
    }
}
