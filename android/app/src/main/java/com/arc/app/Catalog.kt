package com.arc.app

import org.json.JSONArray

/** One selectable node as the core reports it; indices match [Native.switchNode]. */
data class NodeInfo(val name: String, val proto: String)

data class Region(val name: String, val nodes: List<NodeInfo>)

/** Parses the core's `getCatalog` JSON contract: `[{name, nodes: [{name, proto}]}]`. */
fun parseCatalog(json: String): List<Region> {
    val regions = JSONArray(json)
    return List(regions.length()) { i ->
        val r = regions.getJSONObject(i)
        val nodes = r.getJSONArray("nodes")
        Region(
            name = r.getString("name"),
            nodes = List(nodes.length()) { k ->
                val n = nodes.getJSONObject(k)
                NodeInfo(name = n.getString("name"), proto = n.getString("proto"))
            },
        )
    }
}

/** Per-region shape, `name:count` joined by `|`; matches what earlier versions stored. */
fun catalogFingerprint(regions: List<Region>): String =
    regions.joinToString("|") { fingerprintPart(it) }

private fun fingerprintPart(r: Region) = "${r.name}:${r.nodes.size}"

/**
 * Remembered node per region after a catalog change. A region keeps its saved slot only
 * when its fingerprint part at the same index is unchanged; otherwise it resets to 0.
 * Returns the slots and which regions were reset (their stored slot must be rewritten).
 */
fun restoreSlots(
    regions: List<Region>,
    previousFingerprint: String?,
    saved: (Int) -> Int?,
): Pair<IntArray, BooleanArray> {
    val same = previousFingerprint == catalogFingerprint(regions)
    val prevParts = previousFingerprint?.split("|").orEmpty()
    val slots = IntArray(regions.size)
    val reset = BooleanArray(regions.size)
    regions.forEachIndexed { i, r ->
        val keep = same || prevParts.getOrNull(i) == fingerprintPart(r)
        if (keep) {
            slots[i] = (saved(i) ?: 0).coerceIn(0, (r.nodes.size - 1).coerceAtLeast(0))
        } else {
            reset[i] = true
        }
    }
    return slots to reset
}
