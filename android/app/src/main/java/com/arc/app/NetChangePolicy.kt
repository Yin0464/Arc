package com.arc.app

/**
 * Soft-lite / soft-path / hard network-change contract for
 * [UnderlyingNetworks] → Go [ApplyNetworkChange].
 *
 * Hard: underlying lost / null, or offline regain after no usable network.
 * Soft-path: multi-net handoff or link-address change; FakeIP kept, all UDP NAT reset.
 * Soft-lite: blocked clear, validated regain, screen-on / user-present wake;
 * InvalidateActive-style; FakeIP kept; only idle ≥15s UDP evicted.
 *
 * Wake (doze / screen-on) is always soft-lite by itself; underlying identity loss uses the
 * lost/regain paths with [isHard], not the wake receiver.
 *
 * A link-address change is soft-path on its own. It must not downgrade a hard reason:
 * losing the current underlying onto a replacement with different addresses is still hard.
 */
enum class NetChangeKind(val code: Int) {
    SoftLite(0),
    SoftPath(2),
    Hard(1);

    fun stronger(other: NetChangeKind): NetChangeKind =
        if (rank >= other.rank) this else other

    private val rank: Int
        get() = when (this) {
            SoftLite -> 0
            SoftPath -> 1
            Hard -> 2
        }
}

object NetChangePolicy {
    fun isHard(
        lostOrNullUnderlying: Boolean,
        offlineRegain: Boolean,
    ): Boolean = lostOrNullUnderlying || offlineRegain

    /**
     * @return the kind to notify Go, or `null` when Go does not need a notify.
     */
    fun networkChangeFull(
        reasonFull: Boolean,
        switched: Boolean,
        addrChanged: Boolean,
    ): NetChangeKind? = when {
        reasonFull -> NetChangeKind.Hard
        switched || addrChanged -> NetChangeKind.SoftPath
        else -> null
    }

    fun awaitReadyWaitMs(awaitingRegain: Boolean): Long = if (awaitingRegain) 5_000L else 2_500L
}
