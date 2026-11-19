package com.arc.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnNotificationTest {
    @Test
    fun runningShowsNodeName() {
        assertEquals("香港 01", VpnNotification.text("香港 01", null, false))
        assertEquals("自定义", VpnNotification.text("自定义", null, false))
        assertEquals("美国 01", VpnNotification.text("美国 01", null, false))
        assertEquals("美国 01", VpnNotification.text("美国 01", null, false))
        assertEquals("香港 01 · 42ms", VpnNotification.text("香港 01", 42, false))
        assertEquals("美国 01 · 42ms", VpnNotification.text("美国 01", 42, false))
        assertEquals("VPN运行中", VpnNotification.text(null, null, false))
        assertEquals("VPN运行中", VpnNotification.title(false))
    }

    @Test
    fun recoveringCopy() {
        assertEquals("VPN恢复中", VpnNotification.title(true))
        assertEquals("正在重连 · 日本 03", VpnNotification.text("日本 03", 10, true))
        assertEquals("正在重连核心", VpnNotification.text(null, null, true))
    }
}

class VpnErrorsTest {
    @Test
    fun mapsCommonFailures() {
        assertEquals("连接超时", VpnErrors.friendly("i/o timeout"))
        assertEquals("DNS/DoH 失败", VpnErrors.friendly("doh bootstrap failed"))
        assertEquals("DNS/DoH 失败", VpnErrors.friendly("dns lookup failed"))
        assertEquals("出站 protect 失败", VpnErrors.friendly("protect: permission denied"))
        assertEquals("TLS 握手失败", VpnErrors.friendly("tls: handshake failure"))
        assertEquals("等待可用网络", VpnErrors.friendly("等待可用网络"))
        assertEquals("连接中断", VpnErrors.friendly("connection reset by peer"))
        assertEquals("鉴权失败", VpnErrors.friendly("unauthorized"))
    }

    @Test
    fun avoidsLooseSubstringOvermatch() {
        // bare "reset"/"auth"/"dns" inside unrelated tokens must not hijack
        assertEquals("preset route ok", VpnErrors.friendly("preset route ok"))
        assertEquals("author list", VpnErrors.friendly("author list"))
        assertEquals("handshake only", VpnErrors.friendly("handshake only"))
        assertEquals("refused elsewhere", VpnErrors.friendly("refused elsewhere"))
    }
}

class NetChangePolicyTest {
    @Test
    fun hardOnlyOnLossOrRegain() {
        assertTrue(NetChangePolicy.isHard(true, false))
        assertTrue(NetChangePolicy.isHard(false, true))
        assertFalse(NetChangePolicy.isHard(false, false))
    }

    @Test
    fun addressChangeDoesNotDowngradeHard() {
        assertEquals(NetChangeKind.Hard, NetChangePolicy.networkChangeFull(reasonFull = true, switched = true, addrChanged = true))
        assertEquals(NetChangeKind.Hard, NetChangePolicy.networkChangeFull(reasonFull = true, switched = false, addrChanged = true))
        assertEquals(NetChangeKind.Hard, NetChangePolicy.networkChangeFull(reasonFull = true, switched = false, addrChanged = false))
        assertEquals(NetChangeKind.SoftPath, NetChangePolicy.networkChangeFull(reasonFull = false, switched = true, addrChanged = true))
        assertEquals(NetChangeKind.SoftPath, NetChangePolicy.networkChangeFull(reasonFull = false, switched = false, addrChanged = true))
        assertEquals(null, NetChangePolicy.networkChangeFull(reasonFull = false, switched = false, addrChanged = false))
    }

    @Test
    fun awaitReadyWaitSplitsRegainFromColdStart() {
        assertEquals(5_000L, NetChangePolicy.awaitReadyWaitMs(awaitingRegain = true))
        assertEquals(2_500L, NetChangePolicy.awaitReadyWaitMs(awaitingRegain = false))
    }

    @Test
    fun netChangeKindHardWinsCoalesce() {
        assertEquals(NetChangeKind.SoftPath, NetChangeKind.SoftLite.stronger(NetChangeKind.SoftPath))
        assertEquals(NetChangeKind.Hard, NetChangeKind.SoftPath.stronger(NetChangeKind.Hard))
        assertEquals(NetChangeKind.Hard, NetChangeKind.Hard.stronger(NetChangeKind.SoftLite))
    }
}
