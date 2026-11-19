package com.arc.app

/** Maps raw dial/DoH/protect/start failures to short Chinese copy for Toasts / lastVpnError. */
object VpnErrors {
    fun friendly(raw: String?): String {
        val s = raw?.trim().orEmpty()
        if (s.isEmpty()) return "未知错误"
        // Known product Chinese strings: pass through (bounded).
        if (s.startsWith("节点表未加载") ||
            s.startsWith("核心未就绪") ||
            s.startsWith("等待") ||
            s.startsWith("核心反复退出") ||
            s.startsWith("核心退出")
        ) {
            return s.take(48)
        }
        val lower = s.lowercase()
        return when {
            "vpn 建立失败" in lower || "establish" in lower -> "VPN 建立失败（系统拒绝）"
            "fd dup" in lower -> "VPN fd 复制失败"
            "protect:" in lower || "permission denied" in lower -> "出站 protect 失败"
            "doh" in lower || dnsToken(lower) -> "DNS/DoH 失败"
            "i/o timeout" in lower || "deadline exceeded" in lower || "timeout" in lower -> "连接超时"
            "connection refused" in lower -> "连接被拒绝"
            "network is unreachable" in lower || "no route to host" in lower -> "网络不可达"
            "no route" in lower -> "无可用路由"
            "tls:" in lower || "x509" in lower || "certificate" in lower -> "TLS 握手失败"
            "connection reset" in lower || "broken pipe" in lower || eofToken(lower) -> "连接中断"
            "unauthorized" in lower || "authentication" in lower || "auth fail" in lower -> "鉴权失败"
            else -> s.take(48)
        }
    }

    /** Whole-token "dns" only — avoids matching unrelated substrings. */
    private fun dnsToken(lower: String): Boolean {
        var i = 0
        while (i < lower.length) {
            val start = lower.indexOf("dns", i)
            if (start < 0) return false
            val end = start + 3
            val beforeOk = start == 0 || !lower[start - 1].isLetterOrDigit()
            val afterOk = end >= lower.length || !lower[end].isLetterOrDigit()
            if (beforeOk && afterOk) return true
            i = start + 1
        }
        return false
    }

    private fun eofToken(lower: String): Boolean {
        if (lower == "eof" || lower.startsWith("eof:") || lower.endsWith(" eof")) return true
        return "unexpected eof" in lower
    }
}
