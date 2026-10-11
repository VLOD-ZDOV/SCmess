package org.scmess.app.data

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Asks GitHub for the latest release. Sends nothing but a plain GET. */
object Updates {
    private const val API = "https://api.github.com/repos/VLOD-ZDOV/SCmess/releases/latest"

    data class Release(val version: String, val pageUrl: String, val apkUrl: String?, val notes: String)

    fun latest(): Release {
        val conn = URL(API).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            if (conn.responseCode != 200) throw IllegalStateException("GitHub ответил ${conn.responseCode}")
            val json = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
            val assets = json.optJSONArray("assets")
            val apk = assets?.let { a ->
                (0 until a.length()).map { a.getJSONObject(it) }
                    .firstOrNull { it.optString("name").endsWith(".apk") }?.optString("browser_download_url")
            }
            return Release(json.getString("tag_name"), json.getString("html_url"), apk, json.optString("body"))
        } finally {
            conn.disconnect()
        }
    }

    /** "7.1" > "7.0", "7.0.1" > "7.0"; non-numeric parts are ignored. */
    fun isNewer(remote: String, local: String): Boolean {
        fun parts(v: String) = v.trimStart('v', 'V').split('.', '-').map { it.toIntOrNull() ?: 0 }
        val r = parts(remote)
        val l = parts(local)
        for (i in 0 until maxOf(r.size, l.size)) {
            val d = r.getOrElse(i) { 0 } - l.getOrElse(i) { 0 }
            if (d != 0) return d > 0
        }
        return false
    }
}
