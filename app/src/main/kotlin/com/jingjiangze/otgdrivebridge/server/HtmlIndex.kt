package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.webdav.DavNode
import com.jingjiangze.otgdrivebridge.webdav.WebDavPaths
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * The browser face of the WebDAV server: a single-file HTML file manager
 * served from the very URL the DAV clients talk to.
 *
 * A browser navigation sends `Accept: text/html`; a WebDAV client never does
 * (rclone sends `*/*`, Windows MiniRedir nothing usable), so negotiating on
 * that header is what lets one URL serve both worlds while the 207 multistatus
 * contract for mount clients stays untouched. `?format=html` is the explicit
 * override that makes the page linkable without relying on Accept.
 *
 * The page is a static document whose inline JS speaks the server's own verbs
 * (PUT / DELETE / MKCOL) via fetch. Same-origin means the browser's native
 * Digest handling applies: the initial navigation triggers the 401 prompt
 * once, and the cached credentials ride along on every fetch afterwards —
 * no credentials are ever handled in the page itself.
 */
object HtmlIndex {

    private val MODIFIED_FORMAT: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault())

    fun render(
        segments: List<String>,
        children: List<DavNode>,
        mimeTypeOf: (String) -> String
    ): String {
        val baseHref = WebDavPaths.encodeCollectionHref(segments)
        val title = if (segments.isEmpty()) "/" else segments.joinToString("/")
        // Directories first, then a case-insensitive name sort — the order
        // every file manager the user already knows uses.
        val ordered = children.sortedWith(
            compareByDescending<DavNode> { it.isDirectory }.thenBy { it.name.lowercase() }
        )
        val rows = if (ordered.isEmpty()) {
            """<tr><td colspan="4" class="empty">This folder is empty.</td></tr>"""
        } else {
            ordered.joinToString("\n") { row(baseHref, it, mimeTypeOf) }
        }
        return buildString {
            append("<!DOCTYPE html>\n")
            append("<html lang=\"en\">\n<head>\n")
            append("<meta charset=\"utf-8\">\n")
            append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
            append("<title>OTG Drive Bridge — ").append(htmlEscape(title)).append("</title>\n")
            append(STYLE)
            append("</head>\n<body>\n")
            append("<header>\n  <nav>").append(breadcrumb(segments)).append("</nav>\n")
            append("  <div class=\"actions\">\n")
            append("    <input type=\"file\" id=\"file\" multiple>\n")
            append("    <button onclick=\"upload()\">Upload</button>\n")
            append("    <button onclick=\"mkdir()\">New folder</button>\n")
            append("    <button onclick=\"location.reload()\">Refresh</button>\n")
            append("  </div>\n")
            append("  <div id=\"msg\" class=\"msg\"></div>\n")
            append("</header>\n<main>\n<table>\n")
            append("<thead><tr><th>Name</th><th class=\"num\">Size</th><th>Modified</th><th></th></tr></thead>\n")
            append("<tbody>\n").append(rows).append("\n</tbody>\n</table>\n</main>\n")
            append("<script>\nvar BASE = \"").append(baseHref).append("\";\n")
            append(SCRIPT)
            append("</script>\n</body>\n</html>\n")
        }
    }

    /**
     * Escapes [text] for both text and double-quoted-attribute contexts.
     * [com.jingjiangze.otgdrivebridge.webdav.WebDavXml.escape] is not reused:
     * that one targets XML character data, and an attribute context must also
     * neutralise the quote characters themselves.
     */
    fun htmlEscape(text: String): String = buildString(text.length) {
        for (ch in text) when (ch) {
            '&' -> append("&amp;")
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '"' -> append("&quot;")
            '\'' -> append("&#39;")
            else -> append(ch)
        }
    }

    private fun breadcrumb(segments: List<String>): String {
        val parts = mutableListOf("""<a href="/">OTG Drive Bridge</a>""")
        segments.forEachIndexed { i, segment ->
            val href = WebDavPaths.encodeCollectionHref(segments.subList(0, i + 1))
            parts += """<a href="$href">${htmlEscape(segment)}</a>"""
        }
        return parts.joinToString(" / ")
    }

    private fun row(baseHref: String, node: DavNode, mimeTypeOf: (String) -> String): String {
        // percentEncode leaves only unreserved characters, '/' and '%' — safe
        // to splice into href attributes and into single-quoted JS strings.
        val encoded = WebDavPaths.percentEncode(node.name)
        val childHref = if (node.isDirectory) "$baseHref$encoded/" else "$baseHref$encoded"
        val nameCell = if (node.isDirectory) {
            """<a class="name dir" href="$childHref">${htmlEscape(node.name)}/</a>"""
        } else {
            """<a class="name" href="$childHref" download title="${htmlEscape(mimeTypeOf(node.name))}">${htmlEscape(node.name)}</a>"""
        }
        val delete = """<button class="del" onclick="del('$childHref')" aria-label="Delete">✕</button>"""
        return """<tr><td>$nameCell</td><td class="num">${humanSize(node)}</td><td>${modified(node)}</td><td>$delete</td></tr>"""
    }

    private fun humanSize(node: DavNode): String {
        if (node.isDirectory) return "—"
        val bytes = node.length
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(Locale.ROOT, "%.1f KB", kb)
        val mb = kb / 1024.0
        return if (mb < 1024) String.format(Locale.ROOT, "%.1f MB", mb)
        else String.format(Locale.ROOT, "%.1f GB", mb / 1024.0)
    }

    private fun modified(node: DavNode): String =
        if (node.lastModified <= 0L) "—" else MODIFIED_FORMAT.format(Instant.ofEpochMilli(node.lastModified))

    // No '$' anywhere below: these live inside Kotlin raw strings.
    private val STYLE = """
<style>
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem; }
nav a, nav span { text-decoration: none; }
.actions { display: flex; gap: .5rem; margin: .75rem 0; flex-wrap: wrap; align-items: center; }
.msg { min-height: 1.2em; color: #b00; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .35rem .6rem; border-bottom: 1px solid rgba(128,128,128,.35); }
th.num, td.num { text-align: right; white-space: nowrap; }
a.name { text-decoration: none; }
a.dir { font-weight: 600; }
button.del { border: 0; background: none; color: #b00; cursor: pointer; padding: 0 .3rem; }
.empty { color: #888; text-align: center; padding: 2rem 0; }
@media (prefers-color-scheme: dark) { .msg, button.del { color: #f77; } }
</style>
"""

    private val SCRIPT = """
function say(text) { document.getElementById('msg').textContent = text; }
function send(method, url, body) {
  return fetch(url, { method: method, body: body, credentials: 'same-origin' })
    .then(function (r) {
      if (!r.ok) { throw new Error(method + ' ' + url + ' failed: HTTP ' + r.status); }
      return r;
    });
}
function upload() {
  var input = document.getElementById('file');
  var files = input.files;
  if (!files || files.length === 0) { say('Pick a file first.'); return; }
  say('Uploading…');
  var jobs = [];
  for (var i = 0; i < files.length; i++) {
    jobs.push(send('PUT', BASE + encodeURIComponent(files[i].name), files[i]));
  }
  Promise.all(jobs).then(function () { location.reload(); },
                        function (e) { say(e.message); });
}
function mkdir() {
  var name = window.prompt('New folder name');
  if (!name) { return; }
  send('MKCOL', BASE + encodeURIComponent(name))
    .then(function () { location.reload(); }, function (e) { say(e.message); });
}
function del(url) {
  var parts = url.split('/').filter(function (s) { return s.length > 0; });
  var name = parts.length > 0 ? decodeURIComponent(parts[parts.length - 1]) : url;
  if (!window.confirm('Delete ' + name + '?')) { return; }
  send('DELETE', url).then(function () { location.reload(); },
                            function (e) { say(e.message); });
}
"""
}
