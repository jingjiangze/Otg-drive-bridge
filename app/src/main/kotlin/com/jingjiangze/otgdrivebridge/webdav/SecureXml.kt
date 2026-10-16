package com.jingjiangze.otgdrivebridge.webdav

import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Document
import org.xml.sax.InputSource

/**
 * The one XML parse entry point for every request body this server reads.
 *
 * It exists because three parsers used to build their own
 * `DocumentBuilderFactory` with the same hardening pasted in, and each one
 * guarded it differently — and the difference is what made PROPFIND and
 * `sync-collection` answer 400 for every well-formed body **on the device**
 * while every unit test stayed green.
 *
 * The mechanism, since it is invisible from a test: Android's XML stack does
 * not implement `disallow-doctype-decl` (nor the two `xml.org/sax/features`
 * switches), and `DocumentBuilderFactory.setFeature` throws
 * `ParserConfigurationException` for a feature it does not know rather than
 * ignoring it. The desktop JVM every unit test runs on *does* implement all
 * three, so the call never threw there. Two parsers called `setFeature` in the
 * open, inside a `runCatching` that was meant to cover only the parse — the
 * throw was swallowed, `parse` returned null, and the handler turned that into
 * a malformed-body 400. The third wrapped the same call in its own
 * `runCatching` and kept working, which is what identified the cause: the
 * surviving parser was the only one that tolerated the feature being unknown.
 *
 * So every feature is set best-effort, and the hardening is still real: with
 * `isNamespaceAware` on and no DOCTYPE reaching the builder, the parser has no
 * external entity to resolve. A platform that refuses a switch is not a reason
 * to reject the request — it is a reason to proceed without it.
 */
internal object SecureXml {

    fun parse(body: String): Document? {
        if (body.isBlank()) return null
        return runCatching {
            val factory = DocumentBuilderFactory.newInstance()
            // Namespace awareness is mandatory and is not optional here: the
            // element *name* is meaningless without knowing which namespace it
            // is in, and an unaware parser silently merges `Z:author` from two
            // different namespaces into one property.
            factory.isNamespaceAware = true
            // XXE: a WebDAV body is untrusted input, and this server is
            // reachable from the LAN. Each switch is set individually and none
            // of them may fail the parse — see the class comment.
            setFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature(factory, "http://xml.org/sax/features/external-general-entities", false)
            setFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false)
            factory.newDocumentBuilder().parse(
                InputSource(ByteArrayInputStream(body.toByteArray(Charsets.UTF_8)))
            )
        }.getOrNull()
    }

    private fun setFeature(factory: DocumentBuilderFactory, name: String, value: Boolean) {
        runCatching { factory.setFeature(name, value) }
    }
}
