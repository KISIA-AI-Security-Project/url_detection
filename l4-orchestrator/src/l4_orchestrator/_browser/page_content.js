({kind, maxTextBytes, maxLinks, maxLinksBytes}) => {
    // One synchronous read of the assigned main document. No page mutation.
    const encoder = new TextEncoder();
    const byteLength = value => encoder.encode(value).length;
    const result = {
        text: null, text_total_bytes: null, text_truncated: null,
        links: null, links_total: null, links_bytes: null, links_truncated: null
    };
    if (!document.body) throw new Error("The main document has no body.");

    function boundedText(value) {
        const bytes = encoder.encode(value);
        let end = Math.min(bytes.length, maxTextBytes);
        // Keep a complete UTF-8 prefix; do not replace a split character.
        if (end < bytes.length) {
            while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
        }
        return {text: new TextDecoder("utf-8", {fatal: true}).decode(bytes.subarray(0, end)),
                text_total_bytes: bytes.length, text_truncated: end < bytes.length};
    }

    function hiddenLayout(node) {
        for (let current = node; current; current = current.parentElement) {
            const style = getComputedStyle(current);
            if (style.display === "none" || style.contentVisibility === "hidden") return true;
        }
        return false;
    }

    function visibleBox(node) {
        const visibility = getComputedStyle(node).visibility;
        return !["hidden", "collapse"].includes(visibility) &&
            Array.from(node.getClientRects()).some(rect => rect.width > 0 && rect.height > 0);
    }

    function displayedLink(node) {
        if (hiddenLayout(node)) return false;
        if (visibleBox(node)) return true;
        // display:contents has no own box; a visible descendant can also override
        // visibility:hidden. Do not drop links consisting solely of an image.
        for (const child of node.querySelectorAll("*")) {
            if (visibleBox(child)) return true;
        }
        if (getComputedStyle(node).display !== "contents" ||
            ["hidden", "collapse"].includes(getComputedStyle(node).visibility)) return false;
        for (const child of node.childNodes) {
            if (child.nodeType !== Node.TEXT_NODE) continue;
            const range = document.createRange();
            range.selectNodeContents(child);
            if (Array.from(range.getClientRects()).some(rect => rect.width > 0 && rect.height > 0))
                return true;
        }
        return false;
    }

    if (kind !== "links") {
        // Native rendered DOM text, not OCR or a claim about visible pixels.
        // A hidden body/root has innerText's textContent fallback; do not use it.
        const text = hiddenLayout(document.body) ? "" : document.body.innerText;
        Object.assign(result, boundedText(text));
    }
    if (kind !== "text") {
        const links = [];
        let total = 0, size = 2, full = false;  // UTF-8 JSON array bytes include [].
        for (const node of document.querySelectorAll("a[href]")) {
            if (node.namespaceURI !== "http://www.w3.org/1999/xhtml" || !displayedLink(node))
                continue;
            total++;
            if (full) continue;
            if (links.length >= maxLinks) { full = true; continue; }
            const href = node.getAttribute("href");
            let resolved = null;
            try { resolved = new URL(href, document.baseURI).href; } catch {}
            const item = {text: node.innerText, href, resolved_url: resolved};
            const itemBytes = byteLength(JSON.stringify(item)) + (links.length ? 1 : 0);
            if (size + itemBytes > maxLinksBytes) { full = true; continue; }
            links.push(item);
            size += itemBytes;
        }
        Object.assign(result, {links, links_total: total, links_bytes: size,
                               links_truncated: links.length < total});
    }
    result.html = document.documentElement.outerHTML;
    result.url = location.href;
    result.observed_at = new Date().toISOString();
    return result;
}
