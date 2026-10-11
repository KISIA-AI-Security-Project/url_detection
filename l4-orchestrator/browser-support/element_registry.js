import { computeAccessibleName, getRole } from 'dom-accessibility-api';

// Keep actual node identity in this handle's closure, not in page attributes.
// Main-document light DOM only; custom JS-only handlers are not inferred.
const selector = 'button,a[href],area[href],input:not([type="hidden"]),textarea,select,[role]';
const supportedRoles = new Set([
  'button', 'link', 'textbox', 'searchbox', 'combobox', 'listbox',
  'checkbox', 'radio', 'spinbutton', 'slider',
]);

function supported(element) {
  if (element.matches('input[type="hidden"]')) return false;
  return element.matches('button,a[href],area[href],input,textarea,select') ||
    supportedRoles.has(getRole(element));
}

function visible(element) {
  const box = element.getBoundingClientRect();
  const visibility = getComputedStyle(element).visibility;
  return box.width > 0 && box.height > 0 && !['hidden', 'collapse'].includes(visibility);
}

function enabled(element) {
  if (element.matches(':disabled') || element.closest('[inert]')) return false;
  const ariaOwner = element.closest('[aria-disabled="true" i],[aria-disabled="false" i]');
  return ariaOwner?.getAttribute('aria-disabled').toLowerCase() !== 'true';
}

export function createRegistry(prefix) {
  const ownerDocument = document;
  const byNode = new WeakMap();
  const byId = new Map();
  let nextId = 0;

  function current(node) {
    return document === ownerDocument && node.isConnected &&
      node.getRootNode() === ownerDocument && supported(node);
  }

  return {
    collect(visibleOnly) {
      for (const [id, node] of byId) {
        if (!current(node)) {
          byId.delete(id);
          byNode.delete(node);
        }
      }
      const elements = [];
      for (const node of document.querySelectorAll(selector)) {
        if (!supported(node)) continue;
        const isVisible = visible(node);
        if (visibleOnly && !isVisible) continue;
        let id = byNode.get(node);
        if (!id) {
          id = `${prefix}_${++nextId}`;
          byNode.set(node, id);
          byId.set(id, node);
        }
        elements.push({
          element_id: id,
          role: getRole(node) || node.localName,
          name: computeAccessibleName(node, { computedStyleSupportsPseudoElements: true }),
          // Input/textarea values are not page text and are not returned.
          text: ['input', 'textarea'].includes(node.localName) ? '' :
            (node.innerText ?? node.textContent ?? '').replace(/\s+/g, ' ').trim(),
          visible: isVisible,
          enabled: enabled(node),
          // Runtime properties can differ from the initial HTML checked attribute.
          ...(node.namespaceURI === 'http://www.w3.org/1999/xhtml' && node.tagName === 'INPUT' &&
              ['checkbox', 'radio'].includes(node.type) ? {
            checked: node.checked,
            ...(node.type === 'checkbox' ? { indeterminate: node.indeterminate } : {}),
          } : {}),
          // Native select choices are needed to specify select_option without guessing.
          ...(node.namespaceURI === 'http://www.w3.org/1999/xhtml' && node.tagName === 'SELECT' ? {
            multiple: node.multiple,
            options: Array.from(node.options, (option, index) => ({
              index, value: option.value, label: option.label,
              enabled: enabled(node) && enabled(option),
              selected: option.selected,
            })),
          } : {}),
        });
      }
      return { elements, html: document.documentElement.outerHTML, url: location.href };
    },
    resolve(id) {
      const node = byId.get(id);
      return node && current(node) ? node : null;
    },
    resolveForWait(id) {
      // Waiting can observe removal of the original node. Never rematch it.
      return document === ownerDocument ? byId.get(id) || null : null;
    },
  };
}
