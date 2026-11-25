/* Shared helpers for the site's page scripts.

   Loaded before the other extra_javascript files (see mkdocs.yml), which
   read `KeepUtils` from the shared global script scope. */

const KeepUtils = {
  /* Debounce, e.g. for resize handlers, to avoid layout thrashing.
     The last call's arguments are forwarded to fn when it fires. */
  debounce: function (fn, delay) {
    let timer;
    return function () {
      const args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () {
        fn.apply(null, args);
      }, delay);
    };
  },

  /* True when el is a typing context (inputs, textareas, selects,
     contenteditable), where key-nav.js must leave keystrokes
     alone. */
  isTypingTarget: function (el) {
    if (!el || !el.tagName) return false;
    const tag = el.tagName;
    return (
      tag === "INPUT" ||
      tag === "TEXTAREA" ||
      tag === "SELECT" ||
      el.isContentEditable
    );
  },

  /* Site base URL, derived from the header logo's href: the logo
     links to the site root at the right relative depth on every page,
     so it doubles as the base for site-absolute URLs (page-chrome.js
     builds the statusline path from it; key-nav.js clicks the same
     element for the 0 key). */
  siteBase: function () {
    const logo = document.querySelector(".md-header a.md-logo");
    return new URL(logo ? logo.getAttribute("href") : ".", location.href);
  },

  /* The anchor line for in-page vertical positioning — just below the
     fixed header chrome, for the h/l heading motions (key-nav.js). */
  anchorOffset: function () {
    const header = document.querySelector(".md-header");
    return (header ? header.offsetHeight : 0) + 16;
  },

  /* Runs fn once the page is ready and again after every
     navigation.instant page change. Material's document$ BehaviorSubject
     emits on subscribe, so it alone covers the initial load; the
     DOMContentLoaded fallback only matters when the Material bundle (and
     with it instant navigation) is absent. Registering both would run fn
     twice on every full page load. */
  onPageChange: function (fn) {
    if (typeof document$ !== "undefined") {
      document$.subscribe(fn);
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  },
};
