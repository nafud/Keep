/* theme.js: puts the theme that the reader chose on the root, before the page is drawn. It is
   loaded in the head and not deferred for that reason. The choice is made with the key t
   (keep.js) and kept in the storage of the browser for this site. Without a choice, without
   this file and where the storage is refused, the page has the first theme, terminal. */
(function () {
  "use strict";
  try {
    const theme = localStorage.getItem("keep-theme");
    if (theme === "light" || theme === "dark" || theme === "phosphor" || theme === "nord") {
      document.documentElement.setAttribute("data-theme", theme);
    }
  } catch (refused) { /* the first theme stays */ }
})();
