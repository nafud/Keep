/* Generative ASCII homepage logo.

   Renders CONFIG.text with the CONFIG.fontFamily webfont onto an offscreen
   canvas, samples glyph coverage per character cell, and maps it onto an
   ASCII density ramp inside <pre class="keep-ascii">. The grid is derived
   from the measured character cell and the available container width plus a
   viewport-height budget, so the logo always fits without scrollbars.

   The grid is generated exclusively from the real CONFIG.fontFamily
   webfont — never from a fallback font, whose different metrics and
   shapes would produce a wrong-looking logo that then sticks. The font
   ships embedded in this file as a data: URI (CONFIG.fontDataUrl, a
   tiny subset holding only CONFIG.text's glyphs) and is registered
   through the FontFace API, so no network fetch stands between first
   paint and the build. Until verification succeeds (see ensureLogoFont)
   the pre keeps its plain-text fallback, styled as a title by extra.css
   but kept invisible for JS visitors (the keep-js rule there) so the
   title never paints before the grid; a pure-CSS delayed reveal shows
   it anyway if generation never comes, with no JS failure path needed.
   CONFIG.generatedClass switches the pre to grid sizing.

   The logo is static by itself; pointer movement drives a shimmer animation
   whose intensity envelope eases in and out. A page's first generated
   frame enters through the same machinery, starting at full envelope and
   decaying, so the logo materializes out of glitch noise instead of
   snapping from the text fallback (see rebuild). Idempotent and safe to
   re-run on navigation.instant page changes, same as page-chrome.js. */

(function () {
  "use strict";

  const CONFIG = {
    text: "Keep",
    fontFamily: "Keep Blackletter",
    fontFallback: "serif",
    /* UnifrakturMaguntia Book subset to CONFIG.text's glyphs (K e p),
       a 3.7 KB woff2 embedded so the face loads with zero network
       round trips — the render happens within frames of first paint.
       SIL OFL 1.1 (docs/assets/fonts/UnifrakturMaguntia-OFL.txt); the
       licence reserves the font's name for the unchanged font, so the
       subset carries another name. The TTF is from
       github.com/google/fonts, ofl/unifrakturmaguntia. Regenerate
       whenever CONFIG.text gains a new character or the font changes:
         pyftsubset UnifrakturMaguntia-Book.ttf --text="Keep" --flavor=woff2 \
           --layout-features='' --name-IDs="0,1,2,3,4,5,6,13,14" \
           --output-file=keep-blackletter.woff2
       then set the name records 1, 3, 4 and 6 to the new name with
       fontTools, and
         base64 -w0 keep-blackletter.woff2 */
    fontDataUrl:
      "data:font/woff2;base64,d09GMgABAAAAAA5MABEAAAAALlQAAA3xB9oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGhYbIBwwBmAARAgeCYJzERAKhzCGWQE2AiQDEAsKAAQgBcsIByAMgRYbyywjEZasrlGUgtFqRJUmDv6ZwJNBzSPUE+0Q6Iw40U68G/0wqsOGTaS7yD9j5DIoPPB0Zu+PkiwqZa+dJZASzBZg6jnAQQ9mAqABVhBw/6jzrQf0DjaCV2CVwYmVfgeMSXGS5edYNUgnyUmzrncbL/NZ/X5qs2EbFwuoUfhI9d4P3QugYyypXxlVx6pG1dYFXRHH1zVSVFhX/235r3hcobUyQF9GBtC4htEw+76zc2RdHQ2ORqsR3/Q2uzt+Lf8jt0J/WKdhVlCQYRQIQkgQDnUAi4J6rS8ohaZrtolB/e3e9/RK6IkMMoiIBAnZ51EIwA8AkBAIZP098CGAgYiSspoWzCgAXi8A9FliiEOe1WviqOmTGDh11NzpdNoMuFpWwsROVFAPqskgQg0PZ46XAMlXk1VZ8vwUQADQZ1JANTO18v/+N2UJeh+plKurAB0VkAAZ6PUNKX2MQgJgxowEVDOOmTRsLvTe8R7x7rl0A6Owk0I+w4U/LwDx/6/yUz5CKwcDYqoNLA0d14XYbjOEd51ByX33Y0EeMTzWQMToeumkEocYGWsgxRiIqED6KTlGL3PIoWVNHcE2fbO+uXLsZr1MnzhqrEMJVbzhVeM22+J1B80dk3QHLR2BjgKb1e0bZ7NlxRoo+1QKm2rrZfrkTarJXNzlv9ijxlTrDjmsoaOxw7GyxMqpRG4PDNRLHY+lBcVjFOi4SGsP5ml52aR+T4cpq0WJhHkbNSsqEC1smzfDWnCgY6XqWDcH28x5Bo/JgAJNQd5g8145tNQQKxtaaCWNWTmLmc7YrP6sklgDS0x1c0dpCWRy42IBGTMS3RBeLzIACgBmQAU+BjECAAgAXgQEEtJI3a8gvj5L9h3q425zu1uczlaXM2Foe8v5i9H7PFuY0dX8pnv32+2eT1o/+ayrd/pquMdTmfF524f3Wjv77uvjhuKj9hnh546EtNhX9n7epWrt565EINYh7d5dcfpo+KiDD2Rrb7e/6WmR97cdCPEZae/tar/rgV5OZ439zvDOzr7t+/oMPhjyknPJQ65WKgIr5JGyzt4nXLmuFmcgt/c5+0LYXjvO3Lazfdxvt+11lANIdM/YIsQqd9vRR6LcpnDpwqK7UOWW+jVPu8f++7XY6bQdqLjhWiudLtCTNkRMvlBSn9qQKn+a37L+wfjvl83at+W1qHHr2+YUJq26lLLx1KaNrRNTCkfF31g5/6UpC0ZOHuo3YETGqxt//FjSRG2W6UNpxpbzY1N/aL06Li9lkzRFNfyD3jb5SX/1K5+bcuOWv9lW8ezvo2VUxozo9rjJb445MeWb9Z09Ti8bdzd1U9ndeVH/FX/83f61a4fnLXg+fI11yLDR++7/ZWlss7XvF//Y2uEfqst8A87YTx8oaui19uEdjQc16cDR2wEJ7322dFZ0xrmnGyJ2tx5dFzw032SscdZ/NnxR1LpruyJ/Aj49/rClrahna//0pjbLZ7OXV64bP++Pvp051crizf6X/N9YO2P3krqph5/bbt0+53Mf3ykQQl7tNTF3Z0yvhSE9LMsHrB4bcmRjWBdOHrR07Tao07xKGhpwrHBw1cBb44f1sPuu2e+3OnJkpvXzpe8nbxLjxeS280k1KZWr8uw+vv38tvgdnQkQ4X1fq1Kvke31SA7FD9P/k+QZyv0PEolGEkp0oS8WkuhPEpEkkUkSlSShDjOI7GYw6t2ExAepRyMeJfpBeqJRNd7XqKdPiDCkoUyiqM9qr9FEfPArDFINkt9POtqvRnIlmTyEgnxBPAyqUIUqVCWr/l+DQaOmEc1oFj3RL2l/NyERAaa3SfPbc3BE15zfzIPMADzfazwAX0Sum/Vv0f/d9qBpNmBGAkCAVv6fF8xvv+v/WzalwB8JKOqv3sPaciKkz7LlQ5gQt+MvU1hV198FH5CQ1iIhAAuzkRGKBcRCuLIJdLHQJmEW+20ys8Xxg8qoTSVM6mHTiJAybP5Bq6WRP9mFlJCPP8FUm4NV28bjOXker1+9dhXfXsazvZANcMf96LxJ+eaxOTmyO6pwpoffXGPRk+tmUPXfJlo/2pXYjoNX4jIgGq7ee2xKniy+ULSlTuhysG6UAxIFQP0B415YMAy+qFOSBmfCsFRpdL75+1hES0wMDcf2Uigwfy6SnRod8drlv77cgsjgpBOy7Qzh/PUmWrfj/zzu47Y7mMbhAgkN6pp7QuUpcIbh1qUkXHvn+k3EW3CkS6LNMTsMO19ldv4ns5OA0/qEcslBCshLa1nvxV3gxQcfFJ3TFxfvhOq+X3bkkwvkHGTvo78PfP+cN/evXHHSKuPdZaeIflDb7ZWJ4Mu3/x+49JdN8OFCyuMLSbzO0fT2yQr+a8ZLUfLbEh+k0o6RSIeIvap3jP4xSHMerCZLHhqnYpH2HVXCeLbGcsBzTpbzmIHOa3cJzP0YIfnD/M9dFaWxIviHdpHMpteQR0J01YUwayvo6lnBGu4NY2n3lo57x2DG0RiJ5C1Wr0GK5O1uBFSPBUs6q8pyAe09i5gdpM6H0pEyL/nmPYduUMcUuV8BSgvacUG2vEZL9GQA2hOMoABBNbeIYZS9QUiNTdh4qxeH5L+FrnFsu8p/6oECRelsBA8N8TelBw1Uget/YohFaYoIyOpQVzjJOTFXkTV68frQOCgWrnfGSt3kXh+qfyM7WO29+apV5ehHI2nvCEmUp2s/cR2BNw8BD4P7c9BdmabDg9w74bwjJsJjEwyKER5kZycq+yCIGXHzp1eBp+OQcfkoUlI5W1JHxoBCWarqbikVkvMrapVJuk3MHW7iTcdYFZUHhX+8y87zAQxR3uko03e+trEh8dcgzc3LrIhm0IQTNbRhGRNoKMlE6PaIaU6rVR4y+q4mqpDJyBO7d2f8bVQXLEHU0Hw2MC6R07pXLOsBQ6WZR4OjMCYFAnkG8Qe1HJFYlKSQXHz3ef6buuU8gbJOsDQ+G/JZFIdh7cnMfVJwomfpBA+v5cmIUA86miVdrR5LztM6yfuwKw7gKBe/FbLn3Hn+DKKktmzteH+V2hTKTawim5BsqgrfhuqA0dfXo5UkVgxSSa57GMFm3OYc7N055IkOvswPRqpOe+eMZGHPEsgo3K5a8uOAbO9y4EwO/KEFJY+MXhBT/a0pRmwfhSSfGKpl4eTs74zepDp6rIMKbo/hZZB2d61mYPtr29RR33d6RLvkxIKQ2CvWQQx0DGR9VdmIih8HHVvpVMNgbbDLrEwnehSR2VEXEq9HDwdhSMzoKBtxADjWsBFhtcVHbJV1FTYEhPwdXvMe4Q92yqYhztFhD/h5o9jsZnBlO8yzRKZEd3Fia9sjU3+fPZEYByWJZbBniExGCtWkk0Ha1O7BnZ1D1IndyAsUXpzyfBUVxWTIeCYldrUrnBg5Jc+Kch7HhRbYIgfBQAPeFmvcBsRABPsIYsSnzb+lSz+REYkCxLrN6LbZpyI7UNV4y4FJ46r0BMrWN9mK7cnS9neWCdvrd+o6NZvPzBA3C3fmTF8GYlVwcZsMSqj71QGEGbFSqWLO7n5sfvfaeYxJBbU9nWHYbatGKvtSuui4GqtktoDEJvUerB4otRX2ox1b2Oplg3hvUVcn5rldP699m4JKxCXLx79zzTgMO0W7RCalbw5pSGi1emKbgGk33S9iS0aXIzx73tI+b5f1elY1N8LXMWUHktcbLolFNNCBp3eTHS803r/pUjvfrDZ0am7gdkBZoIqFDFn7R1I7mriVxeyYVQm9/J39E4hOniZ3QohGCOPlGXdjNLd8CZcmXOvVvIWdXqph++7Bnn3HYsXKZujkjaeMdWJu80FVPl3aq89CtWSAkp3GUyaCrtTjlLYTnWrhJOTsm2TDNMiu6TJFG2daUyetFxZIoQKm2nMati0ydvZR90YoN/uggBKXCTZqGc0noKFp0HG5M9yMmaUsqdcet5nn49da9rZqsH0ucjeHWVztIGhocmtYej3NT1LW9ox4WVRxQ1/lUrqqyabQi0XvuCQzpfEtIMPUvv63t0GfboGQnedyBMCbZdz027adKtxBtKbo8oD4nL7V1uPmO9STaHscDVuGRgb6MDAay6YtclGU3W82bys22EnFOoyzK2zzPmzp3Dxa3H9dd7j0WuJloHWlObsucbC8LPuWHcija9KAxoKIbo07rS6eTNWLMjvPfIfm/vUcYM4D/2XCqJgug2jF8+PhI/5tslsFCLPxRZD/dnP+L2CaJ8+jkId4IijGblwdMHxhwjnZSEIq54HG+VfoeG2HL2h6mI3MX2o5XxUDhtyAx3QZaTu76eJp3oRXbz3DiW6Jk2/1mVNaA5d1oj4JZwoqAAV8hunR0BhMIlmz0TG0qxTjanZ2AZqCSefphrjnt2Hz0TQpOI5CaI+tDLPcknMQA3AAw6Kc01eDN463jtZMUesHdu1rWx7KmHpZMJZK3H4wRzFdZgqcTyJ/zqNgHN5aLlFiH7w7Oj4sQ41hwj1Q8K1JUuIbY7jCzGGArWdeTL5StH7bC1Ggkkl6LBICZ6Y+mfJpdIPw5Si/31zHCyFHANKSZdxXmI9DthmE7A4wgzyYjfhG3gr+kablgfD1KvCSWL4G2Lem4y+Sd5LnIL8EDYdAKaGMNPZaTLw2YUwJYM25B+B4W1FQkgjb4GQXci1BVWg3y/NhXP4RhLN/4E8POf0pfOT9xJ+a9/4F/33q7uVT337lmMV/wurJtZNf/9f6RyX//77izcMPi+yPPZoL/op3cnVHqGDvyR+//ep1JX+afOiTDH6cFQAA",
    generatedClass: "keep-ascii--generated",
    /* Density ramp for the static frame: darkest ink first, background
       (space) last. Kept short on purpose — a long ramp turns
       anti-aliased edge cells into mid-density glyph mush and the
       silhouette stops reading. */
    charRamp: "$@B%8&WM#*oa+=~-:. ",
    /* Density ramp for animated frames only: the long alphabet the
       shimmer scrambles through — close to the full printable-ASCII
       set, ordered darkest ink to background. The pointer-driven
       glitch reads as terminal noise because a displaced cell can
       land on many distinct glyphs per swing — on the short static
       ramp the same fractional swing collapses to a couple of steps
       and most frames change nothing, which reads as slow and dull.
       Cells the wave has not displaced keep their exact static glyph
       (see buildFrame), so the effect settles seamlessly back into
       the crisp frame. */
    glitchRamp: "$@B%8&WM#NHKDGERSAPVFT*oahkbdpqwmZO0QLCJUYXzcvunxrjfteysg9654327/\\|()1{}[]?=-_+~<>i!lI;:,\"^`'. ",
    referenceFontPx: 200,        /* offscreen measuring/drawing font size */
    supersample: 3,              /* canvas pixels sampled per cell axis */
    inkFill: 0.94,               /* fraction of the grid the glyphs fill */
    maxViewportHeightRatio: 0.42,/* height budget so the page never scrolls */
    /* Contrast curve: coverage below the floor is background (a bare
       few antialiased pixels must not speckle the field with dots),
       above the ceiling is solid ink; the ramp spans only the band
       between, so edges get a short gradient and interiors stay
       dense. */
    coverageFloor: 0.1,
    coverageCeil: 0.82,
    staticJitter: 0.14,          /* per-cell ramp offset, as a ramp fraction */
    animAmplitude: 0.2,          /* shimmer swing, as a ramp fraction */
    animSpeedRadPerMs: 0.006,
    waveDetune: 1.7,             /* frequency ratio of the secondary wave */
    /* The shimmer intensity is an envelope that eases in on movement and
       eases out after the cursor stops, rather than snapping on/off. */
    idleDelayMs: 150,            /* movement gap treated as "cursor stopped" */
    attackMs: 120,               /* shimmer fade-in time */
    /* Fade-out after the cursor stops. Deliberately much longer than
       the attack: the smoothstepped envelope then thins the noise out
       cell by cell over a full second-plus, instead of the abrupt
       cut a short release reads as. */
    releaseMs: 1400,
    resizeDebounceMs: 150,
    probeColumns: 40,            /* sample size for character cell measuring */
  };

  const state = {
    pre: null,
    cols: 0,
    rows: 0,
    baseIndices: null,  /* Int16Array: jittered static ramp index per cell */
    glitchBase: null,   /* Int16Array: the same density on the glitch ramp */
    phases: null,       /* Float32Array: per-cell animation phase */
    ink: null,          /* Uint8Array: 1 where the cell contains glyph ink */
    staticFrame: "",
    buildSignature: "", /* grid + font metrics of the last generated frame */
    rafId: 0,
    lastMoveAt: 0,
    lastTickAt: 0,
    envelope: 0, /* current shimmer intensity, 0 (static) .. 1 (full) */
  };

  /* MediaQueryList objects are live, so one instance stays correct even if
     the user toggles the OS setting. */
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  function clampIndex(index) {
    return Math.min(CONFIG.charRamp.length - 1, Math.max(0, index));
  }

  function clampGlitchIndex(index) {
    return Math.min(CONFIG.glitchRamp.length - 1, Math.max(0, index));
  }

  /* Perceptual easing for the envelope: the raw phase ramps linearly, and
     a linear amplitude fade reads as an abrupt stop. Smoothstep flattens
     the curve at both ends, so the shimmer swells in and dies away. */
  function smoothstep(x) {
    return x * x * (3 - 2 * x);
  }

  /* Deterministic per-cell pseudo-random value in [0, 1). Stable across
     frames so the static logo doesn't flicker between rebuilds. */
  function cellHash(x, y) {
    const s = Math.sin(x * 127.1 + y * 311.7) * 43758.5453123;
    return s - Math.floor(s);
  }

  function cssFont(px) {
    return px + 'px "' + CONFIG.fontFamily + '", ' + CONFIG.fontFallback;
  }

  /* Loads and registers the embedded logo font (memoized). The face is
     added to document.fonts through the FontFace API, so there is no
     <link> for navigation.instant's head reconciliation to strip —
     once added, the face stays for the life of the document, and the
     stylesheet-eviction serif-logo bug this replaced cannot recur. A
     data: URI cannot fail transiently, so a failure here (no FontFace
     API, malformed data) is deterministic and memoizing it is safe;
     the text fallback then simply stays. */
  let fontFacePromise = null;
  function loadFontFace() {
    if (!fontFacePromise) {
      fontFacePromise =
        typeof FontFace === "undefined" || !document.fonts
          ? Promise.resolve(false)
          : new FontFace(CONFIG.fontFamily, 'url("' + CONFIG.fontDataUrl + '")')
              .load()
              .then(function (face) {
                document.fonts.add(face);
                return true;
              })
              .catch(function () {
                return false;
              });
    }
    return fontFacePromise;
  }

  /* Second, belt-and-braces verification: the canvas must actually
     shape CONFIG.text differently with the logo font than with the
     bare fallback. Some privacy modes (canvas-fingerprint protection)
     report a webfont as loaded in document.fonts yet draw canvas text
     with a standardized font — the one failure the FontFaceSet check
     above cannot see, and exactly what puts a generic-font grid on
     screen. Genuinely different faces differ in width or bounds by
     whole pixels at the reference size; the epsilon only absorbs
     measurement noise, so a browser that refuses to shape the real
     font fails this and the text fallback stays. */
  function logoFontRendered() {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return false;
    const metrics = function (font) {
      ctx.font = font;
      const m = ctx.measureText(CONFIG.text);
      return [
        m.width,
        m.actualBoundingBoxAscent || 0,
        m.actualBoundingBoxDescent || 0,
      ];
    };
    const logo = metrics(cssFont(CONFIG.referenceFontPx));
    const fallback = metrics(
      CONFIG.referenceFontPx + "px " + CONFIG.fontFallback
    );
    return logo.some(function (value, i) {
      return Math.abs(value - fallback[i]) > 0.5;
    });
  }

  /* Resolves true once the logo font is verifiably usable: the
     embedded face is loaded AND the canvas really shapes text with it
     (logoFontRendered). Success is remembered; a failed render check
     is re-run on any later trigger (a page revisit, a fonts
     "loadingdone" event), which costs only a canvas measurement. */
  let fontReady = false;
  function ensureLogoFont() {
    if (fontReady) return Promise.resolve(true);
    return loadFontFace().then(function (loaded) {
      fontReady = loaded && logoFontRendered();
      return fontReady;
    });
  }

  /* Measures the rendered size of one monospace character cell inside the
     pre, so grid math follows whatever font/line-height the CSS defines. */
  function measureCharCell(pre) {
    const probe = document.createElement("span");
    probe.style.cssText =
      "position:absolute; visibility:hidden; white-space:pre; display:inline-block;";
    const row = "0".repeat(CONFIG.probeColumns);
    probe.textContent = row + "\n" + row;
    pre.appendChild(probe);
    const rect = probe.getBoundingClientRect();
    pre.removeChild(probe);
    return { width: rect.width / CONFIG.probeColumns, height: rect.height / 2 };
  }

  /* Tight ink bounding box of the logo text at the reference font size. */
  function measureInkBox(ctx) {
    ctx.font = cssFont(CONFIG.referenceFontPx);
    const m = ctx.measureText(CONFIG.text);
    const left = m.actualBoundingBoxLeft || 0;
    const right = m.actualBoundingBoxRight || m.width;
    const ascent = m.actualBoundingBoxAscent || CONFIG.referenceFontPx * 0.8;
    const descent = m.actualBoundingBoxDescent || CONFIG.referenceFontPx * 0.2;
    return {
      left: left,
      ascent: ascent,
      width: left + right,
      height: ascent + descent,
    };
  }

  function availableWidth(container) {
    const style = getComputedStyle(container);
    return (
      container.clientWidth -
      parseFloat(style.paddingLeft) -
      parseFloat(style.paddingRight)
    );
  }

  /* The logo's height budget: the viewport-ratio cap, tightened by the
     article's actual free height, or a short window grows a scrollbar
     the ratio cap alone would have allowed. The free height comes from
     the homepage's own layout mechanics (extra.css): the column is
     flex-stretched to the viewport bottom and the attribution's
     margin-top:auto absorbs exactly the unused column height, so the
     pre may grow into that slack 1:1 — its current height plus the
     auto margin's used value is the true capacity. Without the pinned
     attribution to read the slack from, the ratio cap stands alone. */
  function heightBudget(pre, container) {
    const ratioCap = window.innerHeight * CONFIG.maxViewportHeightRatio;
    const pinned = container.querySelector(".home-attribution");
    if (!pinned) return ratioCap;
    const slack = parseFloat(getComputedStyle(pinned).marginTop) || 0;
    const free = pre.getBoundingClientRect().height + slack;
    return Math.min(ratioCap, free);
  }

  /* Grid dimensions that preserve the glyph aspect ratio while fitting both
     the container width and the height budget. */
  function computeGrid(pre, cell, inkBox) {
    const container = pre.parentElement;
    if (!container) return null;

    const maxHeight = heightBudget(pre, container);
    const cellAspect = cell.height / cell.width;
    const inkAspect = inkBox.height / inkBox.width;
    const rowsForCols = function (cols) {
      return Math.max(1, Math.round((cols * inkAspect) / cellAspect));
    };

    let cols = Math.floor(availableWidth(container) / cell.width);
    let rows = rowsForCols(cols);
    /* Shrink until the height budget truly holds: rowsForCols rounds, so a
       single proportional scale-down can land a fraction of a row over. */
    while (cols > 1 && rows * cell.height > maxHeight) {
      cols = Math.min(
        cols - 1,
        Math.floor((cols * maxHeight) / (rows * cell.height))
      );
      rows = rowsForCols(cols);
    }
    if (cols < 2 || rows < 2) return null;
    return { cols: cols, rows: rows };
  }

  /* Draws the logo text into a supersampled offscreen canvas and returns the
     average glyph coverage (0..1) for every cell of the grid. */
  function sampleCoverage(canvas, ctx, grid, inkBox) {
    const ss = CONFIG.supersample;
    canvas.width = grid.cols * ss;
    canvas.height = grid.rows * ss;

    /* Resizing resets canvas state, so configure the context afterwards. */
    ctx.font = cssFont(CONFIG.referenceFontPx);
    ctx.fillStyle = "#000";
    const scaleX = (canvas.width * CONFIG.inkFill) / inkBox.width;
    const scaleY = (canvas.height * CONFIG.inkFill) / inkBox.height;
    const originX = (canvas.width - inkBox.width * scaleX) / 2 + inkBox.left * scaleX;
    const originY = (canvas.height - inkBox.height * scaleY) / 2 + inkBox.ascent * scaleY;
    ctx.setTransform(scaleX, 0, 0, scaleY, originX, originY);
    ctx.fillText(CONFIG.text, 0, 0);

    const alpha = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    const coverage = new Float32Array(grid.cols * grid.rows);
    for (let y = 0; y < grid.rows; y++) {
      for (let x = 0; x < grid.cols; x++) {
        let sum = 0;
        for (let sy = 0; sy < ss; sy++) {
          for (let sx = 0; sx < ss; sx++) {
            const px = x * ss + sx;
            const py = y * ss + sy;
            sum += alpha[(py * canvas.width + px) * 4 + 3];
          }
        }
        coverage[y * grid.cols + x] = sum / (ss * ss * 255);
      }
    }
    return coverage;
  }

  /* Converts coverage into per-cell render data: a jittered ramp index (for
     an organic, hand-scrambled look), an ink mask, and an animation phase. */
  function buildCells(grid, coverage) {
    const count = grid.cols * grid.rows;
    const maxIndex = CONFIG.charRamp.length - 1;
    const glitchMax = CONFIG.glitchRamp.length - 1;
    state.cols = grid.cols;
    state.rows = grid.rows;
    state.baseIndices = new Int16Array(count);
    state.glitchBase = new Int16Array(count);
    state.phases = new Float32Array(count);
    state.ink = new Uint8Array(count);

    const band = CONFIG.coverageCeil - CONFIG.coverageFloor;
    for (let y = 0; y < grid.rows; y++) {
      for (let x = 0; x < grid.cols; x++) {
        const i = y * grid.cols + x;
        const hash = cellHash(x, y);
        /* Contrast curve (see CONFIG): 0 below the floor, 1 above the
           ceiling, linear across the band between. */
        const density = Math.min(
          1,
          Math.max(0, (coverage[i] - CONFIG.coverageFloor) / band)
        );
        const isInk = density > 0;
        /* The same jittered density lands on both ramps: the short one
           renders the static frame, the long one is where the shimmer
           swings (buildFrame). */
        state.baseIndices[i] = clampIndex(
          Math.round(
            (1 - density) * maxIndex +
              (isInk ? (hash - 0.5) * CONFIG.staticJitter * maxIndex : 0)
          )
        );
        state.glitchBase[i] = clampGlitchIndex(
          Math.round(
            (1 - density) * glitchMax +
              (isInk ? (hash - 0.5) * CONFIG.staticJitter * glitchMax : 0)
          )
        );
        state.phases[i] = hash * Math.PI * 2;
        state.ink[i] = isInk ? 1 : 0;
      }
    }
  }

  /* Builds one text frame. Pass null for the static frame; pass a
     timestamp to shimmer the ink cells. Two detuned sine waves per cell
     give an organic ripple, and the swing is scaled by the current
     envelope so the shimmer eases in and out. Animated displacement
     happens on the long glitch ramp, whose alphabet is what makes the
     effect read as terminal noise; a cell the wave displaces by less
     than one step keeps its exact static glyph, so the frame converges
     on the static one as the envelope dies and the handoff is
     seamless. */
  function buildFrame(nowMs) {
    const glitchMax = CONFIG.glitchRamp.length - 1;
    const swing =
      CONFIG.animAmplitude * glitchMax * smoothstep(state.envelope);
    const angle = nowMs === null ? 0 : nowMs * CONFIG.animSpeedRadPerMs;
    const lines = [];
    for (let y = 0; y < state.rows; y++) {
      let line = "";
      for (let x = 0; x < state.cols; x++) {
        const i = y * state.cols + x;
        if (nowMs !== null && state.ink[i]) {
          const wave =
            0.7 * Math.sin(angle + state.phases[i]) +
            0.3 * Math.sin(angle * CONFIG.waveDetune + state.phases[i] * 2);
          const displacement = wave * swing;
          if (Math.abs(displacement) >= 0.5) {
            line += CONFIG.glitchRamp[
              clampGlitchIndex(state.glitchBase[i] + Math.round(displacement))
            ];
            continue;
          }
        }
        line += CONFIG.charRamp[state.baseIndices[i]];
      }
      lines.push(line);
    }
    return lines.join("\n");
  }

  /* Recomputes the grid for the current layout and repaints the static
     frame. Called on init, on (debounced) resize, and after late font
     loads; the signature guard makes redundant calls cheap. */
  function rebuild() {
    const pre = state.pre;
    if (!pre || !pre.isConnected) return;
    /* The single font gate: no path (init, resize, container resize,
       late font loads) may generate from a fallback font — the text
       fallback stays up until the real font has been verified. The
       JS-registered face persists for the document's life (see
       loadFontFace), so a past verification stays valid. */
    if (!fontReady) return;

    /* A pre still in fallback dress has never shown a generated frame;
       its first frame below settles in from glitch noise. Captured
       before the class flip, which is what marks the pre generated. */
    const firstBuild = !pre.classList.contains(CONFIG.generatedClass);

    /* Grid sizing must be measured at the generated font size, not the
       larger text-fallback size, so the class flips before probing. */
    pre.classList.add(CONFIG.generatedClass);

    const cell = measureCharCell(pre);
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const inkBox = ctx ? measureInkBox(ctx) : null;
    const grid =
      cell.width && cell.height && inkBox && inkBox.width && inkBox.height
        ? computeGrid(pre, cell, inkBox)
        : null;

    if (!grid) {
      /* Cannot generate (no 2D context, degenerate metrics, tiny layout):
         restore the readable title-sized text fallback, and drop any
         stale frame so the shimmer loop cannot paint it over the
         fallback text. */
      pre.classList.remove(CONFIG.generatedClass);
      state.staticFrame = "";
      state.buildSignature = "";
      return;
    }

    /* Identical grid and font metrics produce an identical frame — skip
       the canvas work (e.g. a resize that didn't change the layout), but
       still repaint when the pre is a fresh element from an instant
       navigation and doesn't show the frame yet. */
    const signature = [
      grid.cols,
      grid.rows,
      inkBox.width.toFixed(1),
      inkBox.height.toFixed(1),
    ].join("|");
    if (
      signature === state.buildSignature &&
      pre.textContent === state.staticFrame
    ) {
      return;
    }
    state.buildSignature = signature;

    buildCells(grid, sampleCoverage(canvas, ctx, grid, inkBox));
    state.staticFrame = buildFrame(null);

    /* A page's first generated frame materializes instead of snapping
       in: it starts at full shimmer envelope and animationTick's
       release path decays it into the static frame, so the fallback →
       grid handoff reads as terminal noise resolving rather than a
       font swap. Resize and self-heal rebuilds repaint statically. */
    if (firstBuild && !reducedMotion.matches) {
      state.envelope = 1;
      state.lastMoveAt = 0;
      state.lastTickAt = 0;
      pre.textContent = buildFrame(performance.now());
      if (!state.rafId) state.rafId = requestAnimationFrame(animationTick);
    } else {
      pre.textContent = state.staticFrame;
    }
  }

  function stopAnimation() {
    if (state.rafId) {
      cancelAnimationFrame(state.rafId);
      state.rafId = 0;
    }
    state.envelope = 0;
    state.lastTickAt = 0;
  }

  /* Runs while the cursor moves and through the fade-out after it stops:
     the envelope ramps toward 1 during movement (attack) and toward 0 once
     movement pauses longer than idleDelayMs (release). The loop ends only
     when the envelope has fully released, settling on the static frame. */
  function animationTick(now) {
    state.rafId = 0;
    if (!state.pre || !state.pre.isConnected || !state.staticFrame) return;

    const dt = state.lastTickAt ? now - state.lastTickAt : 0;
    state.lastTickAt = now;
    const moving = now - state.lastMoveAt < CONFIG.idleDelayMs;
    const step = moving ? dt / CONFIG.attackMs : -dt / CONFIG.releaseMs;
    state.envelope = Math.min(1, Math.max(0, state.envelope + step));

    if (!moving && state.envelope === 0) {
      state.pre.textContent = state.staticFrame; /* fully settled */
      state.lastTickAt = 0;
      return;
    }
    state.pre.textContent = buildFrame(now);
    state.rafId = requestAnimationFrame(animationTick);
  }

  function onPointerMove() {
    if (!state.pre || !state.pre.isConnected || !state.staticFrame) return;
    if (reducedMotion.matches) return;

    state.lastMoveAt = performance.now();
    if (!state.rafId) {
      state.rafId = requestAnimationFrame(animationTick);
    }
  }

  /* Idempotent entry point: re-queries the pre because navigation.instant
     replaces page content, and no-ops on pages without the logo. */
  function init() {
    const pre = document.querySelector("pre.keep-ascii");
    state.pre = pre;
    /* A fresh pre from an instant navigation shows its text fallback;
       the previous visit's frame no longer matches it and must not be
       animated into it before rebuild() replaces it. */
    state.staticFrame = "";
    if (containerObserver) containerObserver.disconnect();
    if (!pre) {
      stopAnimation();
      return;
    }
    if (containerObserver && pre.parentElement) {
      containerObserver.observe(pre.parentElement);
    }
    /* Generate only once the logo webfont is verifiably usable AND the
       page's own fonts have settled — measureCharCell depends on the
       pre's rendered font (JetBrains Mono), and building against
       fallback metrics would produce a grid that clips or under-fills
       once the real font swaps in. On failure the text fallback simply
       stays; the loadingdone listener below retries later. */
    Promise.all([ensureLogoFont(), document.fonts && document.fonts.ready])
      .then(function (results) {
        if (results[0] && state.pre === pre && pre.isConnected) rebuild();
      });
  }

  window.addEventListener("pointermove", onPointerMove);
  window.addEventListener(
    "resize",
    KeepUtils.debounce(rebuild, CONFIG.resizeDebounceMs)
  );

  /* The grid is sized from the container width, which can change with
     no window resize (late layout shifts as fonts or the text below
     land): rebuild when the container itself resizes, once a frame
     exists to correct. The signature guard makes redundant fires
     cheap. */
  const containerObserver =
    typeof ResizeObserver === "undefined"
      ? null
      : new ResizeObserver(
          KeepUtils.debounce(function () {
            if (state.pre && state.pre.isConnected && state.staticFrame) {
              rebuild();
            }
          }, CONFIG.resizeDebounceMs)
        );

  /* Fonts that finish after the first build (e.g. a slow @import of the
     page font) change cell metrics; rebuilding self-heals, and the
     signature guard makes it free when nothing changed. The same event
     re-runs a failed verification: ensureLogoFont re-checks the canvas
     render when its last round said no, so an environment that starts
     shaping the font late still replaces the text fallback with the
     generated grid. */
  if (document.fonts && document.fonts.addEventListener) {
    document.fonts.addEventListener("loadingdone", function () {
      if (!state.pre || !state.pre.isConnected) return;
      ensureLogoFont().then(function (usable) {
        if (usable && state.pre && state.pre.isConnected) rebuild();
      });
    });
  }

  KeepUtils.onPageChange(init);
})();
