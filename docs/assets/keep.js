/* keep.js: what the page of Keep does beyond its text. Without this file the page still reads
   the same: the logo stays the plain word, the commands have no copy button and the table of
   contents does not follow the reader.

   1. The logo. The word "Keep" is drawn with the logo typeface onto a canvas that is never
      shown, a key is drawn behind it, and both are turned into two grids of ASCII characters:
      the darker a cell, the denser its character. The key keeps a gap around the letters so the
      word stays readable. The logo stands still by itself. Moving the pointer makes the
      characters shimmer, and the shimmer fades out when the pointer rests. The method is that
      of the logo of Kiln (docs/javascripts/ascii-logo.js there), with a second layer added.
   2. A copy button on every command.
   3. The entry of the table of contents that belongs to the text on screen is marked.

   The logo typeface, fonts/keep-blackletter.woff2, holds the glyphs K, e and p of
   UnifrakturMaguntia Book (SIL OFL 1.1, fonts/UnifrakturMaguntia-OFL.txt), taken from
   github.com/google/fonts, ofl/unifrakturmaguntia, SHA-256 of the TTF d64afc05...b4492cc8.
   The licence reserves the name of the font for the unchanged font, so the subset carries
   another name. To make it again for a changed word:
     pyftsubset UnifrakturMaguntia-Book.ttf --text="Keep" --flavor=woff2 --layout-features='' \
       --name-IDs="0,1,2,3,4,5,6,13,14" --output-file=keep-blackletter.woff2
   and then set the name records 1, 3, 4 and 6 to the new name with fontTools. */
(function () {
  "use strict";

  /* ---- 1. the logo ------------------------------------------------------------------------ */

  const LOGO = {
    text: "Keep",
    font: "Keep Blackletter",
    fallbackFont: "serif",
    /* Characters from the darkest to the empty cell. The ramps of the still picture are short:
       a long one turns the soft edges of the letters into a mush of mid-dark characters. */
    wordRamp: "$@B%8&WM#*oa+=~-:. ",
    keyRamp: "%#*x+=~-:. ",
    /* The shimmer moves along this long ramp, so a cell passes many different characters. */
    glitchRamp: "$@B%8&WM#NHKDGERSAPVFT*oahkbdpqwmZO0QLCJUYXzcvunxrjfteysg9654327/\\|()1{}[]?=-_+~<>i!lI;:,\"^`'. ",
    referencePx: 200,       /* size at which the word is measured and drawn */
    samplesPerCell: 3,      /* canvas pixels per cell width */
    coverageFloor: 0.1,     /* less ink than this in a cell is no ink */
    coverageCeil: 0.6,      /* more than this is solid */
    embolden: 0.022,        /* outline drawn around the letters, as a share of the type size:
                               the thin strokes of the typeface would vanish in the grid */
    jitter: 0.14,           /* each cell is moved along the ramp by up to this share of it */
    amplitude: 0.2,         /* swing of the shimmer, as a share of the long ramp */
    radPerMs: 0.006,
    detune: 1.7,            /* the second wave runs this much faster than the first */
    idleMs: 150,            /* no movement for this long: the pointer rests */
    attackMs: 120,
    releaseMs: 1400,
    haloX: 2, haloY: 1,     /* cells around the letters that the key leaves empty */
    /* The picture is a square of side 1. The word spans its width, the key stands behind it:
       the bow above the word, the shaft through it and the bit below. */
    wordWidth: 0.95,
    wordCentreY: 0.56,
    keyX: 0.6,              /* centre line of the key */
    bowTop: 0.025, bowRadius: 0.2, bowHole: 0.052, bowHoleUp: 0.045, bowCorner: 0.02,
    shaftWidth: 0.072, shaftBottom: 0.975,
    collarWidth: 0.14, collarHeight: 0.03,
    teeth: [[0.15, 0.2, 0.056], [0.1, 0.108, 0.056]]   /* length, distance from the end, height */
  };

  const logo = {
    box: null, wordPre: null, keyPre: null,
    cols: 0, rows: 0,
    word: null, key: null,          /* the two layers, see makeLayer */
    phases: null,
    drawn: "",                      /* cols x rows of the picture on screen */
    still: false,                   /* the picture on screen is the still one */
    frame: 0, lastMove: 0, lastTick: 0,
    envelope: 0                     /* strength of the shimmer, 0 to 1 */
  };
  const lessMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const smooth = (x) => x * x * (3 - 2 * x);
  /* The same number for the same cell every time, so the still picture does not change. */
  function cellHash(x, y) {
    const s = Math.sin(x * 127.1 + y * 311.7) * 43758.5453123;
    return s - Math.floor(s);
  }
  const fontOf = (px) => px + 'px "' + LOGO.font + '", ' + LOGO.fallbackFont;

  /* A browser may report the typeface as loaded and still draw canvas text with another one.
     Then the word would come out in the wrong shapes, so the plain word stays instead. */
  function typefaceDraws() {
    const ctx = document.createElement("canvas").getContext("2d");
    if (!ctx) return false;
    ctx.font = fontOf(LOGO.referencePx);
    const own = ctx.measureText(LOGO.text).width;
    ctx.font = LOGO.referencePx + "px " + LOGO.fallbackFont;
    return Math.abs(own - ctx.measureText(LOGO.text).width) > 0.5;
  }

  /* Width and height of one character of the grid, as the browser lays it out. */
  function cellSize(pre) {
    const probe = document.createElement("span");
    probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
    probe.textContent = "0".repeat(40) + "\n" + "0".repeat(40);
    pre.appendChild(probe);
    const r = probe.getBoundingClientRect();
    pre.removeChild(probe);
    return { w: r.width / 40, h: r.height / 2 };
  }

  function drawWord(ctx, W, H) {
    ctx.font = fontOf(LOGO.referencePx);
    const m = ctx.measureText(LOGO.text);
    const left = m.actualBoundingBoxLeft || 0;
    const inkW = left + (m.actualBoundingBoxRight || m.width);
    const up = m.actualBoundingBoxAscent || LOGO.referencePx * 0.8;
    const inkH = up + (m.actualBoundingBoxDescent || LOGO.referencePx * 0.2);
    const s = (LOGO.wordWidth * W) / inkW;
    ctx.setTransform(s, 0, 0, s, (W - inkW * s) / 2 + left * s, LOGO.wordCentreY * H - (inkH * s) / 2 + up * s);
    ctx.fillText(LOGO.text, 0, 0);
    ctx.lineWidth = LOGO.embolden * LOGO.referencePx;
    ctx.lineJoin = "round";
    ctx.strokeText(LOGO.text, 0, 0);
  }

  function drawKey(ctx, W, H) {
    const cx = LOGO.keyX * W, r = LOGO.bowRadius * W, cy = LOGO.bowTop * H + r;
    const corners = [[cx, cy - r], [cx + r, cy], [cx, cy + r], [cx - r, cy]];
    /* the bow: a square on its corner with rounded corners, and a round hole in it */
    ctx.beginPath();
    ctx.moveTo((corners[3][0] + corners[0][0]) / 2, (corners[3][1] + corners[0][1]) / 2);
    for (let i = 0; i < 4; i++) {
      const a = corners[i], b = corners[(i + 1) % 4];
      ctx.arcTo(a[0], a[1], (a[0] + b[0]) / 2, (a[1] + b[1]) / 2, LOGO.bowCorner * W);
    }
    ctx.closePath();
    const hy = cy - LOGO.bowHoleUp * W;
    ctx.moveTo(cx + LOGO.bowHole * W, hy);
    ctx.arc(cx, hy, LOGO.bowHole * W, 0, Math.PI * 2);
    ctx.fill("evenodd");
    /* the shaft, the collar under the bow, and the teeth of the bit */
    const sw = LOGO.shaftWidth * W, bottom = LOGO.shaftBottom * H;
    ctx.fillRect(cx - sw / 2, cy + r * 0.7, sw, bottom - cy - r * 0.7);
    ctx.fillRect(cx - (LOGO.collarWidth * W) / 2, cy + r * 0.93, LOGO.collarWidth * W, LOGO.collarHeight * W);
    for (const t of LOGO.teeth) ctx.fillRect(cx - sw / 2 - t[0] * W, bottom - t[1] * W, t[0] * W, t[2] * W);
  }

  /* Draw with DRAW and return, for every cell, the share of it that is covered (0 to 1). */
  function coverage(draw, cols, rows, sx, sy) {
    const canvas = document.createElement("canvas");
    canvas.width = cols * sx;
    canvas.height = rows * sy;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    ctx.fillStyle = "#000";
    draw(ctx, canvas.width, canvas.height);
    const alpha = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    const out = new Float32Array(cols * rows);
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        let sum = 0;
        for (let j = 0; j < sy; j++) {
          for (let i = 0; i < sx; i++) sum += alpha[((y * sy + j) * canvas.width + x * sx + i) * 4 + 3];
        }
        out[y * cols + x] = sum / (sx * sy * 255);
      }
    }
    return out;
  }

  /* One layer of the logo: for each cell its place on the short ramp (the still picture), its
     place on the long ramp (where the shimmer starts from) and whether it holds ink at all. */
  function makeLayer(cover, ramp, blocked) {
    const n = cover.length, last = ramp.length - 1, glitchLast = LOGO.glitchRamp.length - 1;
    const layer = { ramp: ramp, base: new Int16Array(n), glitch: new Int16Array(n), ink: new Uint8Array(n) };
    const band = LOGO.coverageCeil - LOGO.coverageFloor;
    for (let i = 0; i < n; i++) {
      const density = blocked && blocked[i] ? 0 : clamp((cover[i] - LOGO.coverageFloor) / band, 0, 1);
      const shift = density > 0 ? (cellHash(i % logo.cols, Math.floor(i / logo.cols)) - 0.5) * LOGO.jitter : 0;
      layer.base[i] = clamp(Math.round((1 - density + shift) * last), 0, density > 0 ? last - 1 : last);
      layer.glitch[i] = clamp(Math.round((1 - density + shift) * glitchLast), 0, glitchLast);
      layer.ink[i] = density > 0 ? 1 : 0;
    }
    return layer;
  }

  /* The cells of the letters and the cells close to them, which the key leaves empty. */
  function halo(wordCover) {
    const out = new Uint8Array(wordCover.length);
    for (let y = 0; y < logo.rows; y++) {
      for (let x = 0; x < logo.cols; x++) {
        if (wordCover[y * logo.cols + x] <= LOGO.coverageFloor) continue;
        for (let dy = -LOGO.haloY; dy <= LOGO.haloY; dy++) {
          for (let dx = -LOGO.haloX; dx <= LOGO.haloX; dx++) {
            const xx = x + dx, yy = y + dy;
            if (xx >= 0 && xx < logo.cols && yy >= 0 && yy < logo.rows) out[yy * logo.cols + xx] = 1;
          }
        }
      }
    }
    return out;
  }

  /* The text of one layer. NOW is null for the still picture. Otherwise two waves move each
     inked cell along the long ramp, as far as the envelope allows. A cell that is moved by
     less than one step shows its still character, so the shimmer ends in the still picture. */
  function layerText(layer, now, offset) {
    const glitchLast = LOGO.glitchRamp.length - 1;
    const swing = LOGO.amplitude * glitchLast * smooth(logo.envelope);
    const angle = now === null ? 0 : now * LOGO.radPerMs;
    let text = "";
    for (let y = 0; y < logo.rows; y++) {
      for (let x = 0; x < logo.cols; x++) {
        const i = y * logo.cols + x;
        if (now !== null && layer.ink[i]) {
          const p = logo.phases[i] + offset;
          const move = (0.7 * Math.sin(angle + p) + 0.3 * Math.sin(angle * LOGO.detune + p * 2)) * swing;
          if (Math.abs(move) >= 0.5) {
            text += LOGO.glitchRamp[clamp(layer.glitch[i] + Math.round(move), 0, glitchLast)];
            continue;
          }
        }
        text += layer.ramp[layer.base[i]];
      }
      if (y < logo.rows - 1) text += "\n";
    }
    return text;
  }

  function paint(now) {
    logo.wordPre.textContent = layerText(logo.word, now, 0);
    logo.keyPre.textContent = layerText(logo.key, now, 1.3);
    logo.still = now === null;
  }

  /* Runs while the pointer moves and until the shimmer has faded after it stopped. */
  function tick(now) {
    logo.frame = 0;
    if (!logo.word) return;
    const dt = logo.lastTick ? now - logo.lastTick : 0;
    logo.lastTick = now;
    const moving = now - logo.lastMove < LOGO.idleMs;
    logo.envelope = clamp(logo.envelope + (moving ? dt / LOGO.attackMs : -dt / LOGO.releaseMs), 0, 1);
    if (!moving && logo.envelope === 0) {
      paint(null);
      logo.lastTick = 0;
      return;
    }
    paint(now);
    logo.frame = requestAnimationFrame(tick);
  }

  function build() {
    const box = logo.box;
    const wasPlain = !box.classList.contains("generated");
    box.classList.add("generated");               /* the grid is measured in its own type size */
    const cell = cellSize(logo.wordPre);
    const cols = cell.w ? Math.floor(box.clientWidth / cell.w) : 0;
    const rows = cell.h ? Math.round((cols * cell.w) / cell.h) : 0;
    if (cols < 24 || rows < 12) {                 /* too small to draw: the plain word */
      box.classList.remove("generated");
      logo.wordPre.textContent = LOGO.text;
      logo.keyPre.textContent = "";
      logo.word = logo.key = null;
      logo.drawn = "";
      return;
    }
    if (logo.drawn === cols + "x" + rows) return;
    logo.cols = cols;
    logo.rows = rows;
    /* square canvas pixels: a cell is about twice as tall as it is wide */
    const sx = LOGO.samplesPerCell, sy = Math.max(1, Math.round((sx * cell.h) / cell.w));
    const wordCover = coverage(drawWord, cols, rows, sx, sy);
    const keyCover = coverage(drawKey, cols, rows, sx, sy);
    if (!wordCover || !keyCover) { box.classList.remove("generated"); return; }
    logo.phases = new Float32Array(cols * rows);
    for (let i = 0; i < logo.phases.length; i++) logo.phases[i] = cellHash(i % cols, Math.floor(i / cols)) * Math.PI * 2;
    logo.word = makeLayer(wordCover, LOGO.wordRamp, null);
    logo.key = makeLayer(keyCover, LOGO.keyRamp, halo(wordCover));
    logo.drawn = cols + "x" + rows;
    if (wasPlain && !lessMotion.matches) {
      /* the first picture settles out of noise instead of replacing the plain word at once */
      logo.envelope = 1;
      logo.lastMove = 0;
      logo.lastTick = 0;
      paint(performance.now());
      if (!logo.frame) logo.frame = requestAnimationFrame(tick);
    } else {
      paint(null);
    }
  }

  function startLogo() {
    logo.box = document.querySelector(".logo");
    if (!logo.box || !document.fonts || !document.fonts.load) return;
    logo.wordPre = logo.box.querySelector(".logo-word");
    logo.keyPre = logo.box.querySelector(".logo-key");
    const mono = getComputedStyle(logo.keyPre).fontFamily;
    Promise.all([document.fonts.load(fontOf(LOGO.referencePx), LOGO.text), document.fonts.load("16px " + mono)])
      .then(function () {
        if (!typefaceDraws()) return;
        build();
        let timer = 0;
        const again = function () {
          clearTimeout(timer);
          timer = setTimeout(build, 150);
        };
        if (typeof ResizeObserver !== "undefined") new ResizeObserver(again).observe(logo.box);
        else window.addEventListener("resize", again);
        window.addEventListener("pointermove", function () {
          if (!logo.word || lessMotion.matches) return;
          logo.lastMove = performance.now();
          if (!logo.frame) logo.frame = requestAnimationFrame(tick);
        });
      })
      .catch(function () { /* the plain word stays */ });
  }

  /* ---- 2. a copy button on every command -------------------------------------------------- */

  function icon(parts) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.4");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    for (const p of parts) {
      const el = document.createElementNS(ns, p[0]);
      for (const k in p[1]) el.setAttribute(k, p[1][k]);
      svg.appendChild(el);
    }
    return svg;
  }
  const twoSheets = [["rect", { x: 5.5, y: 5.5, width: 8, height: 8, rx: 1.5 }],
                     ["path", { d: "M10.5 2.5h-6a2 2 0 0 0-2 2v6" }]];
  const tick16 = [["path", { d: "M3 8.5l3.2 3.2L13 4.8" }]];

  function startCopy() {
    if (!navigator.clipboard || !navigator.clipboard.writeText) return;
    document.querySelectorAll(".code.cmd").forEach(function (block) {
      const code = block.querySelector("code");
      const button = document.createElement("button");
      let timer = 0;
      const show = function (done) {
        button.replaceChildren(icon(done ? tick16 : twoSheets));
        button.classList.toggle("done", done);
        button.setAttribute("aria-label", done ? "Copied" : "Copy the command");
        button.title = done ? "Copied" : "Copy";
      };
      button.type = "button";
      button.className = "copy";
      show(false);
      button.addEventListener("click", function () {
        navigator.clipboard.writeText(code.textContent).then(function () {
          show(true);
          clearTimeout(timer);
          timer = setTimeout(show, 2000, false);
        }, function () {
          /* the browser refused: mark the command, so that it can be copied by hand */
          const range = document.createRange();
          range.selectNodeContents(code);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
        });
      });
      block.appendChild(button);
    });
  }

  /* ---- 3. the table of contents follows the text ------------------------------------------ */

  function startContents() {
    const links = Array.from(document.querySelectorAll('.toc a[href^="#"]'));
    const marks = links
      .map(function (a) { return { link: a, target: document.getElementById(a.getAttribute("href").slice(1)) }; })
      .filter(function (m) { return m.target; });
    if (!marks.length) return;
    let waiting = false;
    const update = function () {
      waiting = false;
      /* the last heading that has passed the upper quarter of the window, or the last of all
         once the page is scrolled to its end */
      let current = marks[0];
      const line = window.innerHeight * 0.25;
      for (const m of marks) if (m.target.getBoundingClientRect().top <= line) current = m;
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) current = marks[marks.length - 1];
      for (const m of marks) {
        if (m === current) m.link.setAttribute("aria-current", "true");
        else m.link.removeAttribute("aria-current");
      }
    };
    window.addEventListener("scroll", function () {
      if (!waiting) { waiting = true; requestAnimationFrame(update); }
    }, { passive: true });
    window.addEventListener("resize", update);
    update();
  }

  startLogo();
  startCopy();
  startContents();
})();
