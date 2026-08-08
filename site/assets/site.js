/* VayuWeb — vayuweb.vayupress.com
   ---------------------------------------------------------------------------
   Plain ES5-ish script served same-origin, so script-src 'self' admits it with
   no nonce. Two responsibilities: the hero's own motion (typewriter, counters,
   ticker), and the three Alpine components.

   Alpine here is the CSP build, which parses expressions with a real tokeniser
   rather than new Function(). Its evaluator supports member access, calls,
   comparison and conditionals — but NOT logical operators, template literals or
   arrow functions. Every expression in index.html is written to that contract,
   and anything more complicated is a getter or a method on the component below.
   The standard build would need 'unsafe-eval', which would mean weakening
   script-src across the whole install so that one page could be interactive. */

(function () {
  "use strict";

  var REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ── the headline ────────────────────────────────────────────────────────
     Typed in two tones, as the reference does: the assertion lands bright and
     the consequence follows dimmer. The accessible copy of the sentence is a
     visually-hidden span in the markup — these two are aria-hidden, so the
     heading reads once and reads whole no matter where the typing has got to. */

  var TYPE_MS = 35;
  var TYPE_DELAY = 400;

  function typewriter() {
    // After the webfonts land, not before. font-display is swap, so measuring
    // during the fallback reserves the fallback's height and the column still
    // jumps — the exact fault the measurement exists to prevent.
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(type);
    } else {
      type();
    }
  }

  function type() {
    var headline = document.getElementById("headline");
    var a = document.querySelector(".headline__a");
    var b = document.querySelector(".headline__b");
    var caret = document.querySelector(".caret");
    if (!headline || !a || !b) return;

    // The markup is the source of the sentence, not a constant in here. Two
    // copies of a headline is one headline and one thing that will disagree
    // with it later.
    var HEAD_A = a.textContent;
    var HEAD_B = b.textContent;

    if (REDUCED) {
      if (caret) caret.classList.add("is-done");
      return;
    }

    // Measure the real sentence before emptying it, so the lede and the buttons
    // stay put instead of being pushed down a line at a time.
    headline.style.minHeight = headline.getBoundingClientRect().height + "px";
    a.textContent = "";
    b.textContent = "";

    var full = HEAD_A + HEAD_B;
    var i = 0;
    window.setTimeout(function step() {
      i += 1;
      a.textContent = full.slice(0, Math.min(i, HEAD_A.length));
      b.textContent = i > HEAD_A.length ? full.slice(HEAD_A.length, i) : "";
      if (i < full.length) {
        window.setTimeout(step, TYPE_MS);
        return;
      }
      if (caret) caret.classList.add("is-done");
      // Release the reservation. It is a measurement taken at one viewport
      // width, and it stops being true the moment the window changes size —
      // leaving a block of dead space under a headline that has already
      // finished. It is only needed while the text is short.
      headline.style.minHeight = "";
    }, TYPE_DELAY);
  }

  /* ── counters ────────────────────────────────────────────────────────────
     easeOutCubic over two seconds. The hero's runs on a delay so it lands with
     the orbit chips; the ones further down wait until they are actually on
     screen, because a number that finished counting before the reader arrived
     has only ever shown them its final state. */

  function easeOutCubic(t) {
    var u = 1 - t;
    return 1 - u * u * u;
  }

  function countTo(el, target, duration, delay) {
    if (REDUCED) {
      el.textContent = target.toLocaleString("en-GB");
      return;
    }
    window.setTimeout(function () {
      var start = null;
      window.requestAnimationFrame(function frame(now) {
        if (start === null) start = now;
        var t = Math.min((now - start) / duration, 1);
        el.textContent = Math.round(easeOutCubic(t) * target).toLocaleString("en-GB");
        if (t < 1) window.requestAnimationFrame(frame);
      });
    }, delay);
  }

  function counters() {
    var core = document.getElementById("core-count");
    if (core) countTo(core, 1270, 2000, 1200);

    var rest = document.querySelectorAll("[data-count]");
    if (!rest.length) return;

    if (!("IntersectionObserver" in window)) {
      Array.prototype.forEach.call(rest, function (el) {
        countTo(el, parseInt(el.getAttribute("data-count"), 10), 2000, 0);
      });
      return;
    }
    var seen = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          seen.unobserve(entry.target);
          countTo(entry.target, parseInt(entry.target.getAttribute("data-count"), 10), 2000, 0);
        });
      },
      { threshold: 0.4 }
    );
    Array.prototype.forEach.call(rest, function (el) {
      seen.observe(el);
    });
  }

  /* ── ticker ──────────────────────────────────────────────────────────────
     The reference runs partner logos. There are no partners — there is a
     namespace, and it is the more interesting object: these are real entries
     from the Annex, spread across its categories.

     Built rather than written into the markup because the rail translates by
     exactly -50%, which is only seamless if the second half is a byte-for-byte
     repeat of the first. Two hand-maintained copies drift. */

  var TICKER = [
    ".vayu", ".folio", ".zine", ".dissent", ".chai", ".ghazal", ".allodial",
    ".commons", ".p2p", ".sov", ".haven", ".kin", ".stacks", ".darkroom",
    ".souk", ".daemon", ".sangha", ".freehold", ".gurukul", ".mandir",
    ".quill", ".mesh", ".offgrid", ".almanac", ".bazaar", ".polis"
  ];

  function ticker() {
    var rail = document.getElementById("ticker-rail");
    if (!rail) return;
    var half = document.createDocumentFragment();
    TICKER.forEach(function (name) {
      var span = document.createElement("span");
      span.className = "ticker__i";
      span.textContent = name;
      half.appendChild(span);
    });
    rail.appendChild(half.cloneNode(true));
    rail.appendChild(half);
  }

  /* ── the forbidden claims ────────────────────────────────────────────────
     Rendered from claims.js, which is generated out of Article 21.4. The words
     are not written into index.html on purpose: the repository's claims gate
     reads this site, and a page that quotes the prohibition would either fail
     that gate or need an exemption covering the whole of the marketing copy —
     which is the last thing that should be exempt. */

  function forbiddenClaims() {
    var list = document.getElementById("claims-list");
    var items = window.VAYUWEB_FORBIDDEN_CLAIMS;
    if (!list || !items) return;
    items.forEach(function (claim) {
      var li = document.createElement("li");
      li.textContent = claim;
      list.appendChild(li);
    });
  }

  /* ── Alpine components ───────────────────────────────────────────────────── */

  document.addEventListener("alpine:init", function () {
    var Alpine = window.Alpine;

    Alpine.data("site", function () {
      return {
        open: false,
        get expanded() {
          return this.open ? "true" : "false";
        },
        toggle: function () {
          this.open = !this.open;
        },
        close: function () {
          this.open = false;
        }
      };
    });

    Alpine.data("chokepoints", function () {
      return {
        mode: "vayu",
        get clear() {
          return this.mode === "clear";
        },
        get vayu() {
          return this.mode === "vayu";
        },
        get clearClass() {
          return this.mode === "clear" ? "is-on" : "";
        },
        get vayuClass() {
          return this.mode === "vayu" ? "is-on" : "";
        },
        showClear: function () {
          this.mode = "clear";
        },
        showVayu: function () {
          this.mode = "vayu";
        }
      };
    });

    /* The explorer reads window.VAYUWEB_NAMESPACE, which namespace.js defines
       and which is generated from the normative Annex. It is read HERE, in
       JavaScript, rather than from an expression in the markup: the CSP build
       refuses to reach a global from an expression, and correctly so. */
    var DATA = window.VAYUWEB_NAMESPACE || { total: 0, categories: [] };
    var ALL = [];
    DATA.categories.forEach(function (category) {
      category.entries.split(" ").forEach(function (tld) {
        ALL.push({ tld: "." + tld, cat: category.name });
      });
    });

    /* The Annex asserts a total; this counts what actually arrived. They can
       only disagree if the shipped copy has been damaged in transit — and a
       namespace that is quietly one entry short is worse than one that is
       visibly broken, because Article 2.31 has a client deciding validity from
       exactly this copy. Say so on the page rather than serving it silently. */
    var INTACT = ALL.length === DATA.total;

    var LIMIT = 120;

    // 0 exact extension, 1 extension starts with it, 2 extension contains it,
    // 3 only the description mentions it.
    function rank(entry, needle) {
      var tld = entry.tld.slice(1);
      if (tld === needle) return 0;
      if (tld.indexOf(needle) === 0) return 1;
      if (tld.indexOf(needle) !== -1) return 2;
      return 3;
    }

    Alpine.data("namespace", function () {
      return {
        q: "",
        active: "",

        get matches() {
          var needle = this.q.trim().toLowerCase().replace(/^\./, "");
          var active = this.active;
          var hits = ALL.filter(function (entry) {
            if (active !== "" && entry.cat !== active) return false;
            if (needle === "") return true;
            if (entry.tld.indexOf(needle) !== -1) return true;
            return entry.cat.toLowerCase().indexOf(needle) !== -1;
          });
          if (needle === "") return hits;
          /* Rank, because the unranked answer was wrong in a way a reader
             would notice: searching "zine" put `.masthead` first — it matches
             on the word "magazine" in its description — and buried `.zine`
             itself. The extension you typed is the extension you meant. */
          return hits.sort(function (a, b) {
            return rank(a, needle) - rank(b, needle);
          });
        },
        get shown() {
          return this.matches.slice(0, LIMIT);
        },
        get truncated() {
          return this.matches.length > LIMIT;
        },
        get empty() {
          return this.matches.length === 0;
        },
        // Only while the whole namespace is in view. Once a category is picked,
        // its name under all 40 of its own extensions is noise repeated 40 times.
        get showCat() {
          return this.active === "";
        },
        get countLabel() {
          if (!INTACT) {
            return "this copy holds " + ALL.length + " of " + DATA.total +
              " — it is incomplete, read the Annex";
          }
          var n = this.matches.length;
          if (n === ALL.length) return ALL.length.toLocaleString("en-GB") + " extensions";
          return n.toLocaleString("en-GB") + " of " + ALL.length.toLocaleString("en-GB");
        },
        get moreLabel() {
          return "Showing the first " + LIMIT + " of " + this.matches.length +
            " — narrow the search to see the rest.";
        },
        get cats() {
          var active = this.active;
          var list = [{ name: "", label: "All", cls: active === "" ? "is-on" : "" }];
          DATA.categories.forEach(function (category) {
            list.push({
              name: category.name,
              label: category.name,
              cls: active === category.name ? "is-on" : ""
            });
          });
          return list;
        },
        pick: function (name) {
          this.active = this.active === name ? "" : name;
        }
      };
    });
  });

  /* ── go ──────────────────────────────────────────────────────────────────── */

  function start() {
    typewriter();
    counters();
    ticker();
    forbiddenClaims();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
