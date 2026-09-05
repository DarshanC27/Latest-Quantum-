/* Quantum Ready — marketing site behaviour.
 *
 * No framework and no build step, so the site can be served from GitHub
 * Pages as-is and edited by hand.
 *
 * The Mosca calculation below mirrors quantumready/engine/quantum.py
 * exactly. If one changes, change both — a marketing page that disagrees
 * with the tool it is selling is worse than no calculator at all.
 */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  /* ---------- contact destination ----------
   * Set ONE of these before launch. Leave both empty and the form tells
   * the visitor it is not connected instead of silently losing their
   * enquiry.
   *   email        - opens the visitor's mail client
   *   formEndpoint - POSTs JSON (Formspree, Netlify Forms, your own API)
   */
  var CONTACT = {
    email: "darshanchabbi271@gmail.com",
    formEndpoint: ""
  };
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  /* ---------- theme ---------- */

  var THEME_KEY = "qr-theme";
  var root = document.documentElement;

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var toggle = $("themeToggle");
    if (toggle) {
      var toDark = theme === "light";
      toggle.setAttribute(
        "aria-label",
        toDark ? "Switch to dark theme" : "Switch to light theme"
      );
      toggle.innerHTML = toDark
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>';
    }
  }

  var stored = null;
  try { stored = localStorage.getItem(THEME_KEY); } catch (e) { /* private mode */ }
  // Honour an explicit choice; otherwise follow the system, defaulting to
  // light because dark-by-default reads as less trustworthy for B2B.
  applyTheme(
    stored ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
  );

  var themeToggle = $("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(next);
      try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* ignore */ }
    });
  }

  /* ---------- mobile navigation ---------- */

  var navToggle = $("navToggle");
  var navLinks = $("navLinks");

  if (navToggle && navLinks) {
    navToggle.addEventListener("click", function () {
      var open = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", String(open));
      navToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    });

    navLinks.addEventListener("click", function (event) {
      if (event.target.tagName === "A") {
        navLinks.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
        navToggle.setAttribute("aria-label", "Open menu");
      }
    });

    // Escape closes the menu and returns focus to the control that opened
    // it, so keyboard users are never stranded inside it.
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && navLinks.classList.contains("open")) {
        navLinks.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
        navToggle.focus();
      }
    });
  }

  /* ---------- Mosca calculator ---------- */

  // Mirrors SECTOR_SHELF_LIFE in quantumready/engine/quantum.py.
  var SECTORS = {
    general: [10, "A common default. Replace it with your real retention obligation."],
    healthcare: [25, "Patient records carry lifetime confidentiality duties."],
    government: [30, "National security and census material is routinely classified for decades."],
    defence: [30, "Classified material has multi-decade review periods."],
    pharmaceutical: [25, "Trial data and formulations retain value for the life of the patent and beyond."],
    legal: [20, "Matter files and privileged material outlive the engagement."],
    insurance: [20, "Policy and claims history persists for the life of cover."],
    finance: [15, "Mortgage, pension and insurance records run for decades."],
    education: [15, "Student records are retained long after graduation."],
    technology: [10, "Source code and customer data."],
    retail: [7, "Payment and customer data under PCI and tax retention."]
  };

  var sector = $("sector");
  var shelf = $("shelf");
  var migration = $("migration");
  var scenario = $("scenario");

  if (sector && shelf && migration && scenario) {
    Object.keys(SECTORS).forEach(function (key) {
      var option = document.createElement("option");
      option.value = key;
      option.textContent =
        key.charAt(0).toUpperCase() + key.slice(1) + " — " + SECTORS[key][0] + " years";
      if (key === "general") option.selected = true;
      sector.appendChild(option);
    });

    sector.addEventListener("change", function () {
      var entry = SECTORS[sector.value];
      if (entry) {
        shelf.value = entry[0];
        var help = document.querySelector("#sectorHelp");
        if (help) help.textContent = entry[1];
      }
      recalculate();
    });

    [shelf, migration, scenario].forEach(function (input) {
      input.addEventListener("input", recalculate);
      input.addEventListener("change", recalculate);
    });

    recalculate();
  }

  function recalculate() {
    var x = parseInt(shelf.value, 10);
    var y = parseInt(migration.value, 10);
    var quantumYear = parseInt(scenario.value, 10);

    $("shelfVal").textContent = x;
    $("migrationVal").textContent = y;

    // Fractional year elapsed, matching the Python engine.
    var now = new Date();
    var startOfYear = new Date(now.getFullYear(), 0, 1);
    var dayOfYear = Math.floor((now - startOfYear) / 86400000);
    var z = quantumYear - (now.getFullYear() + dayOfYear / 365);

    var total = x + y;
    var atRisk = total > z;
    var exposure = total - z;
    var deadlineYear = Math.floor(quantumYear - x - y);

    var verdict = $("verdict");
    var label = $("verdictLabel");
    var formula = $("formula");
    var text = $("verdictText");

    formula.textContent =
      "X(" + x + ") + Y(" + y + ") = " + total +
      (atRisk ? " > " : " ≤ ") + "Z(" + z.toFixed(1) + ")";

    $("legendEnd").textContent = quantumYear + " threat date";

    // The bar shows how much of the required protection window fits inside
    // the time remaining.
    var safeShare = Math.max(0, Math.min(1, z / Math.max(total, z))) * 100;
    $("barSafe").style.width = safeShare.toFixed(1) + "%";
    $("barOver").style.width = (100 - safeShare).toFixed(1) + "%";

    if (atRisk) {
      verdict.className = "verdict exposed";
      label.textContent = "Exposed";
      var timing =
        deadlineYear < now.getFullYear()
          ? "The latest safe start date was " + deadlineYear +
            ", which has passed. On these assumptions the migration is already " +
            "overdue rather than upcoming, and the practical goal is to shorten " +
            "the exposure window rather than eliminate it."
          : "Migration must begin by " + deadlineYear + " at the latest.";
      text.innerHTML =
        "Data created today must stay confidential for <strong>" + x +
        " years</strong>, and migration is expected to take <strong>" + y +
        " years</strong>. That is " + total + " years of required protection, but only <strong>" +
        z.toFixed(1) + " years</strong> remain before the " + quantumYear +
        " threat date. The shortfall is <strong>" + exposure.toFixed(1) +
        " years</strong>: traffic captured today would still be sensitive when it " +
        "becomes decryptable. " + timing;
    } else {
      verdict.className = "verdict ok";
      label.textContent = "Within tolerance";
      text.innerHTML =
        "Required protection of " + total + " years fits inside the <strong>" +
        z.toFixed(1) + " years</strong> remaining before the " + quantumYear +
        " threat date, with " + Math.abs(exposure).toFixed(1) +
        " years to spare. Migration must still begin by <strong>" + deadlineYear +
        "</strong> for that to hold, and the margin disappears if the threat " +
        "date moves earlier.";
    }
  }

  /* ---------- contact form ---------- */

  var contactForm = $("contactForm");
  if (contactForm) {
    contactForm.addEventListener("submit", function (event) {
      event.preventDefault();
      var status = $("formStatus");

      var name = $("name").value.trim();
      var email = $("email").value.trim();
      var domain = $("domain").value.trim();
      var company = $("company").value.trim();
      var message = $("message").value.trim();

      // Validate on submit rather than on keystroke, and point at the first
      // field that needs attention instead of only reporting at the top.
      var missing = null;
      if (!name) missing = $("name");
      else if (!email || email.indexOf("@") < 1) missing = $("email");
      else if (!domain || domain.indexOf(".") < 1) missing = $("domain");

      if (missing) {
        status.textContent =
          "Please complete " + (missing.previousElementSibling
            ? missing.previousElementSibling.textContent.replace("*", "").trim().toLowerCase()
            : "the required fields") + " before submitting.";
        missing.focus();
        return;
      }

      var body =
        "Name: " + name + "\n" +
        "Organisation: " + (company || "-") + "\n" +
        "Email: " + email + "\n" +
        "Domain to scan: " + domain + "\n\n" +
        (message || "(no additional notes)") + "\n\n" +
        "-- I confirm I am authorised to have this domain assessed.";

      if (CONTACT.formEndpoint) {
        // Posts to whatever service is configured (Formspree, Netlify,
        // your own handler). Kept as fetch so the page never navigates
        // away and the user keeps what they typed on failure.
        status.textContent = "Sending\u2026";
        fetch(CONTACT.formEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify({ name: name, organisation: company, email: email,
                                 domain: domain, message: message })
        }).then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          contactForm.reset();
          status.textContent = "Thank you. We will be in touch about " + domain + ".";
        }).catch(function () {
          status.textContent =
            "That did not send. Please message one of the founders on LinkedIn instead.";
        });
        return;
      }

      if (CONTACT.email) {
        window.location.href =
          "mailto:" + CONTACT.email +
          "?subject=" + encodeURIComponent("Free scan request: " + domain) +
          "&body=" + encodeURIComponent(body);
        status.textContent = "Opening your email client.";
        return;
      }

      // No destination configured yet. Say so plainly rather than
      // pretending the submission went somewhere.
      status.textContent =
        "This form is not connected yet \u2014 please message one of the " +
        "founders on LinkedIn and we will pick it up from there.";
    });
  }

  /* ---------- scroll reveal ---------- */

  var revealables = document.querySelectorAll(".reveal");

  if (reduceMotion.matches || !("IntersectionObserver" in window)) {
    // Show everything immediately rather than leaving content invisible.
    Array.prototype.forEach.call(revealables, function (el) {
      el.classList.add("in");
    });
  } else {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          var siblings = entry.target.parentElement
            ? Array.prototype.filter.call(
                entry.target.parentElement.children,
                function (el) { return el.classList.contains("reveal"); }
              )
            : [];
          var index = siblings.indexOf(entry.target);
          // 60ms stagger, capped so a long grid never crawls.
          entry.target.style.setProperty(
            "--d", Math.min(index < 0 ? 0 : index, 5) * 60 + "ms"
          );
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.1 }
    );

    Array.prototype.forEach.call(revealables, function (el) {
      observer.observe(el);
    });
  }


  /* ---------- animated lattice field ---------- */

  // Purely decorative, so it is skipped entirely under reduced-motion and
  // when the tab is hidden. Node count scales with area rather than being
  // fixed, so a phone does not pay for a desktop's density.
  function startLattice() {
    var canvas = $("lattice");
    if (!canvas || reduceMotion.matches) return;

    var ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    var nodes = [], width = 0, height = 0, dpr = 1, raf = null, running = true;
    var LINK = 132;

    function resize() {
      var rect = canvas.parentElement.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width; height = rect.height;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      var target = Math.min(74, Math.max(22, Math.round((width * height) / 17000)));
      nodes = [];
      for (var i = 0; i < target; i++) {
        nodes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.22,
          vy: (Math.random() - 0.5) * 0.22,
          r: 1.3 + Math.random() * 1.7
        });
      }
    }

    function palette() {
      var dark = root.getAttribute("data-theme") === "dark";
      return dark
        ? { node: "rgba(147,197,253,", line: "rgba(96,165,250," }
        : { node: "rgba(37,99,235,",   line: "rgba(37,99,235," };
    }

    function frame() {
      if (!running) return;
      var c = palette();
      ctx.clearRect(0, 0, width, height);

      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        n.x += n.vx; n.y += n.vy;
        // Bounce rather than wrap, so links never jump across the canvas.
        if (n.x < 0 || n.x > width) { n.vx *= -1; n.x = Math.max(0, Math.min(width, n.x)); }
        if (n.y < 0 || n.y > height) { n.vy *= -1; n.y = Math.max(0, Math.min(height, n.y)); }
      }

      for (var a = 0; a < nodes.length; a++) {
        for (var b = a + 1; b < nodes.length; b++) {
          var dx = nodes[a].x - nodes[b].x, dy = nodes[a].y - nodes[b].y;
          var d2 = dx * dx + dy * dy;
          if (d2 > LINK * LINK) continue;
          var alpha = (1 - Math.sqrt(d2) / LINK) * 0.3;
          ctx.strokeStyle = c.line + alpha.toFixed(3) + ")";
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(nodes[a].x, nodes[a].y);
          ctx.lineTo(nodes[b].x, nodes[b].y);
          ctx.stroke();
        }
      }

      for (var k = 0; k < nodes.length; k++) {
        ctx.fillStyle = c.node + "0.5)";
        ctx.beginPath();
        ctx.arc(nodes[k].x, nodes[k].y, nodes[k].r, 0, Math.PI * 2);
        ctx.fill();
      }

      raf = requestAnimationFrame(frame);
    }

    resize();
    frame();

    var resizeTimer;
    window.addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(resize, 180);
    });

    // Stop work entirely when the tab is not visible.
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        running = false;
        if (raf) cancelAnimationFrame(raf);
      } else if (!running) {
        running = true;
        frame();
      }
    });
  }

  /* ---------- parallax orbs ---------- */

  function startParallax() {
    var orbs = document.querySelectorAll(".orb");
    if (!orbs.length || reduceMotion.matches) return;

    var ticking = false;
    function update() {
      var y = window.scrollY;
      for (var i = 0; i < orbs.length; i++) {
        var speed = parseFloat(orbs[i].getAttribute("data-speed")) || -5;
        // Small delta so foreground and background never desync distractingly.
        orbs[i].style.transform = "translate3d(0," + (y * speed / 100).toFixed(2) + "px,0)";
      }
      ticking = false;
    }
    window.addEventListener("scroll", function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(update);
    }, { passive: true });
    update();
  }

  /* ---------- counters ---------- */

  function startCounters() {
    var stats = document.querySelectorAll("[data-count]");
    if (!stats.length) return;

    function run(el) {
      var target = parseFloat(el.getAttribute("data-count"));
      var from = parseFloat(el.getAttribute("data-from") || "0");
      var suffix = el.getAttribute("data-suffix") || "";
      if (reduceMotion.matches) { el.textContent = target + suffix; return; }

      var start = null, duration = 1100;
      function step(ts) {
        if (start === null) start = ts;
        var p = Math.min((ts - start) / duration, 1);
        var eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(from + (target - from) * eased) + suffix;
        if (p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    }

    if (!("IntersectionObserver" in window)) {
      Array.prototype.forEach.call(stats, run);
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        run(e.target);
        io.unobserve(e.target);
      });
    }, { threshold: 0.5 });
    Array.prototype.forEach.call(stats, function (s) { io.observe(s); });
  }

  /* ---------- algorithm strength chart ---------- */

  function buildStrengthChart() {
    var rows = document.querySelectorAll(".algo");
    if (!rows.length) return;
    var MAX = 256; // widest bar in the set, so rows stay comparable

    Array.prototype.forEach.call(rows, function (row) {
      var classical = parseInt(row.getAttribute("data-classical"), 10);
      var quantum = parseInt(row.getAttribute("data-quantum"), 10);
      var kind = row.getAttribute("data-kind");
      var bars = row.querySelector(".algo-bars");

      function bar(label, value, cls) {
        var zero = value === 0 ? " zero" : "";
        return '<div class="algo-bar">' +
          '<span class="k">' + label + '</span>' +
          '<span class="track"><span class="fill ' + cls + '" data-w="' +
            ((value / MAX) * 100).toFixed(1) + '"></span></span>' +
          '<span class="v' + zero + '">' + value + ' bits</span>' +
        '</div>';
      }

      bars.innerHTML =
        bar("Classical", classical, "classical") +
        bar("Quantum", quantum, kind === "safe" ? "safe" : "quantum");
    });

    function fill(row) {
      var fills = row.querySelectorAll(".fill");
      Array.prototype.forEach.call(fills, function (f, i) {
        f.style.setProperty("--d", i * 120 + "ms");
        f.style.width = f.getAttribute("data-w") + "%";
      });
    }

    if (reduceMotion.matches || !("IntersectionObserver" in window)) {
      Array.prototype.forEach.call(rows, fill);
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        fill(e.target);
        io.unobserve(e.target);
      });
    }, { threshold: 0.35 });
    Array.prototype.forEach.call(rows, function (r) { io.observe(r); });
  }

  startLattice();
  startParallax();
  startCounters();
  buildStrengthChart();

  /* ---------- misc ---------- */

  var year = $("year");
  if (year) year.textContent = String(new Date().getFullYear());
})();
