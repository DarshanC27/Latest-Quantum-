/* q3d — a very small 3D wireframe renderer for the design lab.
 *
 * Three.js would be the obvious choice, but every page in this lab is a
 * single file you can open from disk with no build step and no network,
 * so the maths is done here instead. It is only perspective projection
 * plus two rotation matrices — enough for wireframe solids, lattices and
 * orbiting particles, which is all the quantum-flavoured geometry needs.
 *
 * Everything respects prefers-reduced-motion by rendering one static
 * frame rather than animating.
 */
(function (global) {
  "use strict";

  var reduce = global.matchMedia &&
    global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- geometry generators ---------- */

  function cubeLattice(n, spread) {
    // A grid of points in a cube: reads as a qubit array / crystal lattice.
    var pts = [], edges = [], step = spread / (n - 1), i = 0, map = {};
    for (var x = 0; x < n; x++)
      for (var y = 0; y < n; y++)
        for (var z = 0; z < n; z++) {
          map[x + "," + y + "," + z] = i;
          pts.push([-spread / 2 + x * step, -spread / 2 + y * step, -spread / 2 + z * step]);
          i++;
        }
    for (var a = 0; a < n; a++)
      for (var b = 0; b < n; b++)
        for (var c = 0; c < n; c++) {
          var here = map[a + "," + b + "," + c];
          if (a + 1 < n) edges.push([here, map[(a + 1) + "," + b + "," + c]]);
          if (b + 1 < n) edges.push([here, map[a + "," + (b + 1) + "," + c]]);
          if (c + 1 < n) edges.push([here, map[a + "," + b + "," + (c + 1)]]);
        }
    return { points: pts, edges: edges };
  }

  function sphere(radius, rings, segments) {
    // Latitude/longitude wireframe — the Bloch sphere shape.
    var pts = [], edges = [], grid = [];
    for (var r = 0; r <= rings; r++) {
      var phi = (r / rings) * Math.PI, row = [];
      for (var s = 0; s < segments; s++) {
        var theta = (s / segments) * Math.PI * 2;
        row.push(pts.length);
        pts.push([
          radius * Math.sin(phi) * Math.cos(theta),
          radius * Math.cos(phi),
          radius * Math.sin(phi) * Math.sin(theta)
        ]);
      }
      grid.push(row);
    }
    for (var i = 0; i < grid.length; i++)
      for (var j = 0; j < grid[i].length; j++) {
        edges.push([grid[i][j], grid[i][(j + 1) % grid[i].length]]);
        if (i + 1 < grid.length) edges.push([grid[i][j], grid[i + 1][j]]);
      }
    return { points: pts, edges: edges };
  }

  function torus(R, r, major, minor) {
    var pts = [], edges = [], grid = [];
    for (var i = 0; i < major; i++) {
      var u = (i / major) * Math.PI * 2, row = [];
      for (var j = 0; j < minor; j++) {
        var v = (j / minor) * Math.PI * 2;
        row.push(pts.length);
        pts.push([
          (R + r * Math.cos(v)) * Math.cos(u),
          r * Math.sin(v),
          (R + r * Math.cos(v)) * Math.sin(u)
        ]);
      }
      grid.push(row);
    }
    for (var a = 0; a < major; a++)
      for (var b = 0; b < minor; b++) {
        edges.push([grid[a][b], grid[a][(b + 1) % minor]]);
        edges.push([grid[a][b], grid[(a + 1) % major][b]]);
      }
    return { points: pts, edges: edges };
  }

  function icosahedron(radius) {
    var t = (1 + Math.sqrt(5)) / 2;
    var raw = [
      [-1, t, 0], [1, t, 0], [-1, -t, 0], [1, -t, 0],
      [0, -1, t], [0, 1, t], [0, -1, -t], [0, 1, -t],
      [t, 0, -1], [t, 0, 1], [-t, 0, -1], [-t, 0, 1]
    ];
    var scale = radius / Math.sqrt(1 + t * t);
    var pts = raw.map(function (p) { return [p[0] * scale, p[1] * scale, p[2] * scale]; });
    var faces = [
      [0,11,5],[0,5,1],[0,1,7],[0,7,10],[0,10,11],[1,5,9],[5,11,4],[11,10,2],
      [10,7,6],[7,1,8],[3,9,4],[3,4,2],[3,2,6],[3,6,8],[3,8,9],[4,9,5],
      [2,4,11],[6,2,10],[8,6,7],[9,8,1]
    ];
    var seen = {}, edges = [];
    faces.forEach(function (f) {
      [[f[0],f[1]],[f[1],f[2]],[f[2],f[0]]].forEach(function (e) {
        var key = Math.min(e[0], e[1]) + ":" + Math.max(e[0], e[1]);
        if (!seen[key]) { seen[key] = 1; edges.push(e); }
      });
    });
    return { points: pts, edges: edges };
  }

  /* ---------- renderer ---------- */

  function Scene(canvas, options) {
    options = options || {};
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.shape = options.shape || sphere(1, 10, 16);
    this.stroke = options.stroke || "rgba(255,255,255,0.5)";
    this.nodeColour = options.nodeColour || null;
    this.nodeSize = options.nodeSize || 0;
    this.lineWidth = options.lineWidth || 1;
    this.distance = options.distance || 3.2;
    this.scale = options.scale || 1;
    this.speed = options.speed === undefined ? 1 : options.speed;
    this.tilt = 0.35;
    this.spin = 0;
    this.pointer = { x: 0, y: 0 };
    this.running = false;
    this._resize();
  }

  Scene.prototype._resize = function () {
    var rect = this.canvas.getBoundingClientRect();
    var dpr = Math.min(global.devicePixelRatio || 1, 2);
    this.w = rect.width; this.h = rect.height;
    this.canvas.width = Math.max(1, Math.round(this.w * dpr));
    this.canvas.height = Math.max(1, Math.round(this.h * dpr));
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };

  Scene.prototype._project = function (p) {
    var cy = Math.cos(this.spin), sy = Math.sin(this.spin);
    var x = p[0] * cy - p[2] * sy;
    var z = p[0] * sy + p[2] * cy;
    var cx = Math.cos(this.tilt), sx = Math.sin(this.tilt);
    var y = p[1] * cx - z * sx;
    z = p[1] * sx + z * cx;
    var depth = this.distance - z;
    if (depth <= 0.1) depth = 0.1;
    var f = (Math.min(this.w, this.h) * 0.42 * this.scale) / depth;
    return { x: this.w / 2 + x * f, y: this.h / 2 + y * f, d: depth };
  };

  Scene.prototype.draw = function () {
    var ctx = this.ctx, s = this.shape, i;
    ctx.clearRect(0, 0, this.w, this.h);

    var flat = new Array(s.points.length);
    for (i = 0; i < s.points.length; i++) flat[i] = this._project(s.points[i]);

    ctx.lineWidth = this.lineWidth;
    for (i = 0; i < s.edges.length; i++) {
      var a = flat[s.edges[i][0]], b = flat[s.edges[i][1]];
      // Fade with depth so the far side of the solid reads as behind.
      var near = 1 - Math.min(1, Math.max(0, ((a.d + b.d) / 2 - 1) / this.distance));
      ctx.globalAlpha = 0.15 + near * 0.85;
      ctx.strokeStyle = this.stroke;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    if (this.nodeSize > 0) {
      for (i = 0; i < flat.length; i++) {
        var n = flat[i];
        var t = 1 - Math.min(1, Math.max(0, (n.d - 1) / this.distance));
        ctx.globalAlpha = 0.25 + t * 0.75;
        ctx.fillStyle = this.nodeColour || this.stroke;
        ctx.beginPath();
        ctx.arc(n.x, n.y, this.nodeSize * (0.5 + t * 0.8), 0, Math.PI * 2);
        ctx.fill();
      }
    }
    ctx.globalAlpha = 1;
  };

  Scene.prototype.start = function () {
    var self = this;
    if (reduce) { this.draw(); return this; }   // one static frame
    this.running = true;

    (function loop() {
      if (!self.running) return;
      self.spin += 0.0045 * self.speed;
      self.tilt += (self.pointer.y * 0.55 - self.tilt) * 0.045;
      self.draw();
      global.requestAnimationFrame(loop);
    })();

    global.addEventListener("resize", function () {
      self._resize();
      if (reduce) self.draw();
    });

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) { self.running = false; }
      else if (!self.running) { self.running = true; loop(); }
      function loop() {
        if (!self.running) return;
        self.spin += 0.0045 * self.speed;
        self.draw();
        global.requestAnimationFrame(loop);
      }
    });

    return this;
  };

  Scene.prototype.track = function (element) {
    var self = this;
    (element || global).addEventListener("mousemove", function (e) {
      self.pointer.x = (e.clientX / global.innerWidth) * 2 - 1;
      self.pointer.y = (e.clientY / global.innerHeight) * 2 - 1;
    }, { passive: true });
    return this;
  };

  global.Q3D = {
    Scene: Scene,
    cubeLattice: cubeLattice,
    sphere: sphere,
    torus: torus,
    icosahedron: icosahedron,
    reducedMotion: reduce
  };
})(window);
