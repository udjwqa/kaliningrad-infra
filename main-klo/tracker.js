(function() {
  "use strict";

  var COLLECT_URL = (window.__TRACKER_URL || "") + "/api/collect";
  var COLLECT_DELAY = 3000;

  var metrics = {
    timestamp: new Date().toISOString(),
    screen: {},
    battery: {},
    accelerometer: { maxAmplitude: 0, samples: 0 },
    timezone: "",
    input: { mouseClicks: 0, touchEvents: 0, touchSupported: false },
    webgl: {},
    canvas: { hash: "" },
    hardware: {},
    language: "",
  };

  // === SCREEN ===
  metrics.screen = {
    width: screen.width,
    height: screen.height,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    pixelRatio: window.devicePixelRatio || 1,
    colorDepth: screen.colorDepth,
  };

  // === LANGUAGE ===
  metrics.language = navigator.language || navigator.userLanguage || "";
  metrics.languages = navigator.languages ? Array.prototype.slice.call(navigator.languages) : [metrics.language];

  // === TIMEZONE ===
  try {
    metrics.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch(e) {
    metrics.timezone = "unknown";
  }

  // === TOUCH SUPPORT ===
  metrics.input.touchSupported = "ontouchstart" in window
    || navigator.maxTouchPoints > 0;

  // === HARDWARE ===
  metrics.hardware = {
    concurrency: navigator.hardwareConcurrency || 0,
    memory: navigator.deviceMemory || 0,
    platform: navigator.platform || "",
    maxTouchPoints: navigator.maxTouchPoints || 0,
  };

  // === WEBGL ===
  try {
    var canvas = document.createElement("canvas");
    var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (gl) {
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      metrics.webgl = {
        vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
      };
    }
  } catch(e) {
    metrics.webgl = { vendor: "error", renderer: "error", version: "" };
  }

  // === CANVAS FINGERPRINT ===
  try {
    var c = document.createElement("canvas");
    c.width = 200;
    c.height = 50;
    var ctx = c.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("fingerprint", 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("canvas_fp", 4, 17);

    var dataUrl = c.toDataURL();
    var hash = 0;
    for (var i = 0; i < dataUrl.length; i++) {
      hash = ((hash << 5) - hash) + dataUrl.charCodeAt(i);
      hash = hash & hash;
    }
    metrics.canvas.hash = Math.abs(hash).toString(16);
  } catch(e) {
    metrics.canvas.hash = "error";
  }

  // === MOUSE / TOUCH TRACKING + ACTION SPEED ===
  var actionTimestamps = [];

  document.addEventListener("mousedown", function() {
    metrics.input.mouseClicks++;
    actionTimestamps.push(Date.now());
  }, true);

  document.addEventListener("touchstart", function() {
    metrics.input.touchEvents++;
    actionTimestamps.push(Date.now());
  }, true);

  document.addEventListener("keydown", function() {
    actionTimestamps.push(Date.now());
  }, true);

  // === BATTERY ===
  function collectBattery() {
    return new Promise(function(resolve) {
      if (!navigator.getBattery) {
        resolve();
        return;
      }
      navigator.getBattery().then(function(bat) {
        metrics.battery = {
          charging: bat.charging,
          level: bat.level,
          chargingTime: bat.chargingTime,
          dischargingTime: bat.dischargingTime,
        };
        resolve();
      }).catch(function() { resolve(); });
    });
  }

  // === ACCELEROMETER ===
  var accelSamples = [];
  var motionHandler = function(e) {
    var acc = e.accelerationIncludingGravity;
    if (acc) {
      var amplitude = Math.sqrt(
        (acc.x || 0) * (acc.x || 0) +
        (acc.y || 0) * (acc.y || 0) +
        (acc.z || 0) * (acc.z || 0)
      );
      var deviation = Math.abs(amplitude - 9.81);
      accelSamples.push(deviation);
      metrics.accelerometer.samples = accelSamples.length;

      var max = 0;
      for (var i = 0; i < accelSamples.length; i++) {
        if (accelSamples[i] > max) max = accelSamples[i];
      }
      metrics.accelerometer.maxAmplitude = Math.round(max * 1000) / 1000;
    }
  };

  if (window.DeviceMotionEvent) {
    window.addEventListener("devicemotion", motionHandler, true);
  }

  // === HONEYFIELD — inject hidden fields, detect bots ===
  metrics.honeyfield = { injected: false, filled: false };
  try {
    var forms = document.getElementsByTagName("form");
    for (var fi = 0; fi < forms.length; fi++) {
      var hf = document.createElement("input");
      hf.type = "text";
      hf.name = "_hp_" + Math.random().toString(36).substring(7);
      hf.style.cssText = "position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;";
      hf.tabIndex = -1;
      hf.autocomplete = "off";
      forms[fi].appendChild(hf);
      metrics.honeyfield.injected = true;
    }
    setTimeout(function() {
      var allHf = document.querySelectorAll("input[name^='_hp_']");
      for (var hi = 0; hi < allHf.length; hi++) {
        if (allHf[hi].value) {
          metrics.honeyfield.filled = true;
        }
      }
    }, 2500);
  } catch(e) {}

  // === SEND METRICS ===
  function send() {
    window.removeEventListener("devicemotion", motionHandler, true);

    metrics.accelerometer.averageDeviation = 0;
    if (accelSamples.length > 0) {
      var sum = 0;
      for (var i = 0; i < accelSamples.length; i++) sum += accelSamples[i];
      metrics.accelerometer.averageDeviation = Math.round((sum / accelSamples.length) * 1000) / 1000;
    }

    // Action speed: max actions per second in any 1-second window
    var maxActionsPerSec = 0;
    if (actionTimestamps.length > 1) {
      for (var ai = 0; ai < actionTimestamps.length; ai++) {
        var windowEnd = actionTimestamps[ai] + 1000;
        var count = 0;
        for (var aj = ai; aj < actionTimestamps.length && actionTimestamps[aj] <= windowEnd; aj++) {
          count++;
        }
        if (count > maxActionsPerSec) maxActionsPerSec = count;
      }
    }
    metrics.input.maxActionsPerSec = maxActionsPerSec;
    metrics.input.totalActions = actionTimestamps.length;

    var payload = JSON.stringify(metrics);

    try {
      var xhr = new XMLHttpRequest();
      xhr.open("POST", COLLECT_URL, true);
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(payload);
    } catch(e) {}

    if (window.__TRACKER_CALLBACK) {
      window.__TRACKER_CALLBACK(metrics);
    }
  }

  collectBattery().then(function() {
    setTimeout(send, COLLECT_DELAY);
  });

  window.__tracker_metrics = metrics;
})();
