"use strict";

// The local page. It polls /api/state and appends stages as the terminal reveals them.
// All text from the agent goes in with textContent. The only innerHTML is the SVG that Mermaid
// draws (securityLevel "strict" sanitizes it), and the page's Content-Security-Policy blocks
// anything that is not served by this same server.
(function () {
  const POLL_MS = 1000;
  const stagesEl = document.getElementById("stages");
  const statusEl = document.getElementById("status");
  const topicEl = document.getElementById("topic");

  mermaid.initialize({
    startOnLoad: false,
    securityLevel: "strict",
    theme: "default",
    // useMaxWidth false keeps each diagram at its natural width, so a wide one scrolls in its box.
    flowchart: { htmlLabels: false, useMaxWidth: false },
    sequence: { useMaxWidth: false },
  });

  let shown = 0; // stages already on the page
  let seenFocusSeq = null; // null until the first poll, so a reload does not scroll
  let renderErrors = 0;
  let drawCount = 0;
  let drawQueue = Promise.resolve(); // Mermaid draws one diagram at a time

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setStatus(text, problem) {
    statusEl.textContent = text;
    statusEl.classList.toggle("problem", Boolean(problem));
  }

  function blockEl(block, prefix) {
    const wrap = el("div", "block");
    wrap.appendChild(el("span", "tag tag-" + block.tag, block.tag));
    wrap.appendChild(el("p", null, (prefix ? prefix + ": " : "") + block.value));
    if (block.source_url && /^https?:\/\//.test(block.source_url)) {
      const link = el("a", "source", "source");
      link.href = block.source_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      wrap.appendChild(link);
    }
    return wrap;
  }

  function draw(code) {
    const id = "mermaid-" + ++drawCount;
    const job = drawQueue.then(() => mermaid.render(id, code));
    drawQueue = job.catch(() => {}); // a failed diagram must not block the next one
    return job;
  }

  function fillDiagram(box, code, what) {
    draw(code).then(
      (result) => {
        box.innerHTML = result.svg;
      },
      (error) => {
        renderErrors += 1;
        box.replaceChildren(el("p", "render-error", "Could not draw " + what + ": " + (error && error.message ? error.message : error)));
        setStatus("Diagram render errors: " + renderErrors, true);
      }
    );
  }

  function diagramEl(stage) {
    const box = el("div", "diagram");
    fillDiagram(box, stage.diagram.mermaid, "the diagram");
    return box;
  }

  // Frame k shows attack steps 1..k. Previous and Next move between frames.
  function framesEl(stage) {
    const total = stage.frames.length;
    const wrap = el("div", "frames");
    const controls = el("div", "frame-controls");
    const prev = el("button", null, "Previous");
    const next = el("button", null, "Next");
    const label = el("span", "frame-label");
    prev.type = next.type = "button";
    controls.append(prev, label, next);

    const stack = el("div", "diagram");
    const boxes = stage.frames.map((frame) => {
      const box = el("div", "frame");
      fillDiagram(box, frame.mermaid, "frame " + frame.step);
      stack.appendChild(box);
      return box;
    });
    const detail = el("div", "frame-detail");

    function show(k) {
      boxes.forEach((box, i) => {
        box.hidden = i !== k - 1;
      });
      label.textContent = "Frame " + k + " of " + total;
      prev.disabled = k === 1;
      next.disabled = k === total;
      detail.replaceChildren(blockEl(stage.chain[k - 1].detail, "Step " + k));
      current = k;
    }
    let current = 1;
    prev.addEventListener("click", () => current > 1 && show(current - 1));
    next.addEventListener("click", () => current < total && show(current + 1));
    show(1);

    wrap.append(controls, stack, detail);
    return wrap;
  }

  // Terms this stage introduces, each with a tagged one-sentence definition.
  function glossaryEl(glossary) {
    const box = el("div", "glossary");
    box.appendChild(el("h3", null, "New terms"));
    glossary.forEach((entry) => {
      const item = el("div", "term");
      item.appendChild(el("strong", "term-name", entry.term));
      item.appendChild(blockEl(entry.definition));
      box.appendChild(item);
    });
    return box;
  }

  function stageEl(stage) {
    const section = el("section", "stage");
    section.id = "stage-" + stage.stage_number;
    section.appendChild(el("h2", null, "Stage " + stage.stage_number + ": " + stage.title));
    stage.blocks.forEach((block) => section.appendChild(blockEl(block)));
    if (stage.glossary && stage.glossary.length > 0) section.appendChild(glossaryEl(stage.glossary));
    if (stage.frames && stage.frames.length > 0) {
      section.appendChild(framesEl(stage));
    } else if (stage.diagram) {
      section.appendChild(diagramEl(stage));
    }
    return section;
  }

  function focusStage(number) {
    const section = document.getElementById("stage-" + number);
    if (!section) return;
    section.scrollIntoView({ behavior: "smooth", block: "start" });
    section.classList.add("flash");
    setTimeout(() => section.classList.remove("flash"), 2000);
  }

  function apply(state) {
    topicEl.textContent = state.topic;
    // New stages go below the existing ones. Existing stages are never rebuilt, so the scroll
    // position and any frame the reader is looking at stay as they are.
    while (shown < state.stages.length) {
      stagesEl.appendChild(stageEl(state.stages[shown]));
      shown += 1;
    }
    if (renderErrors === 0) {
      setStatus("Stages shown: " + state.revealed + " of " + state.written + " written (" + state.planned + " planned). Type next in the terminal for more.");
    }
    if (seenFocusSeq !== null && state.focus.seq !== seenFocusSeq) focusStage(state.focus.stage);
    seenFocusSeq = state.focus.seq;
  }

  async function poll() {
    try {
      const response = await fetch("/api/state", { cache: "no-store", credentials: "same-origin" });
      if (response.status === 403) {
        setStatus("This session is not valid. Open the address printed in the terminal again.", true);
      } else if (!response.ok) {
        throw new Error("HTTP " + response.status);
      } else {
        apply(await response.json());
      }
    } catch (error) {
      setStatus("Cannot reach the agent. Is it still running in the terminal?", true);
    }
    setTimeout(poll, POLL_MS);
  }

  poll();
})();
