// Native disclosures work without JavaScript. Escape closes navigation and restores focus.
const navigationMenus = [
  ...document.querySelectorAll(".site-menu, .docs-mobile"),
];
for (const menu of navigationMenus) {
  menu.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.open) {
      menu.open = false;
      menu.querySelector("summary").focus();
    }
  });
  menu.querySelectorAll("a").forEach((link) =>
    link.addEventListener("click", () => {
      menu.open = false;
    }),
  );
}
matchMedia("(min-width: 761px)").addEventListener("change", () => {
  for (const menu of navigationMenus) menu.open = false;
});

for (const button of document.querySelectorAll("[data-copy-target]")) {
  let resetTimer;
  button.addEventListener("click", async () => {
    const command = document.getElementById(button.dataset.copyTarget);
    const status =
      button.closest(".install-card")?.nextElementSibling ??
      button.closest(".command-box")?.nextElementSibling;
    const text = command.textContent.trim();
    clearTimeout(resetTimer);
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
      if (status) status.textContent = "Command copied.";
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(command);
      selection.removeAllRanges();
      selection.addRange(range);
      if (status)
        status.textContent = "Command selected. Use your device’s copy action.";
    }
    resetTimer = setTimeout(() => {
      button.textContent = "Copy";
      if (status) status.textContent = "";
    }, 3500);
  });
}

for (const tablist of document.querySelectorAll('[role="tablist"]')) {
  const tabs = [...tablist.querySelectorAll('[role="tab"]')];
  const panel = document.getElementById(tabs[0].getAttribute("aria-controls"));
  function activateTab(selected) {
    tabs.forEach((tab) => {
      const active = tab === selected;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      tab.classList.toggle("active", active);
    });
    panel.setAttribute("aria-labelledby", selected.id);
    panel.querySelector("code").textContent = selected.dataset.cmd;
    panel.querySelector(".copy-btn").textContent = "Copy";
    panel.closest(".install-card").nextElementSibling.textContent = "";
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activateTab(tab));
    tab.addEventListener("keydown", (event) => {
      let next;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      else if (event.key === "ArrowLeft")
        next = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else return;
      event.preventDefault();
      activateTab(tabs[next]);
      tabs[next].focus();
    });
  });
}

// Expand a disclosure when a shared deep link points into it.
function revealAnchor() {
  let identifier;
  try {
    identifier = decodeURIComponent(location.hash.slice(1));
  } catch {
    return;
  }
  const target = document.getElementById(identifier);
  if (!target) return;
  let ancestor = target;
  while (ancestor) {
    if (ancestor.tagName === "DETAILS") ancestor.open = true;
    ancestor = ancestor.parentElement;
  }
  target.scrollIntoView();
}
window.addEventListener("hashchange", revealAnchor);
revealAnchor();
