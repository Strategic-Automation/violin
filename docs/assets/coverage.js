const filterPills = document.querySelectorAll(".filter-pill");
const playbookCards = document.querySelectorAll(".playbook-card");
const searchInput = document.getElementById("playbook-search");

function updatePlaybooks() {
  const activePill = document.querySelector(".filter-pill.active");
  const filterCat = activePill ? activePill.getAttribute("data-filter") : "all";
  const query = (searchInput ? searchInput.value : "").toLowerCase().trim();

  let count = 0;
  playbookCards.forEach((card) => {
    const cat = card.getAttribute("data-cat");
    const name = card.querySelector(".playbook-name").textContent.toLowerCase();
    const matchesCat = filterCat === "all" || cat === filterCat;
    const matchesQuery = !query || name.includes(query) || cat.includes(query);

    if (matchesCat && matchesQuery) {
      card.hidden = false;
      count++;
    } else {
      card.hidden = true;
    }
  });
  document.getElementById("playbook-results").textContent = count
    ? `${count} of ${playbookCards.length} playbooks`
    : "No matching playbooks. Try another search or select All.";
}

filterPills.forEach((pill) => {
  pill.setAttribute("aria-pressed", String(pill.classList.contains("active")));
  pill.addEventListener("click", () => {
    filterPills.forEach((p) => {
      p.classList.remove("active");
      p.setAttribute("aria-pressed", "false");
    });
    pill.classList.add("active");
    pill.setAttribute("aria-pressed", "true");
    updatePlaybooks();
  });
});

if (searchInput) {
  searchInput.addEventListener("input", updatePlaybooks);
}

// Keep cards readable without JavaScript; initialize the enhanced result count.
updatePlaybooks();
