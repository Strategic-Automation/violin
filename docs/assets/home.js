// Preserve links shared before the documentation was split into pages.
const legacySections = {
  how: "guard.html#how",
  for: "guard.html#for",
  compare: "guard.html#compare",
  limits: "guard.html#limits",
  engagement: "guide.html#engagement",
  start: "guide.html#start",
  faq: "guide.html#faq",
  playbooks: "coverage.html#playbooks",
  tools: "tools.html#tools",
  articles: "engineering.html#articles",
};
function followLegacyLink() {
  const destination = legacySections[location.hash.slice(1)];
  if (destination) location.replace(new URL(destination, location.href));
}
window.addEventListener("hashchange", followLegacyLink);
followLegacyLink();
