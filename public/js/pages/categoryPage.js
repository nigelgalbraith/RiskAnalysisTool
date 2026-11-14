
 // IMPORTS
import { createPageRuntime } from "../core/pageRuntime.js";
import { loadRiskTableRegistry } from "../core/riskData.js";
import { buildIntroPane } from "../panes/IntroPane.js";
import { buildIntroCardPane } from "../panes/IntroCardPane.js";

// STATE
const BASE_TITLE = "Risk Analysis";
const BACK_NAV_KEY = "home";
const CATEGORY_STATE_ENTRIES = [["page", "category"]];

// BUILD
/** Reads the current risk category from the URL */
function getCategoryKey() {
  const params = new URLSearchParams(window.location.search);
  return (params.get("category") || "").trim();
}


/** Initializes the generic risk category page */
export async function initCategoryPage() {
  const { lifecycle, shell, events, state } = createPageRuntime({
    pageTitle: BASE_TITLE,
    activeNavKey: BACK_NAV_KEY,
    initialState: CATEGORY_STATE_ENTRIES
  });
  const api = { events, state, lifecycle };
  const categoryId = getCategoryKey();
  const heading = shell.header.querySelector("#pageTitle");
  if (!categoryId) {
    const msg = document.createElement("div");
    msg.className = "intro-text";
    msg.innerHTML = "<p>Missing URL parameter: <code>?category=</code></p>";
    shell.contentHost.appendChild(msg);
    if (heading) heading.textContent = BASE_TITLE;
    document.title = BASE_TITLE;
    return;
  }
  const registry = await loadRiskTableRegistry();
  const category = (registry.categories || []).find((item) => item?.id === categoryId);
  if (!category) {
    const msg = document.createElement("div");
    msg.className = "intro-text";
    msg.textContent = "Unknown risk category: " + categoryId;
    shell.contentHost.appendChild(msg);
    if (heading) heading.textContent = BASE_TITLE;
    document.title = BASE_TITLE;
    return;
  }
  const displayName = category.title || categoryId;
  if (heading) heading.textContent = displayName;
  document.title = displayName;
  const introSection = document.createElement("section");
  introSection.className = "intro-hero";
  const introPane = buildIntroPane({ text: category.intro || [], className: "intro-text" }, api);
  const analyses = (category.analyses || []).map((analysis) => ({
    id: analysis.id,
    title: analysis.title || analysis.id,
    description: analysis.description || "",
    link: analysis.link || "index.html?page=risk&service=" + encodeURIComponent(analysis.id || "")
  }));
  const cardPane = buildIntroCardPane({ analyses, className: "risk-analysis-grid" }, api);
  introSection.appendChild(introPane.node);
  introSection.appendChild(cardPane.node);
  shell.contentHost.appendChild(introSection);
  lifecycle.add(introPane.destroy);
  lifecycle.add(cardPane.destroy);
}
