import { expect, test } from "@playwright/test";
import crypto from "node:crypto";
import fs from "node:fs";

// Everything here runs against the isolated stack from global-setup.js.
const stack = () => JSON.parse(fs.readFileSync(process.env.E2E_STATE_FILE, "utf-8"));
const PASSWORD = () => `Pw-${crypto.randomBytes(9).toString("base64url")}`;

async function login(request, username, password) {
  const r = await request.post(`${stack().backend}/api/auth/login`, { data: { username, password } });
  expect(r.ok()).toBeTruthy();
  return (await r.json()).access_token;
}

/** A brand-new normal account (through the public registration API). */
async function makeUser(request, tag) {
  const username = `${tag}-${crypto.randomBytes(3).toString("hex")}`;
  const password = PASSWORD();
  const r = await request.post(`${stack().backend}/api/auth/register`, {
    data: { username, password, email: `${username}@example.org`, full_name: `${tag} Person`, organization: "Portal Org" },
  });
  expect(r.status()).toBe(201);
  return { username, password };
}

async function adminToken(request) {
  const s = stack();
  return login(request, s.admin.username, s.admin.password);
}

async function newRequest(request, user, over = {}) {
  const token = await login(request, user.username, user.password);
  const r = await request.post(`${stack().backend}/api/endpoint-requests`, {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      organization: "Portal Org",
      department: "Portal Dept",
      justification: "Portal test",
      requested_scope: ["authentication", "process_activity"],
      consent_acknowledged: true,
      ...over,
    },
  });
  expect(r.status()).toBe(201);
  return (await r.json()).id;
}

async function decide(request, id, action, data = {}) {
  const token = await adminToken(request);
  const r = await request.post(`${stack().backend}/api/admin/endpoint-requests/${id}/${action}`, {
    headers: { Authorization: `Bearer ${token}` },
    data,
  });
  expect(r.ok(), `${action} failed`).toBeTruthy();
}

async function signIn(page, user) {
  await page.goto("/");
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "My endpoint requests" })).toBeVisible();
}

const statusRegion = (page) => page.getByRole("region", { name: "Status" });
const bell = (page) => page.getByRole("button", { name: /^Notifications/ });

test.describe.configure({ mode: "serial" });

test("a visitor can create an account in the browser, sign in, and see an empty portal", async ({ page }) => {
  const username = `ui-${crypto.randomBytes(3).toString("hex")}`;
  const password = PASSWORD();
  await page.goto("/");
  await page.getByRole("button", { name: "Create one" }).click();
  await page.getByLabel("Full name").fill("Ui Person");
  await page.getByLabel("Email").fill(`${username}@example.org`);
  await page.getByLabel("Organization").fill("Ui Org");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill("short");
  await page.getByRole("button", { name: "Create account" }).click(); // browser validation blocks a short password
  await expect(page.getByRole("heading", { name: /Create account/ })).toBeVisible();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("status")).toContainText("Account created");

  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "My endpoint requests" })).toBeVisible();
  await expect(page.getByText("Ui Person")).toBeVisible(); // profile
  await expect(page.getByText("Ui Org")).toBeVisible();
  await expect(page.getByText("You have not made any requests yet")).toBeVisible();
});

test("the user dashboard renders profile and navigation, with no administrator links", async ({ page, request }) => {
  const user = await makeUser(request, "dash");
  await signIn(page, user);
  await expect(page.getByText(`${"dash"} Person`)).toBeVisible();
  await expect(page.getByText(`${user.username}@example.org`)).toBeVisible();
  await expect(page.getByText("Portal Org")).toBeVisible();
  await expect(page.getByRole("link", { name: /Request to use UBADS Agent/ })).toBeVisible();
  for (const name of ["Events", "Endpoint Requests", "Anomalies", "Settings", "Users & Baselines"]) {
    await expect(page.getByRole("link", { name })).toHaveCount(0);
  }
});

test("submitting a request needs consent, then shows the pending status", async ({ page, request }) => {
  const user = await makeUser(request, "form");
  await signIn(page, user);
  await page.getByRole("link", { name: /Request to use UBADS Agent/ }).click();
  await expect(page.getByRole("heading", { name: "Request to use the UBADS Agent" })).toBeVisible();
  await expect(page.getByText(/Browser compatibility check/)).toBeVisible();

  const submit = page.getByRole("button", { name: "Submit request" });
  await expect(page.getByLabel(/Authentication events/)).toBeChecked(); // sensible default
  await expect(submit).toBeDisabled(); // no consent yet
  await page.getByLabel(/Department/).fill("Security Lab");
  await page.getByLabel(/Justification/).fill("Research laptop for the behaviour study");
  await page.getByLabel(/Process activity/).check();
  await expect(submit).toBeDisabled(); // scope chosen, still no consent
  await page.getByLabel(/I understand that the UBADS agent/).check();
  await expect(submit).toBeEnabled();
  await page.getByLabel(/Authentication events/).uncheck();
  await page.getByLabel(/Process activity/).uncheck();
  await expect(submit).toBeDisabled(); // consent but no scope
  await page.getByLabel(/Process activity/).check();
  await submit.click();

  await expect(page).toHaveURL(/\/portal\/requests\/[0-9a-f-]+$/);
  await expect(page.getByRole("status")).toContainText("Request submitted");
  await expect(statusRegion(page)).toContainText("Waiting for administrator review");
  await expect(statusRegion(page)).toContainText("Nothing is installed or collected yet");
  await expect(page.getByText("PENDING", { exact: true })).toBeVisible();
  await expect(page.getByText("Security Lab")).toBeVisible();
  await expect(page.getByText("Research laptop for the behaviour study")).toBeVisible();
  await expect(page.getByText("process_activity", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: /installer download/i })).toHaveCount(0);

  await page.getByRole("link", { name: "← All requests" }).click();
  await expect(page.getByRole("row").filter({ hasText: "Security Lab" })).toContainText("PENDING");
});

test("a pending user cannot download: no link, a clear denial on the page, and a 403 from the backend", async ({ page, request }) => {
  const user = await makeUser(request, "pend");
  const id = await newRequest(request, user);
  await signIn(page, user);
  await page.goto(`/portal/requests/${id}`);
  await expect(page.getByRole("link", { name: /installer download/i })).toHaveCount(0);

  await page.goto(`/portal/requests/${id}/download`); // typing the URL directly
  await expect(page.getByRole("alert")).toContainText("still waiting for administrator approval");
  await expect(page.getByRole("button", { name: "Download installer" })).toHaveCount(0);

  const token = await login(request, user.username, user.password);
  const direct = await request.get(`${stack().backend}/api/endpoint-requests/${id}/download`, { headers: { Authorization: `Bearer ${token}` } });
  expect(direct.status()).toBe(403);
  const packageResponse = await request.post(`${stack().backend}/api/endpoint-requests/${id}/enrollment-package`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(packageResponse.status()).toBe(403);
  expect(await direct.text()).not.toContain(stack().installerContent);
});

test("notifications: unread badge, list, open the related request, mark read", async ({ page, request }) => {
  const user = await makeUser(request, "note");
  const id = await newRequest(request, user);
  await decide(request, id, "approve", { approved_scope: ["authentication"] });
  await signIn(page, user);

  await expect(page.getByTestId("unread-badge")).toHaveText("2"); // submitted + approved
  await bell(page).click();
  const menu = page.getByRole("menu", { name: "Notifications" });
  await expect(menu.getByRole("menuitem")).toHaveCount(2);
  await expect(menu.getByRole("menuitem").first()).toContainText("Request approved");
  await expect(menu.getByRole("menuitem").first()).toContainText(/\d{4}|\d+:\d+/); // timestamp shown
  await expect(menu.getByLabel("unread")).toHaveCount(2);

  await menu.getByRole("menuitem").first().click(); // navigates to the request and marks it read
  await expect(page).toHaveURL(new RegExp(`/portal/requests/${id}$`));
  await expect(page.getByTestId("unread-badge")).toHaveText("1");

  await bell(page).click();
  await page.getByRole("menu", { name: "Notifications" }).getByRole("button", { name: /Mark all read/ }).click();
  await expect(page.getByTestId("unread-badge")).toHaveCount(0);
  await page.keyboard.press("Escape");

  await page.getByRole("link", { name: "Notifications" }).click();
  await expect(page.getByRole("heading", { name: "Notifications" })).toBeVisible();
  await expect(page.getByText("Request submitted")).toBeVisible();
  await expect(page.getByLabel("unread")).toHaveCount(0);
});

test("an approved user downloads one endpoint-specific installer package without exposing its code", async ({ page, request }) => {
  const user = await makeUser(request, "appr");
  const id = await newRequest(request, user);
  await decide(request, id, "approve", { approved_scope: ["authentication"] });
  await signIn(page, user);
  await page.goto(`/portal/requests/${id}`);

  await expect(statusRegion(page)).toContainText("Approved - not installed yet");
  await expect(statusRegion(page)).toContainText("nothing has been installed on any computer");
  await expect(page.getByText("The administrator approved less than you asked for.")).toBeVisible();
  await page.getByRole("link", { name: /Go to installer download/ }).click();

  await expect(page.getByRole("heading", { name: "Download the Windows agent" })).toBeVisible();
  await expect(page.getByText(/does not\s+install anything by itself/i)).toBeVisible();
  await expect(page.getByText("Endpoint-specific enrollment package")).toBeVisible();
  await expect(page.getByText(/SHA-256: [0-9a-f]{64}/)).toBeVisible();
  await expect(page.getByText(/User Account Control/)).toBeVisible(); // UAC explained
  await expect(page.getByText(/enroll it automatically/)).toBeVisible();
  await expect(page.getByText(/short-lived, single-use authorization/)).toBeVisible();
  await expect(page.getByText(/Installed apps/)).toBeVisible(); // uninstall instructions
  await expect(page.getByText(/ask an administrator to revoke/)).toBeVisible();
  await expect(page.getByText("Authentication events", { exact: true })).toBeVisible(); // approved scope only
  await expect(page.getByText("Process activity", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Keystrokes")).toBeVisible(); // listed under never collected

  let packageRequests = 0;
  const consoleMessages = [];
  page.on("request", (req) => {
    if (req.method() === "POST" && req.url().includes(`/api/endpoint-requests/${id}/enrollment-package`)) packageRequests += 1;
  });
  page.on("console", (message) => consoleMessages.push(message.text()));
  const button = page.getByRole("button", { name: "Download installer" });
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    button.dblclick({ force: true, delay: 10 }),
  ]);
  const filename = download.suggestedFilename();
  expect(/^UBADS-Agent-Setup--ubads1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}\.exe$/.test(filename)).toBe(true);
  expect(fs.readFileSync(await download.path(), "utf-8")).toBe(stack().installerContent);
  expect(packageRequests).toBe(1);
  const enrollmentCode = filename.slice("UBADS-Agent-Setup--".length, -".exe".length);
  const pageText = await page.locator("body").innerText();
  expect(pageText.includes(enrollmentCode)).toBe(false);
  expect(consoleMessages.some((message) => message.includes(enrollmentCode))).toBe(false);
  await expect(page.getByRole("status")).toContainText("Download started");
  await expect(page.getByRole("button", { name: "Package downloaded" })).toBeDisabled();
});

test("an enrolled request no longer offers a package and explains the status", async ({ page, request }) => {
  const user = await makeUser(request, "used");
  const id = await newRequest(request, user);
  await decide(request, id, "approve", { approved_scope: ["authentication"] });
  const token = await login(request, user.username, user.password);
  const packageResponse = await request.post(`${stack().backend}/api/endpoint-requests/${id}/enrollment-package`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(packageResponse.status()).toBe(200);
  const disposition = packageResponse.headers()["content-disposition"] || "";
  const filenameMatch = disposition.match(/filename="UBADS-Agent-Setup--(.+)\.exe"/);
  expect(Boolean(filenameMatch)).toBe(true);

  const redeemed = await request.post(`${stack().backend}/api/agent/enrollment/redeem`, {
    data: {
      code: filenameMatch[1],
      display_name: "TEST-PORTAL-ENDPOINT",
      operating_system: "Windows 11",
      agent_version: "0.1.0",
    },
  });
  expect(redeemed.status()).toBe(200);

  await signIn(page, user);
  await page.goto(`/portal/requests/${id}/download`);
  await expect(page.getByRole("alert")).toContainText("already enrolled");
  await expect(page.getByRole("button", { name: "Download installer" })).toHaveCount(0);
});

test("rejected and revoked users cannot download and see the outcome", async ({ page, request }) => {
  const rejected = await makeUser(request, "rej");
  const rejectedId = await newRequest(request, rejected);
  await decide(request, rejectedId, "reject", { reason: "Not an authorised machine" });

  const revoked = await makeUser(request, "rev");
  const revokedId = await newRequest(request, revoked);
  await decide(request, revokedId, "approve");
  await decide(request, revokedId, "revoke", { reason: "Policy change" });

  await signIn(page, rejected);
  await page.goto(`/portal/requests/${rejectedId}`);
  await expect(statusRegion(page)).toContainText("Request rejected");
  await expect(statusRegion(page)).toContainText("Not an authorised machine");
  await expect(page.getByRole("link", { name: /installer download/i })).toHaveCount(0);
  await page.goto(`/portal/requests/${rejectedId}/download`);
  await expect(page.getByRole("alert")).toContainText("was rejected");
  await expect(page.getByRole("button", { name: "Download installer" })).toHaveCount(0);
  await page.getByRole("button", { name: /Sign out/ }).click();

  await signIn(page, revoked);
  await page.goto(`/portal/requests/${revokedId}`);
  await expect(statusRegion(page)).toContainText("Authorization revoked");
  await expect(statusRegion(page)).toContainText("Policy change");
  await expect(page.getByRole("link", { name: /installer download/i })).toHaveCount(0);
  await page.goto(`/portal/requests/${revokedId}/download`);
  await expect(page.getByRole("alert")).toContainText("was revoked");
  await expect(page.getByRole("button", { name: "Download installer" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "My endpoint requests" })).toHaveCount(0);

  // the same denial straight from the backend, bypassing the UI entirely
  for (const [who, id] of [[revoked, revokedId], [rejected, rejectedId]]) {
    const token = await login(request, who.username, who.password);
    const r = await request.get(`${stack().backend}/api/endpoint-requests/${id}/download`, { headers: { Authorization: `Bearer ${token}` } });
    expect(r.status()).toBe(403);
    const packageResponse = await request.post(`${stack().backend}/api/endpoint-requests/${id}/enrollment-package`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(packageResponse.status()).toBe(403);
  }
});

test("a user cannot open another user's request, download or notifications", async ({ page, request }) => {
  const owner = await makeUser(request, "own");
  const intruder = await makeUser(request, "intr");
  const id = await newRequest(request, owner, { justification: "OWNER-PRIVATE-JUSTIFICATION" });
  await decide(request, id, "approve");

  await signIn(page, intruder);
  await page.goto(`/portal/requests/${id}`);
  await expect(page.getByText("does not exist, or it does not belong to your account")).toBeVisible();
  await expect(page.getByText("OWNER-PRIVATE-JUSTIFICATION")).toHaveCount(0);
  await page.goto(`/portal/requests/${id}/download`);
  await expect(page.getByRole("alert")).toContainText("does not exist, or it does not belong to your account");
  await expect(page.getByRole("button", { name: "Download installer" })).toHaveCount(0);
  await page.goto("/portal");
  await expect(page.getByText("You have not made any requests yet")).toBeVisible();
  await expect(bell(page)).toHaveAccessibleName("Notifications"); // zero unread for the intruder
  await expect(page.getByTestId("unread-badge")).toHaveCount(0);

  const token = await login(request, intruder.username, intruder.password);
  const h = { headers: { Authorization: `Bearer ${token}` } };
  expect((await request.get(`${stack().backend}/api/endpoint-requests/${id}/download`, h)).status()).toBe(404);
  expect((await request.post(`${stack().backend}/api/endpoint-requests/${id}/enrollment-package`, h)).status()).toBe(404);
  expect((await request.get(`${stack().backend}/api/endpoint-requests/${id}`, h)).status()).toBe(404);
  expect(await (await request.get(`${stack().backend}/api/notifications`, h)).json()).toEqual([]);
  expect((await request.get(`${stack().backend}/api/admin/endpoint-requests`, h)).status()).toBe(403);
});

test("the administrator portal still works, including notification deep links", async ({ page, request }) => {
  const user = await makeUser(request, "adm");
  const id = await newRequest(request, user, { department: "Admin-Visible-Dept" });
  const s = stack();
  await page.goto("/");
  await page.getByLabel("Username").fill(s.admin.username);
  await page.getByLabel("Password").fill(s.admin.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("link", { name: "Endpoint Requests" })).toBeVisible();

  await expect(page.getByTestId("unread-badge")).toBeVisible(); // "new request" alert for the admin
  await bell(page).click();
  const item = page.getByRole("menu", { name: "Notifications" }).getByRole("menuitem").filter({ hasText: "adm-" }).first();
  await expect(item).toContainText("New endpoint request");
  await item.click();

  await expect(page).toHaveURL(new RegExp(`/endpoint-requests\\?request=${id}`));
  await expect(page.getByText("Request details")).toBeVisible();
  await expect(page.getByText("Admin-Visible-Dept").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Approve" }).click();
  await expect(page.getByRole("status")).toContainText("Request approved");

  // and the admin app's other pages are still reachable
  await page.keyboard.press("Escape"); // close the details drawer
  await page.getByRole("link", { name: "Events" }).click();
  await expect(page.getByRole("heading", { name: "Events", level: 2 })).toBeVisible();
});
