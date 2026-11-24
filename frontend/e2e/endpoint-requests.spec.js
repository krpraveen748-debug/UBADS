import { expect, test } from "@playwright/test";
import fs from "node:fs";

// All accounts below exist only in the throwaway database created by
// global-setup.js. Credentials are read from a temp file and never logged.
const stack = () => JSON.parse(fs.readFileSync(process.env.E2E_STATE_FILE, "utf-8"));

async function apiToken(request, who) {
  const s = stack();
  const r = await request.post(`${s.backend}/api/auth/login`, { data: { username: s[who].username, password: s[who].password } });
  expect(r.ok()).toBeTruthy();
  return (await r.json()).access_token;
}

let counter = 0;
/** Creates a pending request as the seeded normal user (through the API). */
async function createRequest(request, overrides = {}) {
  const s = stack();
  const token = await apiToken(request, "user");
  const department = `Dept-${Date.now()}-${counter++}`;
  const r = await request.post(`${s.backend}/api/endpoint-requests`, {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      organization: "E2E Org",
      department,
      justification: `Justification for ${department}`,
      requested_scope: ["authentication"],
      consent_acknowledged: true,
      ...overrides,
    },
  });
  expect(r.status()).toBe(201);
  return { ...(await r.json()), department };
}

async function signIn(page, who) {
  const s = stack();
  await page.goto("/");
  await page.getByLabel("Username").fill(s[who].username);
  await page.getByLabel("Password").fill(s[who].password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function openEndpointRequests(page) {
  await signIn(page, "admin");
  await page.getByRole("link", { name: "Endpoint Requests" }).click();
  await expect(page.getByRole("heading", { name: "Endpoint Requests", level: 2 })).toBeVisible();
}

const pendingCount = (page) => page.locator('p:text-is("Pending") + p');
const rowFor = (page, department) => page.getByRole("row").filter({ hasText: department });
const drawer = (page) => page.locator("div.fixed.inset-0.z-50");

test.describe.configure({ mode: "serial" });

test("admin can sign in and open Endpoint Requests", async ({ page }) => {
  await openEndpointRequests(page);
  await expect(page).toHaveURL(/\/endpoint-requests$/);
  await expect(page.getByText("Review users' requests")).toBeVisible();
  await expect(pendingCount(page)).toHaveText("0");
});

test("pending count updates and request details display after a new request", async ({ page, request }) => {
  await openEndpointRequests(page);
  await expect(pendingCount(page)).toHaveText("0");

  const req = await createRequest(request, { requested_scope: ["authentication", "process_activity"] });
  await page.reload();
  await expect(pendingCount(page)).toHaveText("1");

  const row = rowFor(page, req.department);
  await expect(row).toContainText("E2E Requester");
  await expect(row).toContainText("e2e-user@example.org");
  await expect(row).toContainText("E2E Org");
  await expect(row).toContainText("authentication, process");
  await expect(row).toContainText("PENDING");

  await row.click();
  const d = drawer(page);
  await expect(d.getByText("Request details")).toBeVisible();
  await expect(d.getByText("e2e-user@example.org").first()).toBeVisible();
  await expect(d.getByText(req.department).first()).toBeVisible();
  await expect(d.getByText(`Justification for ${req.department}`)).toBeVisible();
  await expect(d.getByText("Requested monitoring scope")).toBeVisible();
  await expect(d.getByText("process_activity", { exact: true })).toBeVisible();
  // audit history is visible
  await expect(d.getByText("Audit history")).toBeVisible();
  await expect(d.getByText("request.created")).toBeVisible();
});

test("rejecting requires a reason, then records it and the audit entry", async ({ page, request }) => {
  const req = await createRequest(request);
  await openEndpointRequests(page);
  await rowFor(page, req.department).click();

  await drawer(page).getByRole("button", { name: "Reject" }).click();
  const dialog = page.getByRole("dialog");
  const confirm = dialog.getByRole("button", { name: "Reject" });
  await expect(confirm).toBeDisabled(); // no reason yet
  await dialog.getByRole("textbox").fill("  ");
  await expect(confirm).toBeDisabled(); // whitespace is not a reason
  await dialog.getByRole("textbox").fill("Not an authorized machine");
  await expect(confirm).toBeEnabled();
  await confirm.click();

  await expect(page.getByRole("status")).toContainText("Request rejected");
  const d = drawer(page);
  await expect(d.getByText("REJECTED", { exact: true })).toBeVisible();
  await expect(d.getByText("Not an authorized machine").first()).toBeVisible();
  await expect(d.getByText("request.rejected")).toBeVisible();
  await expect(d.getByRole("button", { name: "Approve" })).toHaveCount(0); // decided requests cannot be re-decided
});

test("approving can narrow the monitoring scope and is audited", async ({ page, request }) => {
  const req = await createRequest(request, { requested_scope: ["authentication", "file_activity"] });
  await openEndpointRequests(page);
  await rowFor(page, req.department).click();

  await drawer(page).getByRole("button", { name: "Approve" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("file_activity").uncheck();
  await dialog.getByRole("button", { name: "Approve" }).click();

  await expect(page.getByRole("status")).toContainText("Request approved");
  const d = drawer(page);
  await expect(d.getByText("APPROVED", { exact: true })).toBeVisible();
  await expect(d.getByText("Approved scope")).toBeVisible();
  await expect(d.getByText("request.approved")).toBeVisible();
  await expect(d.getByRole("button", { name: "Revoke" })).toBeVisible();

  // revoke the approved request
  await d.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("status")).toContainText("revoked");
  await expect(d.getByText("REVOKED", { exact: true })).toBeVisible();
  await expect(d.getByText("request.revoked")).toBeVisible();
});

test("status filter shows history of decided requests", async ({ page }) => {
  await openEndpointRequests(page);
  await page.getByLabel("Status").selectOption("REJECTED");
  await expect(page.getByRole("row").filter({ hasText: "REJECTED" }).first()).toBeVisible();
  await page.getByLabel("Status").selectOption("PENDING");
  await expect(page.getByRole("row").filter({ hasText: "REJECTED" })).toHaveCount(0);
});

test("a normal user cannot reach administrator pages and lands in the user portal", async ({ page }) => {
  const adminCalls = [];
  page.on("request", (r) => {
    const u = r.url();
    // only calls to the BACKEND count (Vite also serves a static src/api/endpoints.js module)
    if (u.startsWith(stack().backend) && (u.includes("/api/admin/") || u.includes("/api/events") || u.includes("/api/endpoints"))) adminCalls.push(u);
  });
  await signIn(page, "user");
  await expect(page.getByRole("heading", { name: "My endpoint requests" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Endpoint Requests" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Events" })).toHaveCount(0);

  await page.goto("/endpoint-requests"); // typing the admin URL directly
  await expect(page).toHaveURL(/\/portal$/);
  await expect(page.getByRole("heading", { name: "Endpoint Requests", level: 2, exact: true })).toHaveCount(0); // the admin page
  expect(adminCalls).toEqual([]); // the UI never even asked for admin data

  await page.getByRole("button", { name: /Sign out/ }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

test("sign-in failures show a clear message, not a blank page", async ({ page }) => {
  const s = stack();
  await page.goto("/");
  await page.getByLabel("Username").fill(s.admin.username);
  await page.getByLabel("Password").fill("definitely-wrong-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("Invalid username or password.");

  await page.route(/\/api\/auth\/login$/, (route) => route.abort());
  await page.getByLabel("Password").fill("whatever-password-1");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Cannot reach the UBADS backend");
});

test("API failures on the requests list show an understandable error and can be retried", async ({ page }) => {
  await signIn(page, "admin");
  const listUrl = /\/api\/admin\/endpoint-requests(\?.*)?$/;
  await page.route(listUrl, (route) => route.fulfill({ status: 500, contentType: "application/json", body: '{"detail":"Internal server error."}' }));
  await page.getByRole("link", { name: "Endpoint Requests" }).click();
  await expect(page.getByText("Backend is currently unavailable")).toBeVisible();

  await page.unroute(listUrl);
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("heading", { name: "Endpoint Requests", level: 2 })).toBeVisible();
  await expect(page.getByText("Backend is currently unavailable")).toHaveCount(0);
});

test("network loss shows an error, and failures in the detail drawer and actions are reported", async ({ page, request }) => {
  const req = await createRequest(request);
  await openEndpointRequests(page);

  // detail load fails
  const detailUrl = /\/api\/admin\/endpoint-requests\/[^/?]+$/;
  await page.route(detailUrl, (route) => route.fulfill({ status: 500, contentType: "application/json", body: '{"detail":"Simulated server failure"}' }));
  await rowFor(page, req.department).click();
  await expect(drawer(page).getByRole("alert")).toHaveText("Simulated server failure");
  await page.unroute(detailUrl);
  await page.keyboard.press("Escape");

  // an action fails (e.g. someone else decided it first) - the dialog stays open with the reason
  await rowFor(page, req.department).click();
  await drawer(page).getByRole("button", { name: "Reject" }).click();
  const rejectUrl = /\/reject$/;
  await page.route(rejectUrl, (route) => route.fulfill({ status: 409, contentType: "application/json", body: '{"detail":"Cannot reject a request that is APPROVED."}' }));
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox").fill("Reason text here");
  await dialog.getByRole("button", { name: "Reject" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("Cannot reject a request that is APPROVED.");
  await expect(dialog).toBeVisible();
  await page.unroute(rejectUrl);

  // total network loss on the list
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page.keyboard.press("Escape");
  await page.route(/\/api\/admin\/endpoint-requests(\?.*)?$/, (route) => route.abort());
  await page.getByLabel("Status").selectOption("REJECTED"); // triggers a fresh list request
  await expect(page.getByText("Backend is currently unavailable")).toBeVisible();
});

test("an expired or revoked session returns the user to sign-in instead of a blank page", async ({ page, request }) => {
  await openEndpointRequests(page);
  const s = stack();
  const token = await page.evaluate(() => window.sessionStorage.getItem("ubads.dashboardToken"));
  expect(token).toBeTruthy();
  const out = await request.post(`${s.backend}/api/auth/logout`, { headers: { Authorization: `Bearer ${token}` } }); // revoke server-side
  expect(out.ok()).toBeTruthy();
  // The next API call gets a 401 and the app signs out. Depending on timing the sign-in
  // screen may replace the page while this action is still in flight, which is the
  // behaviour under test, so a detached element here is fine.
  await page.getByLabel("Status").selectOption("APPROVED", { timeout: 3000 }).catch(() => {});
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

test("if the account profile cannot be loaded after a reload, an error with Retry is shown (not a blank page)", async ({ page }) => {
  await openEndpointRequests(page);
  const meUrl = /\/api\/auth\/me$/;
  await page.route(meUrl, (route) => route.abort());
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("Cannot reach the UBADS backend");
  await page.unroute(meUrl);
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("heading", { name: "Endpoint Requests", level: 2 })).toBeVisible();
});
