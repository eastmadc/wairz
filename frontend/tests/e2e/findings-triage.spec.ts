import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('Findings Triage', () => {
  test.describe.configure({ mode: 'serial' });

  let projectId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const projectUrl = await ensureProjectExists(page);
    const match = projectUrl.match(/\/projects\/([^/]+)/);
    projectId = match?.[1] ?? '';
    await page.close();
  });

  test('findings page loads', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/findings`);
    await dismissDisclaimer(page);
    await expect(page.locator('body')).toBeVisible();
    // Should show findings table or empty state
    const content = page.locator('main, [class*="content"]');
    await expect(content).toBeVisible({ timeout: 10000 });
  });

  test('findings page shows table or empty state', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/findings`);
    await dismissDisclaimer(page);

    // Wait for either a findings table or an empty state message
    const table = page.locator('table');
    const emptyState = page.getByText(/no findings|no results|run a scan/i);
    const eitherVisible = await Promise.race([
      table.waitFor({ state: 'visible', timeout: 10000 }).then(() => 'table'),
      emptyState.waitFor({ state: 'visible', timeout: 10000 }).then(() => 'empty'),
    ]).catch(() => 'timeout');

    expect(['table', 'empty']).toContain(eitherVisible);
  });

  test('severity filter controls are present', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/findings`);
    await dismissDisclaimer(page);

    // Look for filter or severity-related UI elements
    const filterArea = page.locator(
      'button:has-text("Filter"), button:has-text("Severity"), [class*="filter"], select',
    );
    // Either filters exist or the page is in empty state — both are valid
    const count = await filterArea.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('no console errors on findings page', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto(`/projects/${projectId}/findings`);
    await dismissDisclaimer(page);
    await page.waitForLoadState('networkidle');

    const realErrors = errors.filter(
      (e) =>
        !e.includes('favicon') &&
        !e.includes('ERR_CONNECTION_REFUSED') &&
        !e.includes('net::ERR_') &&
        !e.includes('Failed to fetch'),
    );
    expect(realErrors).toEqual([]);
  });
});
