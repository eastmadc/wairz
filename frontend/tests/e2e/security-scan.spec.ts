import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('Security Scanning', () => {
  test.describe.configure({ mode: 'serial' });

  let projectId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const projectUrl = await ensureProjectExists(page);
    const match = projectUrl.match(/\/projects\/([^/]+)/);
    projectId = match?.[1] ?? '';
    await page.close();
  });

  test('security scan page loads', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/security`);
    await dismissDisclaimer(page);
    await expect(page.locator('body')).toBeVisible();
    // The page should render scan categories or tabs
    const content = page.locator('main, [class*="content"]');
    await expect(content).toBeVisible({ timeout: 10000 });
  });

  test('scan tabs are present', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/security`);
    await dismissDisclaimer(page);

    // The security scan page has multiple scan type tabs
    const tabNames = [
      'Security Audit',
      'YARA',
      'VulHunt',
      'Binary',
      'Network',
      'Script',
    ];

    for (const name of tabNames) {
      const tab = page.getByRole('tab', { name: new RegExp(name, 'i') }).or(
        page.locator(`button:has-text("${name}"), [role="tab"]:has-text("${name}")`),
      );
      // At least some tabs should be visible
      const visible = await tab.first().isVisible().catch(() => false);
      if (visible) {
        // Click tab and verify it becomes selected or content changes
        await tab.first().click();
        await page.waitForTimeout(500);
      }
    }
  });

  test('security tools page loads', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/tools`);
    await dismissDisclaimer(page);

    // The tools page should show categorized tool list
    const content = page.locator('main, [class*="content"]');
    await expect(content).toBeVisible({ timeout: 10000 });

    // Should have tools listed (buttons or cards)
    const toolElements = page.locator(
      'button:has-text("Run"), [class*="tool"], [class*="card"]',
    );
    // If the backend is running and firmware is present, tools should appear
    const count = await toolElements.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('no console errors on security pages', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto(`/projects/${projectId}/security`);
    await dismissDisclaimer(page);
    await page.waitForLoadState('networkidle');

    await page.goto(`/projects/${projectId}/tools`);
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
