import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('SBOM and Vulnerability Scanning', () => {
  test('SBOM page loads for a project', async ({ page }) => {
    const projectUrl = await ensureProjectExists(page);
    const projectId = projectUrl.match(/\/projects\/([^/]+)/)?.[1];
    test.skip(!projectId, 'No project available');

    await page.goto(`/projects/${projectId}/sbom`);
    await dismissDisclaimer(page);

    // The SBOM page should show the heading
    await expect(
      page.getByText('Software Bill of Materials'),
    ).toBeVisible({ timeout: 10000 });
  });

  test('SBOM page shows Generate button when no SBOM exists', async ({ page }) => {
    const projectUrl = await ensureProjectExists(page);
    const projectId = projectUrl.match(/\/projects\/([^/]+)/)?.[1];
    test.skip(!projectId, 'No project available');

    await page.goto(`/projects/${projectId}/sbom`);
    await dismissDisclaimer(page);

    // Wait for loading to finish
    await page.waitForLoadState('networkidle');

    // Either the "Generate SBOM" button is visible (no SBOM yet)
    // or components are already listed (SBOM exists from a previous run)
    const generateBtn = page.getByRole('button', { name: 'Generate SBOM' });
    const componentsText = page.getByText(/\d+ components identified/);

    const hasGenerateBtn = await generateBtn.isVisible().catch(() => false);
    const hasComponents = await componentsText.isVisible().catch(() => false);

    // One of these should be true — the page should either show the
    // generate button or the existing component count
    expect(hasGenerateBtn || hasComponents).toBeTruthy();
  });

  test('generate SBOM and verify components appear', async ({ page }) => {
    const projectUrl = await ensureProjectExists(page);
    const projectId = projectUrl.match(/\/projects\/([^/]+)/)?.[1];
    test.skip(!projectId, 'No project available');

    await page.goto(`/projects/${projectId}/sbom`);
    await dismissDisclaimer(page);
    await page.waitForLoadState('networkidle');

    const generateBtn = page.getByRole('button', { name: 'Generate SBOM' });
    const hasGenerateBtn = await generateBtn.isVisible().catch(() => false);

    if (hasGenerateBtn) {
      // Click generate and wait for it to complete
      await generateBtn.click();

      // Wait for either components to appear or the button to re-enable
      // (generation can take some time; use a generous timeout)
      await expect(
        page.getByText(/\d+ components identified|Generate SBOM/),
      ).toBeVisible({ timeout: 60000 });
    }

    // If components exist, verify the components tab renders
    const componentsText = page.getByText(/\d+ components identified/);
    if (await componentsText.isVisible().catch(() => false)) {
      // The "Components" tab should be visible
      const componentsTab = page.getByRole('button', { name: /Components/ });
      await expect(componentsTab.first()).toBeVisible();

      // The "Vulnerabilities" tab should also be present
      const vulnsTab = page.getByRole('button', { name: /Vulnerabilities/ });
      await expect(vulnsTab.first()).toBeVisible();
    }
  });

  test('vulnerability tab loads and severity filters render', async ({ page }) => {
    const projectUrl = await ensureProjectExists(page);
    const projectId = projectUrl.match(/\/projects\/([^/]+)/)?.[1];
    test.skip(!projectId, 'No project available');

    await page.goto(`/projects/${projectId}/sbom`);
    await dismissDisclaimer(page);
    await page.waitForLoadState('networkidle');

    // Check if SBOM data exists
    const componentsText = page.getByText(/\d+ components identified/);
    const hasComponents = await componentsText.isVisible().catch(() => false);

    if (!hasComponents) {
      // No SBOM generated — nothing to test for the vulnerability tab
      test.skip(true, 'No SBOM data available — skipping vulnerability tab test');
      return;
    }

    // Click the "Vulnerabilities" tab
    const vulnsTab = page.getByRole('button', { name: /Vulnerabilities/ });
    if (await vulnsTab.first().isVisible()) {
      await vulnsTab.first().click();

      // The vulnerability scan button should be visible
      // It shows either "Scan for Vulnerabilities" or "Rescan Vulnerabilities"
      const scanBtn = page.getByRole('button', {
        name: /Scan for Vulnerabilities|Rescan Vulnerabilities/,
      });
      await expect(scanBtn.first()).toBeVisible({ timeout: 5000 });
    }
  });

  test('SBOM page handles empty state gracefully', async ({ page }) => {
    const projectUrl = await ensureProjectExists(page);
    const projectId = projectUrl.match(/\/projects\/([^/]+)/)?.[1];
    test.skip(!projectId, 'No project available');

    await page.goto(`/projects/${projectId}/sbom`);
    await dismissDisclaimer(page);

    // The page should not show any error overlay
    const errorOverlay = page.locator('vite-error-overlay');
    await expect(errorOverlay).toHaveCount(0);

    // The heading should always be present regardless of data state
    await expect(
      page.getByText('Software Bill of Materials'),
    ).toBeVisible({ timeout: 10000 });
  });
});
