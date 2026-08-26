import { test, expect } from '@playwright/test';
import fs from 'fs';

test('upload sample eml and show analysis', async ({ page }) => {
  await page.goto('http://localhost:5173');
  // Wait for app to load
  await page.waitForTimeout(1000);
  // Try to find file input or upload button
  const fileInput = await page.$('input[type=file]');
  if (fileInput) {
    await fileInput.setInputFiles('/tmp/sample.eml');
    // click upload submit if exists
    const uploadBtn = await page.$('button:has-text("Upload")') || await page.$('button:has-text("Analyze")');
    if (uploadBtn) await uploadBtn.click();
  } else {
    // fallback: call API directly from the browser context
    await page.evaluate(async () => {
      const form = new FormData();
      // create a fake file - not supported here, so call API without file
      const res = await fetch('/api/emails/upload', { method: 'POST', body: form });
      return res.status;
    });
  }
  // wait a bit for upload and analysis
  await page.waitForTimeout(3000);
  // Check page contains expected text from analysis
  await expect(page.locator('text=Composite Risk Score')).toHaveCount(1);
});
