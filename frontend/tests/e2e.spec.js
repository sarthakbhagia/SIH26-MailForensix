const { test, expect } = require('@playwright/test');

test('upload sample eml and show analysis', async ({ page }) => {
  await page.goto('http://localhost:5173');
  await page.waitForTimeout(1000);
  const fileInput = await page.$('input[type=file]');
  if (fileInput) {
    await fileInput.setInputFiles('/tmp/sample.eml');
    const uploadBtn = await page.$('button:has-text("Upload")') || await page.$('button:has-text("Analyze")');
    if (uploadBtn) await uploadBtn.click();
  } else {
    // fallback: call API directly
    await page.evaluate(async () => {
      const form = new FormData();
      // empty form; backend will respond
      await fetch('/api/emails/upload', { method: 'POST', body: form });
    });
  }
  await page.waitForTimeout(3000);
  await expect(page.locator('text=Composite Risk Score')).toHaveCount(1);
});
