import playwright from 'playwright';
import fs from 'fs';
(async ()=>{
  const browser = await playwright.chromium.launch({headless: true});
  const page = await browser.newPage();
  await page.goto('http://localhost:5173');
  await page.waitForTimeout(1000);
  const fileInput = await page.$('input[type=file]');
  if (fileInput) {
    await fileInput.setInputFiles('/tmp/sample.eml');
    const uploadBtn = await page.$('button:has-text("Upload")') || await page.$('button:has-text("Analyze")');
    if (uploadBtn) {
      await uploadBtn.click();
      console.log('Clicked upload button');
    } else {
      console.log('Upload button not found; relying on change event');
    }
  } else {
    console.log('No file input in UI; skipping file upload via UI. Calling API directly.');
    const res = await page.evaluate(async ()=>{
      const form = new FormData();
      return fetch('/api/emails/upload',{method:'POST',body:form}).then(r=>r.status);
    });
    console.log('API upload status (from browser):',res);
  }
  // wait and check page text
  await page.waitForTimeout(3000);
  const hasText = await page.locator('text=Composite Risk Score').count();
  console.log('Composite Risk Score occurrences on page:', hasText);
  await browser.close();
})();
