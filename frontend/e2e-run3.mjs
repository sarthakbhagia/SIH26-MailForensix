import playwright from 'playwright';
import fs from 'fs';
(async ()=>{
  const port=8081;
  const browser = await playwright.chromium.launch({headless: true});
  const page = await browser.newPage();
  const url = `http://localhost:${port}`;
  console.log('Visiting',url);
  await page.goto(url,{waitUntil:'load'});
  await page.waitForTimeout(1000);
  const fileInput = await page.$('input[type=file]');
  if (fileInput) {
    console.log('Found file input, setting file');
    await fileInput.setInputFiles('/tmp/sample.eml');
    const uploadBtn = await page.$('button:has-text("Upload")') || await page.$('button:has-text("Analyze")');
    if (uploadBtn) {
      await uploadBtn.click();
      console.log('Clicked upload button');
    } else {
      console.log('Upload button not found; relying on change event');
    }
  } else {
    console.log('No file input in UI; calling API directly from browser context');
    const res = await page.evaluate(async ()=>{
      const form = new FormData();
      return fetch('/api/emails/upload',{method:'POST',body:form}).then(r=>r.status);
    });
    console.log('API upload status (from browser):',res);
  }
  // wait and check page text
  for (let i=0;i<10;i++){
    const count = await page.locator('text=Composite Risk Score').count();
    console.log('Composite Risk Score count',count);
    if (count>0) break;
    await page.waitForTimeout(1000);
  }
  await browser.close();
})();
