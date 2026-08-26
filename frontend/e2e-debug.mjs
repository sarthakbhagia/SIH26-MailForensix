import playwright from 'playwright';
(async ()=>{
  const port=8081;
  const browser = await playwright.chromium.launch({headless: true});
  const page = await browser.newPage();
  const url = `http://localhost:${port}`;
  await page.goto(url,{waitUntil:'load'});
  await page.waitForTimeout(1000);
  const fileInput = await page.$('input[type=file]');
  if (fileInput) {
    await fileInput.setInputFiles('/tmp/sample.eml');
    const uploadBtn = await page.$('button:has-text("Upload")') || await page.$('button:has-text("Analyze")');
    if (uploadBtn) await uploadBtn.click();
  } else {
    await page.evaluate(async ()=>{ const form = new FormData(); await fetch('/api/emails/upload',{method:'POST',body:form}); });
  }
  await page.waitForTimeout(2000);
  const content = await page.content();
  console.log('---PAGE START---');
  console.log(content.slice(0,2000));
  console.log('---PAGE END---');
  await browser.close();
})();
