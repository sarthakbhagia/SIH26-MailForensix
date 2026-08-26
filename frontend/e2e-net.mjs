import playwright from 'playwright';
(async ()=>{
  const port=8081;
  const browser = await playwright.chromium.launch({headless: true});
  const page = await browser.newPage();
  page.on('requestfinished', async req=>{
    try{
      const url=req.url();
      if (url.includes('/api/')){
        const resp=await req.response();
        const status=resp.status();
        const text=await resp.text();
        console.log('REQFIN',url,status,text.slice(0,500));
      }
    }catch(e){console.log('reqfin err',e.message)}
  });
  await page.goto(`http://localhost:${port}`);
  await page.waitForTimeout(1000);
  const fileInput = await page.$('input[type=file]');
  if (fileInput) {
    await fileInput.setInputFiles('/tmp/sample.eml');
    const uploadBtn = await page.$('button:has-text("Upload")') || await page.$('button:has-text("Analyze")');
    if (uploadBtn) await uploadBtn.click();
  } else {
    await page.evaluate(async ()=>{ const form = new FormData(); await fetch('/api/emails/upload',{method:'POST',body:form}); });
  }
  await page.waitForTimeout(5000);
  await browser.close();
})();
