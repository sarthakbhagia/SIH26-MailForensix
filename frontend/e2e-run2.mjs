import playwright from 'playwright';
const ports=[5173,8081,8082,8083,3000,5174];
for (const port of ports){
  try{
    const browser = await playwright.chromium.launch({headless:true});
    const page = await browser.newPage();
    const url=`http://localhost:${port}`;
    console.log('Trying',url);
    await page.goto(url,{timeout:3000,waitUntil:'load'});
    console.log('Connected to',url);
    // simple check
    const body = await page.content();
    console.log('Page length',body.length);
    await browser.close();
    process.exit(0);
  }catch(e){
    console.log('Failed',port,e.message);
  }
}
console.log('All ports failed');
process.exit(1);
