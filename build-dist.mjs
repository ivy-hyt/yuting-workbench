import fs from 'fs';

const html = fs.readFileSync('app/index.html', 'utf8');
const css = fs.readFileSync('app/css/style.css', 'utf8');
const data = fs.readFileSync('app/js/data.js', 'utf8');
const app = fs.readFileSync('app/js/app.js', 'utf8');

let out = html
  .replace('<link rel="stylesheet" href="css/style.css">', `<style>\n${css}\n</style>`)
  .replace('<script src="js/data.js"></script>', `<script>\n${data}\n</script>`)
  .replace('<script src="js/app.js"></script>', `<script>\n${app}\n</script>`);

fs.writeFileSync('dist/index.html', out);
console.log('✅ dist/index.html 已重新合并（含 HealthKit 分支）');
