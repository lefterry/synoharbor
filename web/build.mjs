import {build} from 'esbuild';
import {mkdir,copyFile,readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
await mkdir('dist',{recursive:true});
await build({entryPoints:['src/main.tsx'],bundle:true,minify:true,sourcemap:false,outdir:'dist',entryNames:'app',target:'es2022'});
const digest=createHash('sha256').update(await readFile('dist/app.js')).update(await readFile('dist/app.css')).digest('hex').slice(0,12);
await writeFile('dist/index.html',(await readFile('index.html','utf8')).replace('./app.js','./app.js?v='+digest).replace('./app.css','./app.css?v='+digest));
await copyFile('logo.svg','dist/logo.svg');
