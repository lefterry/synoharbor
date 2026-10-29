import {build} from 'esbuild';
import {mkdir,copyFile} from 'node:fs/promises';
await mkdir('dist',{recursive:true});
await build({entryPoints:['src/main.tsx'],bundle:true,minify:true,sourcemap:false,outdir:'dist',entryNames:'app',target:'es2022'});
await copyFile('index.html','dist/index.html');
await copyFile('logo.svg','dist/logo.svg');
