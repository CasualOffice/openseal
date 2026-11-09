// SPK-02: run the wasm32 verifier (RustCrypto only) over the sealed PDFs in Node.
//   node run_wasm.mjs <verifier.wasm> out/*.pdf
// Prints the spk02_verify code per file: 0 = valid, else spk02-verify's VerifyError code.
import { readFileSync } from "node:fs";

const [wasmPath, ...pdfs] = process.argv.slice(2);
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const { memory, spk02_alloc, spk02_verify } = instance.exports;
const imports = WebAssembly.Module.imports(new WebAssembly.Module(readFileSync(wasmPath)));
console.log(`${wasmPath}: ${readFileSync(wasmPath).length} bytes, imports: ${JSON.stringify(imports)}`);
for (const p of pdfs) {
  const bytes = readFileSync(p);
  const ptr = spk02_alloc(bytes.length);
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  const t = performance.now();
  const code = spk02_verify(ptr, bytes.length);
  console.log(`${p}: ${code === 0 ? "valid" : "INVALID code " + code} (${(performance.now() - t).toFixed(1)} ms)`);
}
