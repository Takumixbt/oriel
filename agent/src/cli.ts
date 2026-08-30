import { pathToFileURL } from "node:url";
import { runDemo } from "./demo.js";

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command !== "demo") {
    throw new Error("usage: npm run demo");
  }
  console.log(JSON.stringify(await runDemo(), null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
