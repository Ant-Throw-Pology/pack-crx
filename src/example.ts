import pack, { generateUpdateXML } from ".";
import { serve, type ServeOptions } from "bun";
import { constants, writeFile } from "node:fs/promises";

const {
    crx,
    id: crxId,
    manifest,
    rsa
} = await pack({
    contents: "./extension", // path to extension root
    privateKey: "./key.pem", // path to key (if it doesn't exist, that's fine)
    crx: null,
    id: null
});

// Write the CRX
await writeFile("./extension.crx", crx);

// Write the private key unless it already exists
try {
await writeFile("./key.pem", rsa.exportKey("pkcs8-private-pem"), {flag: constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY});
} catch (e) {}

let updateXML: string;

// Serve the extension (optional)
const server = serve({
    fetch(request, server) {
        const url = new URL(request.url);
        if (url.pathname.startsWith("/updates.xml")) {
            updateXML ??= generateUpdateXML(crxId, server.url.toString() + "extension.crx", manifest.version);
            return new Response(updateXML, {headers: {"Content-Type": "application/xml"}});
        } else if (url.pathname.startsWith("/extension.crx")) {
            return new Response(crx, {headers: {"Content-Type": "application/x-chrome-extension"}});
        }
        return new Response(undefined, {status: 404, statusText: "Not Found"});
    },
    port: 3000,
    hostname: "localhost"
} as ServeOptions);

console.log(`Server opened at ${server.url}`);