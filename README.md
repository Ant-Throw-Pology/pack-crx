# pack-crx

A(nother) Chrome Extension packager in ESM and TypeScript.

Use of the file system is opt-in, so you can use only `Uint8Array`s if you want/need to.

Fun fact: If you create two extensions from the same private key, they will have the same ID. **Do not do this. Chrome will (probably) treat them as the same extension - one as an update to another.**

## Example

```ts
import pack, { generateUpdateXML } from "pack-crx";
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
```

## API

**IMPORTANT:** All keys passed to this package should be in **pkcs8-der** format. This is also the format in which they will be returned.

### pack

The easiest way to use this package is through the default export, `pack`.

`pack` takes an object of input parameters, **all of which are optional:**

<!-- It is highly recommended to turn off line wrapping while editing this table -->

| Name               | Type (also can be `undefined`)   | Description                                                                                           | Auto-generation notes                                                                                            |
|--------------------|----------------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `contents`         | `Uint8Array` or `string`         | The ZIP archive of the contents of the extension, or a path to the folder containing the extension.   | Cannot be auto-generated                                                                                         |
| `privateKey`       | `Uint8Array`, `string` or `null` | The private key for the extension, or a path to it.                                                   | If loading from a string, the contents should be in pkcs8-pem if the path ends in `.pem`.                        |
| `keySize`          | `number`                         | The size of key to generate, if needed.                                                               | No dependencies, defaults to 4096                                                                                |
| `publicKey`        | `Uint8Array`, `string` or `null` | The public key for the extension, or a path to it.                                                    | Requires `privateKey`. If loading from a string, the contents should be in pkcs8-pem if the path ends in `.pem`. |
| `rsa`              | `NodeRSA`                        | The instance of NodeRSA to use.                                                                       | Automatically created along with `privateKey`.                                                                   |
| `id`               | `string` or `null`               | The extension's ID.                                                                                   | Requires `publicKey`.                                                                                            |
| `crx`              | `Uint8Array` or `null`           | The outputted CRX file.                                                                               | Requires `contents`, `privateKey`, and `publicKey`.                                                              |
| `crxVersion`       | `number`                         | The CRX format version to use. Defaults to 3.                                                         | Defaults to 3.                                                                                                   |
| `crxUrl`           | `string`                         | The URL to where the CRX file (not the updates XML) will be hosted.                                   | Cannot be auto-generated.                                                                                        |
| `updateXML`        | `string` or `null`               | The [updates XML file](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux). | Requires `id`, `extVersion`, and `minChromeVersion`.                                                             |
| `extVersion`       | `string` or `null`               | The extension's version.                                                                              | Requires `manifest`.                                                                                             |
| `minChromeVersion` | `string` or `null`               | The minimum Chrome version the extension requires.                                                    | Requires `manifest`. (but can also be derived from `crxVersion`)                                                 |
| `manifest`         | `ChromeManifest` or `null`       | The extension's [manifest](https://developer.chrome.com/docs/extensions/reference/manifest).          | Requires `contents` to be a path string.                                                                         |

If `null` is given for a property, then the function will generate a value for it based on the other properties.

If a property requires another but that property is not requested (with `null`), then it is generated and given anyways.

If `privateKey` or `publicKey` are strings, `pack` will load the file at each path as a key. If the extension is `.pem`, they are loaded as pkcs8-pem and converted to pkcs8-der.

`pack` always returns a `Promise`, even if all of the operations inside are synchronous.

However, the return result is the same object as the input - just with the properties modified - so if you *really* want synchronous operations, you can keep a reference to the input object, call the function, and access the synchronous results from that object. Just make sure you don't set `privateKey` or `manifest` to `null` or `contents` to a string, otherwise some of your values might not arrive synchronously.

### packCrx3

```ts
function packCrx3(privateKey: Uint8Array, publicKey: Uint8Array, contents: Uint8Array): Uint8Array
```

Pack a CRX3 extension.

(param) `privateKey` (`Uint8Array`) - The extension's private key. \
(param) `publicKey` (`Uint8Array`) - The extension's public key. \
(param) `contents` (`Uint8Array`) - The zipped contents of the extension. This should contain a `manifest.json` file directly inside it, but we don't validate that in this function.

(returns) `Uint8Array` - The contents of the packaged extension.

### packCrx2 (deprecated)

```ts
function packCrx2(privateKey: Uint8Array, publicKey: Uint8Array, contents: Uint8Array): Uint8Array
```

Pack a CRX2 extension. Chrome stopped supporting these entirely in version 73.0.3683, which released in October of 2017.

(param) `privateKey` (`Uint8Array`) - The extension's private key. \
(param) `publicKey` (`Uint8Array`) - The extension's public key. \
(param) `contents` (`Uint8Array`) - The zipped contents of the extension. This should contain a `manifest.json` file directly inside it, but we don't validate that in this function.

(returns) `Uint8Array` - The contents of the packaged extension.

### generateCrxId

```ts
function generateCrxId(publicKey: Uint8Array): string
```

Generate an extension's ID (24 characters, a-p) from its public key.

(param) `publicKey` (`Uint8Array`) - The public key of the extension.

(returns) `string` - The generated extension ID.

### packContents

```ts
function packContents(where: string): Promise<{contents: Uint8Array, manifest: ChromeManifest}>
```

Load a directory from the filesystem into a ZIP archive, using the node:fs API.

(param) `where` (`string`) - The path to the directory.

(returns) `object` 
* `contents` (`Uint8Array`) - The ZIP-encoded data.
* `manifest` (`ChromeManifest`) - The manifest for the extension, parsed as JSON.

### generateUpdateXML

```ts
function generateUpdateXML(crxId: string, url: string, version: string, minChromeVersion?: string): string
```

Generate the updates XML file for [serving an extension yourself](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux).

(param) `crxId` (`string`) - The extension's ID. \
(param) `url` (`string`) - The URL where the extension's CRX file will be hosted. \
(param) `version` (`string`) - The extension's version. \
(param) `minChromeVersion` (`string`, optional) - The minimum Chrome version that the extension can be installed on.

(returns) `string` - The updates XML text

### unpack

```ts
function unpack(crx: Uint8Array): Uint8Array
```

Unpack a CRX file and extract its contents as ZIP data.

(param) `crx` (`Uint8Array`) - The CRX to be unpacked.

(returns) `object`
- `archive` (`Uint8Array`) - The ZIP data.
- `crxVersion` (`3`) - The CRX format version.
- `header` (`CrxFileHeader`) - The header for the CRX file, for signatures and things.
OR
- `archive` (`Uint8Array`) - The ZIP data.
- `crxVersion` (`2`) - The CRX format version.
- `key` (`Uint8Array`) - The extension's public key.
- `sign` (`Uint8Array`) - The signature over the contents of the extension.

### Key utilities

The following functions are self-explanatory:

```ts
function generatePrivateKey(bits?: number): Uint8Array
function generatePublicKey(privateKey: Uint8Array): Uint8Array
function convertToPem(key: Uint8Array, type: "private" | "public"): string
function convertFromPem(key: string, type: "private" | "public"): Uint8Array
```

However, they all create new NodeRSA instances which are immediately discarded, so it is recommended to make your own RSA instance (or use the one from `pack`) and its methods to export/import keys.