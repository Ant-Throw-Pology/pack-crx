import { createHash } from "node:crypto";
import Pbf from "pbf";
import * as crx3 from "./crx3.pb";
import JSZip from "jszip";
import fs from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { Buffer } from "node:buffer";
import RSA from "node-rsa";

interface ChromeBaseManifest {
    // Required keys
    manifest_version: number;
    name: string;
    version: string;
    
    // Required by Chrome Web Store
    description?: string;
    icons?: {[x: `${number}`]: string};
    
    // Optional
    author?: string;
    background?: {
        service_worker?: string;
        type?: "module";
    };
    chrome_settings_overrides?: {
        alternate_urls?: string[];
        encoding?: string;
        favicon_url?: string;
        homepage?: string;
        image_url?: string;
        image_url_post_params?: string;
        is_default?: boolean;
        keyword?: string;
        name?: string;
        prepopulated_id?: number;
        search_provider?: object;
        search_url?: string;
        search_url_post_params?: string;
        startup_pages?: string[];
        suggest_url?: string;
        suggest_url_post_params?: string;
    };
    chrome_url_overrides?: {
        bookmarks?: string;
        history?: string;
        newtab?: string;
    };
    commands?: {
        [x: string]: {
            description: string;
            suggested_key?: string;
        }
    };
    content_scripts?: {
        matches: string[];
        css?: string[];
        js?: string[];
        run_at?: "document_start" | "document_end" | "document_idle";
        match_about_blank?: boolean;
        match_origin_as_fallback?: boolean;
        world?: "ISOLATED" | "MAIN";
    }[];
    content_security_policy?: {
        extension_pages?: string;
        sandbox?: string;
    };
    cross_origin_embedder_policy?: string;
    cross_origin_opener_policy?: string;
    declarative_net_request?: {
        rule_resources?: {
            id: string;
            enabled: boolean;
            path: string;
        }[];
    };
    default_locale?: string;
    devtools_page?: string;
    export?: {
        allowlist?: string[];
    };
    externally_connectable?: {
        ids?: string[];
        matches?: string[];
        accepts_tls_channel_id?: boolean;
    };
    homepage_url?: string;
    host_permissions?: string[];
    import?: {
        id: string;
        minimum_version?: string;
    }[];
    incognito?: "spanning" | "split" | "not_allowed";
    key?: string;
    minimum_chrome_version?: string;
    oauth2?: {
        client_id: string;
        scopes: string[];
    };
    omnibox?: {
        keyword?: string;
    };
    optional_host_permissions?: string[];
    optional_permissions?: string[];
    options_page?: string;
    options_ui?: {
        page: string;
        open_in_tab?: boolean;
    };
    permissions?: string[];
    requirements?: {
        [x: string]: {features: string[]};
    };
    sandbox?: {
        pages: string[];
    };
    short_name?: string;
    side_panel?: string;
    storage?: {
        managed_schema?: string;
    };
    tts_engine?: {
        voices?: {
            voice_name: string;
            lang?: string;
            event_types?: ("start" | "word" | "sentence" | "marker" | "end" | "error")[];
        }[];
    };
    update_url?: string;
    version_name?: string;
    web_accessible_resources?: ({
        resources: string[];
    } & ({
        matches: string[];
    } | {
        extension_ids: string[];
    }))[];
    
    // ChromeOS
    file_browser_handlers?: {
        id: string;
        default_title: string;
        file_filters: string[];
    }[];
    file_handlers?: {
        action: string;
        name: string;
        accept: {
            [x: string]: string[];
        };
        launch_type?: "single-client" | "multiple-clients";
    }[];
    file_system_provider_capabilities?: {
        configurable?: boolean;
        multiple_mounts?: boolean;
        watchable?: boolean;
        source: "file" | "device" | "network";
    };
    input_components?: {
        name: string;
        id?: string;
        language?: string | string[];
        layouts?: string | string[];
        input_view?: string;
        options_page?: string;
    }[];
}

export type ChromeMV2Manifest = ChromeBaseManifest & {
    manifest_version: 2;
    browser_action?: {
        default_icon?: {[x: `${number}`]: string};
        default_title?: string;
        default_popup?: string;
    };
    page_action?: {
        default_icon?: {[x: `${number}`]: string};
        default_title?: string;
        default_popup?: string;
    };
};

export type ChromeMV3Manifest = ChromeBaseManifest & {
    manifest_version: 3;
    action?: {
        default_icon?: {[x: `${number}`]: string};
        default_title?: string;
        default_popup?: string;
    };
};

export type ChromeManifest = ChromeMV2Manifest | ChromeMV3Manifest;

export interface CrxFileHeader {
    sha256_with_rsa?: AsymmetricKeyProof[];
    sha256_with_ecdsa?: AsymmetricKeyProof[];
    signed_header_data?: Uint8Array;
}

export interface AsymmetricKeyProof {
    public_key?: Uint8Array;
    signature?: Uint8Array;
}

/**
 * CRX IDs are 16 bytes long
 * @constant
 */
const CRX_ID_SIZE = 16;

/**
 * CRX3 uses 32bit numbers in various places,
 * so let's prepare size constant for that.
 * @constant
 */
const SIZE_BYTES = 4;

/**
 * Used for file format.
 * @see {@link https://github.com/chromium/chromium/blob/master/components/crx_file/crx3.proto}
 * @constant
 */
const kSignature = Uint8Array.from("Cr24", ch => ch.charCodeAt(0));

/**
 * Used for file format.
 * @see {@link https://github.com/chromium/chromium/blob/master/components/crx_file/crx3.proto}
 * @constant
 */
const kVersion = Uint8Array.from([3, 0, 0, 0]);

/**
 * Used for generating package signatures.
 * @see {@link https://github.com/chromium/chromium/blob/master/components/crx_file/crx3.proto}
 * @constant
 */
const kSignatureContext = Uint8Array.from("CRX3 SignedData\x00", ch => ch.charCodeAt(0));

/**
 * Pack a CRX2 extension. Chrome stopped supporting these entirely in version 73.0.3683, which released in October of 2017.
 * 
 * @param privateKey The extension's private key.
 * @param publicKey The extension's public key.
 * @param contents The zipped contents of the extension. This should contain a `manifest.json` file directly inside it, but we don't validate that in this function.
 * 
 * @returns The contents of the packaged extension.
 * 
 * @deprecated
 */
export function packCrx2(privateKey: Uint8Array, publicKey: Uint8Array, contents: Uint8Array, rsa?: RSA): Uint8Array {
    rsa ??= new RSA(Buffer.from(privateKey), "pkcs8-private-der");
    rsa.setOptions({signingScheme: "pkcs1-sha1"});
    const signature = rsa.sign(contents);
    const length = 16 /* magic + version + key length + sign length */ + publicKey.length + signature.length;
    const result = new Uint8Array(length);
    result.set(kSignature, 0);
    const dv = new DataView(result.buffer);
    dv.setUint32(4, 2, true);
    dv.setUint32(8, publicKey.length, true);
    dv.setUint32(12, signature.length, true);
    result.set(publicKey, 16);
    result.set(signature, 16 + publicKey.length);
    result.set(contents, length);
    return result;
}

/**
 * Pack a CRX3 extension.
 * 
 * @param privateKey The extension's private key.
 * @param publicKey The extension's public key.
 * @param contents The zipped contents of the extension. This should contain a `manifest.json` file directly inside it, but we don't validate that in this function.
 * 
 * @returns The contents of the packaged extension.
 */
export function packCrx3(privateKey: Uint8Array, publicKey: Uint8Array, contents: Uint8Array, rsa?: RSA): Uint8Array {
    let pb = new Pbf();
    crx3.SignedData.write({
        crx_id: generateBinaryCrxId(publicKey)
    }, pb);
    const signedHeaderData = pb.finish();
    
    const signature = generateCrx3Signature(privateKey, signedHeaderData, contents, rsa);
    
    pb = new Pbf();
    crx3.CrxFileHeader.write({
        sha256_with_rsa: [{
            public_key: publicKey satisfies Uint8Array,
            signature
        }],
        signed_header_data: signedHeaderData
    } as CrxFileHeader, pb);
    const header = pb.finish();
    
    const size =
        kSignature.length + // Magic constant
        kVersion.length + // Version number
        SIZE_BYTES + // Header size
        header.length +
        contents.length;
    
    const result = new Uint8Array(size);
    
    let index = 0;
    result.set(kSignature, index);
    result.set(kVersion, index += kSignature.length);
    new DataView(result.buffer).setUint32(index += kVersion.length, header.length, true);
    result.set(header, index += SIZE_BYTES);
    result.set(contents, index += header.length);
    
    return result;
}

function generateBinaryCrxId(publicKey: Uint8Array): Uint8Array {
    var hash = createHash("sha256");
    hash.update(publicKey);
    return Uint8Array.from(hash.digest()).slice(0, CRX_ID_SIZE);
}

function generateCrx3Signature(privateKey: Uint8Array, signedHeaderData: Uint8Array, contents: Uint8Array, rsa?: RSA): Uint8Array {
    rsa ??= new RSA(Buffer.from(privateKey), "pkcs8-private-der");
    rsa.setOptions({signingScheme: "pkcs1-sha256"});
    
    // Size of signed_header_data
    const sizeOctets = new DataView(new ArrayBuffer(SIZE_BYTES));
    sizeOctets.setUint32(0, signedHeaderData.length, true);
    
    const toSign = Buffer.concat([
        kSignatureContext,
        new Uint8Array(sizeOctets.buffer),
        signedHeaderData,
        contents
    ]);
    
    return Uint8Array.from(rsa.sign(toSign));
}

/**
 * Generate an extension's ID (32 characters, a-p) from its public key.
 * 
 * @param publicKey The public key of the extension.
 * 
 * @returns The generated extension ID.
 */
export function generateCrxId(publicKey: Uint8Array): string {
    return createHash("sha256")
        .update(publicKey)
        .digest()
        .toString("hex")
        .split("")
        .map(x => (parseInt(x, 16) + 0x0a).toString(26))
        .join("")
        .slice(0, 32);
}

/**
 * Load a directory from the filesystem into a ZIP archive, using the node:fs API.
 * 
 * @param where The path to the directory.
 */
export async function packContents(where: string): Promise<{
    /** The ZIP-encoded data. */
    contents: Uint8Array,
    /** The manifest for the extension, parsed as JSON. */
    manifest: ChromeManifest
}> {
    const zip = new JSZip();
    let manifest: Promise<Uint8Array> | undefined;
    async function f(loc: string) {
        for (const entry of await fs.readdir(loc, {withFileTypes: true})) {
            const fp = join(loc, entry.name);
            if (entry.isDirectory()) {
                await f(fp);
            } else {
                const contents = fs.readFile(fp).then(buf => Uint8Array.from(buf));
                const rp = relative(where, fp);
                if (rp == "manifest.json") manifest ??= contents;
                zip.file(rp, contents);
            }
        }
    }
    await f(resolve(process.cwd(), where));
    if (manifest == undefined) throw new Error("Manifest file not found");
    return {
        contents: await zip.generateAsync({
            compression: "DEFLATE",
            type: "uint8array"
        }),
        manifest: JSON.parse(new TextDecoder().decode(await manifest))
    };
}

/**
 * Generate the updates XML file for [serving an extension yourself](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux).
 * 
 * @param crxId The extension's ID.
 * @param url The URL where the extension's CRX file will be hosted.
 * @param version The extension's version.
 * @param minChromeVersion The minimum Chrome version that the extension can be installed on.
 * 
 * @returns The updates XML text
 */
export function generateUpdateXML(crxId: string, url: string, version: string, minChromeVersion?: string): string {
    return `<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='${crxId}'>
    <updatecheck codebase='${url}' version='${version}'${minChromeVersion ? ` prodversionmin='${minChromeVersion}'` : ""} />
  </app>
</gupdate>`;
}

export function generatePrivateKey(bits = 4096): Uint8Array {
    return Uint8Array.from(new RSA({b: bits}).exportKey("pkcs8-private-der"));
}

export function generatePublicKey(privateKey: Uint8Array): Uint8Array {
    return Uint8Array.from(new RSA(Buffer.from(privateKey), "pkcs8-private-der").exportKey("pkcs8-public-der"));
}

export function convertToPem(key: Uint8Array, type: "private" | "public"): string {
    return new RSA(Buffer.from(key), `pkcs8-${type}-der`).exportKey(`pkcs8-${type}-pem`);
}

export function convertFromPem(key: string, type: "private" | "public"): Uint8Array {
    return Uint8Array.from(new RSA(key, `pkcs8-${type}-pem`).exportKey(`pkcs8-${type}-der`));
}

/**
 * Unpack a CRX file and extract its contents as ZIP data.
 * 
 * @param crx The CRX to be unpacked.
 */
export function unpack(crx: Uint8Array): {
    /** The ZIP data. */
    archive: Uint8Array,
    /** The CRX format version. */
    crxVersion: 2,
    /** The extension's public key. */
    key: Uint8Array,
    /** The signature over the contents of the extension. */
    sign: Uint8Array
} | {
    /** The ZIP data. */
    archive: Uint8Array,
    /** The CRX format version. */
    crxVersion: 3,
    /** The header for the CRX file, for signatures and things. */
    header: CrxFileHeader
} {
    const abuf = crx.buffer;
    const dv = new DataView(abuf);
    if (kSignature.every((v, i) => dv.getUint8(i) == v)) {
        const crxVersion = dv.getUint32(4, true);
        if (crxVersion == 2) {
            const keyLength = dv.getUint32(8, true);
            const signLength = dv.getUint32(12, true);
            return {
                archive: crx.slice(16 + keyLength + signLength),
                crxVersion: 2,
                key: crx.slice(16, 16 + keyLength),
                sign: crx.slice(16 + keyLength, 16 + keyLength + signLength)
            };
        } else if (crxVersion == 3) {
            const headerLength = dv.getUint32(8, true);
            const archive = crx.slice(12 + headerLength);
            const header = crx.slice(12, 12 + headerLength);
            const pb = new Pbf(header);
            const decodedHeader = crx3.CrxFileHeader.read(pb);
            return {archive, crxVersion: 3, header: decodedHeader};
        }
    }
    throw new Error("The file given is not a valid CRX file");
}

export interface PackInput {
    /** The ZIP archive of the contents of the extension, or a path to the folder containing the extension. */
    contents?: Uint8Array | string;
    /** The private key for the extension, or a path to it. */
    privateKey?: Uint8Array | string | null;
    /** The size of key to generate, if needed. */
    keySize?: number;
    /** The public key for the extension, or a path to it. */
    publicKey?: Uint8Array | string | null;
    /** The instance of NodeRSA to use. */
    rsa?: RSA;
    /** The extension's ID. */
    id?: string | null;
    /** The outputted CRX file. */
    crx?: Uint8Array | null;
    /** The CRX format version to use. Defaults to 3. */
    crxVersion?: number;
    /** The URL to where the CRX file (not the updates XML) will be hosted. */
    crxUrl?: string;
    /** The [updates XML file](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux). */
    updateXML?: string | null;
    /** The extension's version. */
    extVersion?: string | null;
    /** The minimum Chrome version the extension requires. */
    minChromeVersion?: string | null;
    /** The extension's [manifest](https://developer.chrome.com/docs/extensions/reference/manifest). */
    manifest?: ChromeManifest | null;
}

type SetKeys<A extends object, B extends object> = {[x in keyof A | keyof B]: x extends keyof B ? unknown extends B[x] ? x extends keyof A ? A[x] : never : B[x] : x extends keyof A ? A[x] : never};

export type TransformPack<I extends PackInput> =
    I["privateKey"] extends string ?
        TransformPack<SetKeys<I, {
            privateKey: Uint8Array | undefined;
            rsa: RSA;
        }>>
    : I["publicKey"] extends string ?
        TransformPack<SetKeys<I, {
            publicKey: Uint8Array | undefined;
        }>>
    : I["updateXML"] extends null ?
        undefined extends I["crxUrl"] ? never : TransformPack<SetKeys<I, {
            updateXML: string;
            id: undefined extends I["id"] ? null : I["id"];
            extVersion: undefined extends I["extVersion"] ? null : I["extVersion"];
            minChromeVersion: undefined extends I["minChromeVersion"] ? null : I["minChromeVersion"];
        }>>
    : I["extVersion"] extends null ?
        TransformPack<SetKeys<I, {
            extVersion: string;
            manifest: undefined extends I["manifest"] ? null : I["manifest"];
        }>>
    : I["minChromeVersion"] extends null ?
        TransformPack<SetKeys<I, {
            minChromeVersion: string | undefined;
            manifest: undefined extends I["manifest"] ? null : I["manifest"];
        }>>
    : I["manifest"] extends null ?
        undefined extends I["contents"] ? never
        : Uint8Array extends I["contents"] ? never
        : TransformPack<SetKeys<I, {
            manifest: ChromeManifest;
        }>>
    : I["crx"] extends null ?
        undefined extends I["contents"] ? never : TransformPack<SetKeys<I, {
            crx: Uint8Array;
            privateKey: undefined extends I["privateKey"] ? null : I["privateKey"];
            publicKey: undefined extends I["publicKey"] ? null : I["publicKey"];
        }>>
    : I["id"] extends null ?
        TransformPack<SetKeys<I, {
            id: string;
            publicKey: undefined extends I["publicKey"] ? null : I["publicKey"];
        }>>
    : I["publicKey"] extends null ?
        TransformPack<SetKeys<I, {
            publicKey: Uint8Array;
            privateKey: undefined extends I["privateKey"] ? null : I["privateKey"];
        }>>
    : I["privateKey"] extends null ?
        TransformPack<SetKeys<I, {
            privateKey: Uint8Array;
            rsa: RSA;
        }>>
    : I["contents"] extends string ? 
        TransformPack<SetKeys<I, {
            contents: Uint8Array;
            manifest: ChromeManifest;
        }>>
    : I;

/**
 * Use the entirety of this API in one function.
 * 
 * @param options An object containing input parameters.
 * 
 * If `null` is given for a property, then the function will generate a value for it based on the other properties.
 * 
 * If a property requires another but that property is not requested (with `null`), then it is generated and given anyways.
 * 
 * If `privateKey` or `publicKey` are strings, `pack` will load the file at each path as a key. If the extension is `.pem`, they are loaded as pkcs8-pem and converted to pkcs8-der.
 * 
 * `pack` always returns a `Promise`, even if all of the operations inside are synchronous.
 * 
 * However, the return result is the same object as the input - just with the properties modified - so if you *really* want synchronous operations, you can keep a reference to the input object, call the function, and access the synchronous results from that object. Just make sure you don't set `privateKey` or `manifest` to `null` or `contents` to a string, otherwise some of your values might not arrive synchronously.
 */
export async function pack<I extends PackInput>(options: I): Promise<TransformPack<I>> {
    if (typeof options.privateKey == "string") {
        try {
            const isPem = options.privateKey.endsWith(".pem");
            const contents = await fs.readFile(options.privateKey);
            if (isPem) options.privateKey = Uint8Array.from((options.rsa ??= new RSA(contents, "pkcs8-private-pem")).exportKey("pkcs8-private-der"));
            else options.privateKey = Uint8Array.from(contents);
        } catch (e) {
            if (!`${e}`.includes("ENOENT")) throw e;
            options.privateKey = undefined;
        }
    }
    if (typeof options.publicKey == "string") {
        try {
            const isPem = options.publicKey.endsWith(".pem");
            const contents = await fs.readFile(options.publicKey);
            if (isPem) options.publicKey = Uint8Array.from(new RSA(contents, "pkcs8-public-pem").exportKey("pkcs8-public-der"));
            else options.publicKey = Uint8Array.from(contents);
        } catch (e) {
            if (!`${e}`.includes("ENOENT")) throw e;
            options.publicKey = undefined;
        }
    }
    if (options.updateXML === null) {
        if (options.crxUrl === undefined) throw new Error("crxUrl must be defined to generate updateXML");
        if (options.id === undefined) options.id = null;
        if (options.extVersion === undefined) options.extVersion = null;
        if (options.minChromeVersion === undefined) options.minChromeVersion = null;
    }
    if (options.extVersion === null) {
        if (options.manifest === undefined) options.manifest = null;
    }
    if (options.minChromeVersion === null) {
        if (options.manifest === undefined) options.manifest = null;
    }
    if (options.crx === null) {
        if (options.contents === undefined) throw new Error("contents must be defined to generate crx");
        if (options.privateKey === undefined) options.privateKey = null;
        if (options.publicKey === undefined) options.publicKey = null;
    }
    if (options.id === null) {
        if (options.publicKey === undefined) options.publicKey = null;
    }
    if (options.publicKey === null) {
        if (options.privateKey === undefined) options.privateKey = null;
    }
    
    if (options.privateKey === null) {
        options.rsa ??= new RSA({b: options.keySize || 4096});
        options.privateKey = Uint8Array.from(options.rsa.exportKey("pkcs8-private-der"));
        options.publicKey = Uint8Array.from(options.rsa.exportKey("pkcs8-public-der"));
    }
    if (options.publicKey === null) {
        options.publicKey = Uint8Array.from((options.rsa ??= new RSA(Buffer.from(options.privateKey!), "pkcs8-private-der")).exportKey("pkcs8-public-der"));
    }
    if (typeof options.contents == "string") {
        ({contents: options.contents, manifest: options.manifest} = await packContents(options.contents));
    }
    if (options.crx === null) {
        if (options.crxVersion == 3 || options.crxVersion == undefined) options.crx = packCrx3(options.privateKey!, options.publicKey!, options.contents!, options.rsa);
        else if (options.crxVersion == 2) options.crx = packCrx2(options.privateKey!, options.publicKey!, options.contents!, options.rsa);
    }
    if (options.id === null) {
        options.id = generateCrxId(options.publicKey!);
    }
    if (options.extVersion === null) {
        if (!options.manifest) throw new Error("manifest must be defined to generate extVersion");
        options.extVersion = options.manifest.version;
    }
    if (options.minChromeVersion === null) {
        options.minChromeVersion = options.manifest?.minimum_chrome_version || (options.crxVersion == 3 || options.crxVersion == undefined ? "73.0.3683" : undefined);
    }
    if (options.updateXML === null) {
        options.updateXML = generateUpdateXML(options.id!, options.crxUrl!, options.extVersion!, options.minChromeVersion);
    }
    return options as any;
}

export default pack;