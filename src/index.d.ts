import type NodeRSA from "node-rsa";

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

export function packCrx2(privateKey: Uint8Array, publicKey: Uint8Array, contents: Uint8Array, rsa?: NodeRSA): Uint8Array;
export function packCrx3(privateKey: Uint8Array, publicKey: Uint8Array, contents: Uint8Array, rsa?: NodeRSA): Uint8Array;
export function generateCrxId(publicKey: Uint8Array): string;
export function packContents(where: string): Promise<{
    /** The ZIP-encoded data. */
    contents: Uint8Array,
    /** The manifest for the extension, parsed as JSON. */
    manifest: ChromeManifest
}>;
export function generateUpdateXML(crxId: string, url: string, version: string, minChromeVersion?: string): string;
export function generatePrivateKey(bits?: number): Uint8Array;
export function generatePublicKey(privateKey: Uint8Array): Uint8Array;
export function convertToPem(key: Uint8Array, type: "private" | "public"): string;
export function convertFromPem(key: string, type: "private" | "public"): Uint8Array;
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
};
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
    rsa?: NodeRSA;
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
    I["publicKey"] extends string ?
        TransformPack<SetKeys<I, {
            publicKey: Uint8Array | undefined;
            rsa: NodeRSA;
        }>>
    : I["privateKey"] extends string ?
        TransformPack<SetKeys<I, {
            privateKey: Uint8Array | undefined;
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
            rsa: NodeRSA;
        }>>
    : I["contents"] extends string ? 
        TransformPack<SetKeys<I, {
            contents: Uint8Array;
            manifest: ChromeManifest;
        }>>
    : I;
export function pack<I extends PackInput>(options: I): Promise<TransformPack<I>>;
export default pack;