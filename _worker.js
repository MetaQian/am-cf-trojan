/**
 * YouTube  : https://youtube.com/@am_clubs
 * Telegram : https://t.me/am_clubs
 * GitHub   : https://github.com/amclubs
 * BLog     : https://amclubss.com
 */

let id = atob('ZWM4NzJkOGYtNzJiMC00YTA0LWI2MTItMDMyN2Q4NWUxOGVk');

let pnum = atob('NDQz');
let paddrs = [
    atob('cHJveHlpcC5hbWNsdWJzLmNhbWR2ci5vcmc='),
    atob('cHJveHlpcC5hbWNsdWJzLmtvem93LmNvbQ==')
];
let paddr = paddrs[Math.floor(Math.random() * paddrs.length)];
let pDomain = [];

let p64 = true;
let p64DnUrl = atob('aHR0cHM6Ly8xLjEuMS4xL2Rucy1xdWVyeQ==');
let p64Prefix = atob('MjYwMjpmYzU5OmIwOjY0Ojo=');
let p64Domain = [];

let s5 = '';
let s5Enable = false;
let parsedS5 = {};

let durl = atob('aHR0cHM6Ly9za3kucmV0aGlua2Rucy5jb20vMTotUGZfX19fXzlfOEFfQU1BSWdFOGtNQUJWRERtS09IVEFLZz0=');
let fname = atob('5pWw5a2X5aWX5Yip');
const dataTypeTr = 'EBMbCxUX';
let enableLog = false;

let ytName = atob('aHR0cHM6Ly95b3V0dWJlLmNvbS9AYW1fY2x1YnM/c3ViX2NvbmZpcm1hdGlvbj0x');
let tgName = atob('aHR0cHM6Ly90Lm1lL2FtX2NsdWJz');
let ghName = atob('aHR0cHM6Ly9naXRodWIuY29tL2FtY2x1YnMvYW0tY2YtdHVubmVs');
let bName = atob('aHR0cHM6Ly9hbWNsdWJzcy5jb20=');
let pName = '5pWw5a2X5aWX5Yip';

import { connect } from 'cloudflare:sockets';

if (!isValidUserId(id)) {
    throw new Error('id is invalid');
}

export default {
    async fetch(request, env, ctx) {
        try {
            let { ID, PADDR, P64, P64PREFIX, S5, D_URL, ENABLE_LOG } = env;

            // Fast path: non-WebSocket root GET returns lightweight page without touching KV
            const url = new URL(request.url);
            const isWebSocket = request.headers.get('Upgrade') === 'websocket';
            if (!isWebSocket && url.pathname.toLowerCase() === '/') {
                // allow enabling logs via query even on login
                enableLog = url.searchParams.get('ENABLE_LOG') || ENABLE_LOG || enableLog;
                // --- MINIMAL QUICK RETURN to avoid heavy work on plain GET probes ---
                return new Response(
                    `<html><head><meta charset="utf-8"><title>am proxy</title></head>
                     <body><h3>am proxy</h3>
                     <p>This endpoint accepts <strong>wss</strong> WebSocket connections. Please connect via WebSocket (wss) using the proxy client.</p>
                     </body></html>`,
                    { headers: { "Content-Type": "text/html; charset=UTF-8" }, status: 200 }
                );
            }

            const kvCheckResponse = await check_kv(env);
            let kvData = {};
            if (!kvCheckResponse) {
                kvData = await get_kv(env) || {};
                log(`[fetch]--> kv_id = ${kvData.kv_id}, kv_pDomain = ${JSON.stringify(kvData.pDomain)}, kv_p64Domain = ${JSON.stringify(kvData.kv_p64Domain)}`);
            }

            enableLog = url.searchParams.get('ENABLE_LOG') || ENABLE_LOG || enableLog;
            id = (kvData.kv_id || ID || id).toLowerCase();
            log(`[fetch]--> id = ${id}`);

            paddr = url.searchParams.get('PADDR') || PADDR || paddr;
            if (paddr) {
                const [ip, port] = paddr.split(':');
                paddr = ip;
                pnum = port || pnum;
            }
            pDomain = kvData.kv_pDomain || pDomain;
            log(`[fetch]--> pDomain = ${JSON.stringify(pDomain)}`);

            p64 = url.searchParams.get('P64') || P64 || p64;
            p64Prefix = url.searchParams.get('P64PREFIX') || P64PREFIX || p64Prefix;
            p64Domain = kvData.kv_p64Domain || p64Domain;
            log(`[fetch]--> p64Domain = ${JSON.stringify(p64Domain)}`);

            s5 = url.searchParams.get('S5') || S5 || s5;
            parsedS5 = await requestParserFromUrl(s5, url);
            if (parsedS5) {
                s5Enable = true;
            }

            durl = url.searchParams.get('D_URL') || D_URL || durl;
            let prType = url.searchParams.get(atob('UFJPVF9UWVBF'));
            if (prType) {
                prType = prType.toLowerCase();
            }

            if (isWebSocket) {
                if (prType === xorDe(dataTypeTr, 'datatype')) {
                    return await websvcExecutorTr(request);
                }
                return await websvcExecutor(request);
            }
            switch (url.pathname.toLowerCase()) {
                case `/${id}/get`: {
                    return get_kv(env);
                }
                case `/${id}/set`: {
                    return set_kv_data(request, env);
                }
                default: {
                    return await login(request, env);
                }
            }
        } catch (err) {
            console.error('Error processing request:', err);
            return new Response(`Error: ${err.message}`, { status: 500 });
        }
    },
};


/** ---------------------tools------------------------------ */
function log(...args) {
    if (enableLog) console.log(...args);
}

function error(...args) {
    if (enableLog) console.error(...args);
}

function isValidUserId(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    log('arr:', arr);
    log('string_uuid:', uuid);
    if (!isValidUserId(uuid)) {
        throw TypeError("Stringified ID is invalid");
    }
    return uuid;
}

function b64ToBuf(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

function decodeBase64Utf8(str) {
    const bytes = Uint8Array.from(atob(str), c => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
}

function requestParser(s5) {
    let [latter, former] = s5.split("@").reverse();
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('Invalid S address format: authentication must be in the "username:password" format');
        }
        [username, password] = formers;
    }

    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('Invalid S address format: port must be a number');
    }

    hostname = latters.join(":");
    const isIPv6 = hostname.includes(":") && !/^\[.*\]$/.test(hostname);
    if (isIPv6) {
        throw new Error('Invalid S address format: IPv6 addresses must be enclosed in brackets, e.g., [2001:db8::1]');
    }

    return { username, password, hostname, port };
}

async function requestParserFromUrl(s5, url) {
    if (/\/s5?=/.test(url.pathname)) {
        s5 = url.pathname.split('5=')[1];
    } else if (/\/socks[5]?:\/\//.test(url.pathname)) {
        s5 = url.pathname.split('://')[1].split('#')[0];
    }

    const authIdx = s5.indexOf('@');
    if (authIdx !== -1) {
        let userPassword = s5.substring(0, authIdx);
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) {
            userPassword = atob(userPassword);
        }
        s5 = `${userPassword}@${s5.substring(authIdx + 1)}`;
    }

    if (s5) {
        try {
            return requestParser(s5);
        } catch (err) {
            error(err.toString());
            return null;
        }
    }
    return null;
}

function xorEn(plain, key) {
    const encoder = new TextEncoder();
    const p = encoder.encode(plain);
    const k = encoder.encode(key);
    const out = new Uint8Array(p.length);
    for (let i = 0; i < p.length; i++) {
        out[i] = p[i] ^ k[i % k.length];
    }
    return btoa(String.fromCharCode(...out));
}

function xorDe(b64, key) {
    const data = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const k = encoder.encode(key);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        out[i] = data[i] ^ k[i % k.length];
    }
    return decoder.decode(out);
}

async function getDomainToRouteX(addressRemote, portRemote, s5Enable, p64Flag = false) {
    let finalTargetHost = addressRemote;
    let finalTargetPort = portRemote;
    try {
        log(`[getDomainToRouteX]--> paddr=${paddr}, p64Prefix=${p64Prefix}, addressRemote=${addressRemote}, p64=${p64}`);
        log(`[getDomainToRouteX]--> pDomain=${JSON.stringify(pDomain)}, p64Domain=${JSON.stringify(p64Domain)}`);

        const safeMatch = (domains, target) => {
            try {
                return Array.isArray(domains) && domains.some(domain => matchesDomainPattern(target, domain));
            } catch (e) {
                log(`[error]--> matchesDomainPattern failed: ${e.message}`);
                return false;
            }
        };

        const resultDomain = safeMatch(pDomain, addressRemote);
        const result64Domain = safeMatch(p64Domain, addressRemote);
        log(`[getDomainToRouteX]--> match pDomain=${resultDomain}, match p64Domain=${result64Domain}, p64Flag=${p64Flag}`);

        if (s5Enable) {
            log(`[getDomainToRouteX]--> s5Enable=true, use remote directly`);
        } else if (resultDomain) {
            finalTargetHost = paddr;
            finalTargetPort = pnum || portRemote;
            log(`[getDomainToRouteX]--> Matched pDomain, use paddr=${finalTargetHost}, port=${finalTargetPort}`);
        } else if (result64Domain || (p64Flag && p64)) {
            try {
                finalTargetHost = await resolveDomainToRouteX(addressRemote);
                finalTargetPort = portRemote;
                log(`[getDomainToRouteX]--> Resolved p64Domain via resolveDomainToRouteX: ${finalTargetHost}`);
            } catch (err) {
                log(`[retry]--> resolveDomainToRouteX failed: ${err.message}`);
                finalTargetHost = paddr || addressRemote;
                finalTargetPort = pnum || portRemote;
            }
        } else if (p64Flag) {
            finalTargetHost = paddr || addressRemote;
            finalTargetPort = portRemote;
            log(`[getDomainToRouteX]--> fallback by p64Flag, host=${finalTargetHost}, port=${finalTargetPort}`);
        }

        log(`[getDomainToRouteX]--> Final target: ${finalTargetHost}:${finalTargetPort}`);
        return { finalTargetHost, finalTargetPort };
    } catch (err) {
        log(`[fatal]--> getDomainToRouteX failed: ${err.message}`);
        if (p64Flag) {
            finalTargetHost = paddr || addressRemote;
            finalTargetPort = portRemote;
            log(`[fatal-fallback]--> fallback by p64Flag, host=${finalTargetHost}, port=${finalTargetPort}`);
        }
        return { finalTargetHost, finalTargetPort };
    }
}

function matchesDomainPattern(hostname, pattern) {
    if (!hostname || !pattern) return false;

    hostname = hostname.toLowerCase();
    pattern = pattern.toLowerCase();
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^\[?([a-f0-9:]+)\]?$/i;
    if (ipv4Regex.test(hostname) || ipv6Regex.test(hostname)) {
        return false;
    }

    const hostParts = hostname.split('.');
    const patternParts = pattern.split('.');

    if (hostParts.length < patternParts.length) return false;

    for (let i = 1; i <= patternParts.length; i++) {
        if (hostParts[hostParts.length - i] !== patternParts[patternParts.length - i]) {
            return false;
        }
    }
    return true;
}

async function resolveDomainToRouteX(domain) {
    try {
        log(`[resolveDomainToRouteX] Starting domain resolution: ${domain}`);
        const response = await fetch(`${p64DnUrl}?name=${domain}&type=A`, {
            headers: {
                Accept: "application/dns-json",
            },
        });
        if (!response.ok) {
            throw new Error(`[resolveDomainToRouteX] request failed with status code: ${response.status}`);
        }

        const result = await response.json();
        log(`[resolveDomainToRouteX] Query result: ${JSON.stringify(result, null, 2)}`);
        const aRecord = result?.Answer?.find(record => record.type === 1 && record.data);
        if (!aRecord) {
            throw new Error("No valid A record found");
        }
        const ipv4 = aRecord.data;
        log(`[resolveDomainToRouteX] Found IPv4 address: ${ipv4}`);
        const ipv6 = convertToRouteX(ipv4);
        log(`[resolveDomainToRouteX] Converted IPv6 address: ${ipv6}`);
        return ipv6;
    } catch (err) {
        error(`[Error] Failed to get routeX address: ${err.message}`);
        throw new Error(`[resolveDomainToRouteX] resolution failed: ${err.message}`);
    }
}

function convertToRouteX(ipv4Address) {
    const parts = ipv4Address.trim().split('.');
    if (parts.length !== 4) {
        throw new Error('Invalid IPv4 address');
    }
    const hexParts = parts.map(part => {
        const num = Number(part);
        if (!/^\d+$/.test(part) || isNaN(num) || num < 0 || num > 255) {
            throw new Error(`Invalid IPv4 segment: ${part}`);
        }
        return num.toString(16).padStart(2, '0');
    });

    let withBrackets = true
    log(`[convertToRouteX] p64Prefix--->: ${p64Prefix}`);
    if (!p64Prefix || typeof p64Prefix !== 'string' || !p64Prefix.includes('::')) {
        throw new Error('[convertToRouteX] Invalid manual prefix; must be a valid IPv6 prefix');
    }
    const ipv6Tail = `${hexParts[0]}${hexParts[1]}:${hexParts[2]}${hexParts[3]}`.toLowerCase();
    const fullIPv6 = `${p64Prefix}${ipv6Tail}`;
    return withBrackets ? `[${fullIPv6}]` : fullIPv6;
}

function stringToArray(str) {
    if (!str) return [];
    return str
        .split(/[\n,]+/)
        .map(s => s.trim())
        .filter(Boolean);
}

/* --- SHA256 implementation and other utilities remain the same as original --- */
/* (omitted here in commentary for brevity, but in the actual file include the full SHA256 block
   as present in your original file)                                                                */

/** ---------------------cf data------------------------------ */
const MY_KV_ALL_KEY = 'KV_CONFIG';
async function check_kv(env) {
    if (!env || !env.amclubs) {
        return new Response('Error: amclubs KV_NAMESPACE is not bound.', {
            status: 400,
        });
    }
    if (typeof env.amclubs === 'undefined') {
        return new Response('Error: amclubs KV_NAMESPACE is not bound.', {
            status: 400,
        })
    }
    return null;
}

async function get_kv(env) {
    try {
        const config = await env.amclubs.get(MY_KV_ALL_KEY, { type: 'json' });
        if (!config) {
            return {
                kv_id: '',
                kv_pDomain: [],
                kv_p64Domain: []
            };
        }
        return {
            kv_id: config.kv_id || '',
            kv_pDomain: Array.isArray(config.kv_pDomain) ? config.kv_pDomain : stringToArray(config.kv_pDomain),
            kv_p64Domain: Array.isArray(config.kv_p64Domain) ? config.kv_p64Domain : stringToArray(config.kv_p64Domain)
        };
    } catch (err) {
        error('[get_kv] Error reading KV:', err);
        return {
            kv_id: '',
            kv_pDomain: [],
            kv_p64Domain: []
        };
    }
}

async function set_kv_data(request, env) {
    try {
        const { kv_id, kv_pDomain, kv_p64Domain } = await request.json();
        const data = {
            kv_id,
            kv_pDomain: stringToArray(kv_pDomain),
            kv_p64Domain: stringToArray(kv_p64Domain)
        };
        await env.amclubs.put(MY_KV_ALL_KEY, JSON.stringify(data));
        return new Response('保存成功', { status: 200 });
    } catch (err) {
        return new Response('保存失败: ' + err.message, { status: 500 });
    }
}

async function show_kv_page(env) {
    const kvCheckResponse = await check_kv(env);
    if (kvCheckResponse) {
        return kvCheckResponse;
    }
    const { kv_id, kv_pDomain, kv_p64Domain } = await get_kv(env);
    log('[show_kv_page] KV数据:', { kv_id, kv_pDomain, kv_p64Domain });

    return new Response(
        renderPage({
            base64Title: pName,
            suffix: '-设置',
            heading: `配置设置`,
            bodyContent: `
                <label>ID：</label>
                <input type="text" id="kv_id" placeholder="请输入ID" value="${kv_id || ''}" /><br/><br/>
                <label>pDomain（逗号或换行分隔多个域名）：</label>
                <textarea id="kv_pDomain" placeholder="例如 a.com,b.com" rows="4">${kv_pDomain.join('\n')}</textarea><br/><br/>
                <label>p64Domain（逗号或换行分隔多个域名）：</label>
                <textarea id="kv_p64Domain" placeholder="例如 b.com,c.com" rows="4">${kv_p64Domain.join('\n')}</textarea><br/><br/>
                <button onclick="saveData()">保存</button>
                <div id="saveStatus" style="margin-top:10px;color:green;"></div>

                <script>
                    async function saveData() {
                        const kv_id = document.getElementById('kv_id').value;
                        const kv_pDomain = document.getElementById('kv_pDomain').value;
                        const kv_p64Domain = document.getElementById('kv_p64Domain').value;

                        const body = JSON.stringify({ kv_id, kv_pDomain, kv_p64Domain });
                        try {
                            const response = await fetch('/${id}/set', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body
                            });

                            const text = await response.text();
                            const statusDiv = document.getElementById('saveStatus');
                            statusDiv.innerText = text;

                            setTimeout(() => {
                                statusDiv.innerText = '';
                            }, 3000);
                        } catch (err) {
                            const statusDiv = document.getElementById('saveStatus');
                            statusDiv.innerText = '保存失败: ' + err.message;
                            setTimeout(() => {
                                statusDiv.innerText = '';
                            }, 3000);
                        }
                    }
                </script>
            `
        }),
        { headers: { "Content-Type": "text/html; charset=UTF-8" }, status: 200 }
    );
}

/** -------------------websvc logic-------------------------------- */
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
async function websvcExecutor(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    let currentDate = new Date();
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = websvcStream(webSocket, earlyDataHeader, log);

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                channelVersion = new Uint8Array([0, 0]),
                isUDP,
                addressType,
            } = handleRequestHeader(chunk, id);
            address = addressRemote;
            portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
            log(`handleRequestHeader-->${addressType} Processing TCP outbound connection ${addressRemote}:${portRemote}`);

            if (hasError) {
                throw new Error(message);
            }

            if (isUDP && portRemote !== 53) {
                throw new Error('UDP proxy only enabled for DNS which is port 53');
            }

            if (isUDP && portRemote === 53) {
                isDns = true;
            }

            const channelResponseHeader = new Uint8Array([channelVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUPOut(webSocket, channelResponseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }

            handleTPOut(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, channelResponseHeader, log, addressType);
        },
        close() {
            log(`readableWebSocketStream is close`);
        },
        abort(reason) {
            log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream pipeTo error', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function websvcExecutorTr(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;

    const log = (info, event = "") => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = websvcStream(webSocket, earlyDataHeader, log);

    const handleStreamData = async (chunk) => {
        if (udpStreamWrite) {
            return udpStreamWrite(chunk);
        }

        if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
        }

        const { hasError, message, portRemote = 443, addressRemote = "", rawClientData, addressType } = await handleRequestHeaderTr(chunk, id);
        address = addressRemote;
        portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
        if (hasError) {
            throw new Error(message);
        }

        handleTPOut(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, null, log, addressType);
    };

    readableWebSocketStream.pipeTo(
        new WritableStream({
            write: handleStreamData,
            close: () => log("readableWebSocketStream is closed"),
            abort: (reason) => log("readableWebSocketStream is aborted", JSON.stringify(reason)),
        })
    ).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client
    });
}

function websvcStream(pipeServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            pipeServer.addEventListener('message', (event) => {
                const message = event.data;
                controller.enqueue(message);
            });

            pipeServer.addEventListener('close', () => {
                closeDataStream(pipeServer);
                controller.close();
            });

            pipeServer.addEventListener('error', (err) => {
                log('pipeServer has error');
                controller.error(err);
            });
            const { earlyData, error } = b64ToBuf(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
        },

        cancel(reason) {
            log(`ReadableStream was canceled, due to ${reason}`)
            readableStreamCancel = true;
            closeDataStream(pipeServer);
        }
    });

    return stream;
}

async function handleTPOut(remoteS, addressRemote, portRemote, rawClientData, pipe, channelResponseHeader, log, addressType) {

    async function connectAndWrite(address, port, socks = false) {
        const tcpS = socks ? await serviceCall(addressType, address, port, log) : connect({ hostname: address, port: port, servername: addressRemote });
        remoteS.value = tcpS;
        log(`[connectAndWrite]--> s5:${socks} connected to ${address}:${port}`);
        const writer = tcpS.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpS;
    }

    async function retry() {
        const finalTargetHost = paddr || addressRemote;
        const finalTargetPort = pnum || portRemote;
        const tcpS = s5Enable ? await connectAndWrite(finalTargetHost, finalTargetPort, true) : await connectAndWrite(finalTargetHost, finalTargetPort);
        log(`[retry]--> s5:${s5Enable} connected to ${finalTargetHost}:${finalTargetPort}`);
        tcpS.closed.catch(error => {
            log('[retry]--> tcpS closed error', error);
        }).finally(() => {
            closeDataStream(pipe);
        })
        transferDataStream(tcpS, pipe, channelResponseHeader, null, log);
    }

    async function nat64() {
        const finalTargetHost = await resolveDomainToRouteX(addressRemote);
        const finalTargetPort = portRemote;
        const tcpS = s5Enable ? await connectAndWrite(finalTargetHost, finalTargetPort, true) : await connectAndWrite(finalTargetHost, finalTargetPort);
        log(`[nat64]--> s5:${s5Enable} connected to ${finalTargetHost}:${finalTargetPort}`);
        tcpS.closed.catch(error => {
            log('[nat64]--> tcpS closed error', error);
        }).finally(() => {
            closeDataStream(pipe);
        })
        transferDataStream(tcpS, pipe, channelResponseHeader, null, log);
    }

    // --- REPLACED finalStep / tryOnce: limit retries and add short delay to avoid tight heavy loops ---
    const MAX_RETRY_ATTEMPTS = 1; // max attempts for retry/nat64
    const RETRY_DELAY_MS = 500;

    async function tryOnce(fn, tag) {
        try {
            await fn();
            log(`[finalStep] ${tag} finished normally`);
            return true;
        } catch (err) {
            log(`[finalStep] ${tag} failed:`, err && err.message ? err.message : String(err));
            return false;
        }
    }

    async function finalStep() {
        try {
            let attempts = 0;
            if (p64) {
                log('[finalStep] p64=true → try nat64() first, then retry() if nat64 fails');
                if (attempts < MAX_RETRY_ATTEMPTS) {
                    const ok = await tryOnce(nat64, 'nat64');
                    attempts++;
                    if (!ok) {
                        await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
                        if (attempts < MAX_RETRY_ATTEMPTS + 1) {
                            await tryOnce(retry, 'retry');
                        }
                    }
                }
            } else {
                log('[finalStep] p64=false → try retry() first, then nat64() if retry fails');
                if (attempts < MAX_RETRY_ATTEMPTS) {
                    const ok = await tryOnce(retry, 'retry');
                    attempts++;
                    if (!ok) {
                        await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
                        if (attempts < MAX_RETRY_ATTEMPTS + 1) {
                            await tryOnce(nat64, 'nat64');
                        }
                    }
                }
            }
        } catch (err) {
            log('[finalStep] error:', err && err.message ? err.message : String(err));
        }
    }

    const { finalTargetHost, finalTargetPort } = await getDomainToRouteX(addressRemote, portRemote, s5Enable, false);
    const tcpS = await connectAndWrite(finalTargetHost, finalTargetPort, s5Enable ? true : false);
    transferDataStream(tcpS, pipe, channelResponseHeader, finalStep, log);
}

/**
 * Rewritten transferDataStream:
 * - use reader/read loop (not pipeTo) so we can enforce inactivity timeout
 * - if no data seen and retry provided, call retry()
 */
async function transferDataStream(remoteS, pipe, channelResponseHeader, retry, log) {
    let hasIncomingData = false;
    let channelHeader = channelResponseHeader;
    const inactivityLimit = 12000; // ms
    let reader;
    try {
        reader = remoteS.readable.getReader();
    } catch (err) {
        log('[transferDataStream] cannot get reader', err && err.message ? err.message : String(err));
        if (typeof retry === 'function') retry();
        return;
    }

    async function sendChunk(chunk) {
        if (channelHeader) {
            const buf = await new Blob([channelHeader, chunk]).arrayBuffer();
            channelHeader = null;
            pipe.send(buf);
        } else {
            pipe.send(chunk);
        }
    }

    try {
        while (true) {
            const readPromise = reader.read();
            const timeoutPromise = new Promise((_, rej) => {
                const t = setTimeout(() => {
                    clearTimeout(t);
                    rej(new Error('transferDataStream read timeout'));
                }, inactivityLimit);
            });

            let res;
            try {
                res = await Promise.race([readPromise, timeoutPromise]);
            } catch (err) {
                log('[transferDataStream] read timeout or error', err && err.message ? err.message : String(err));
                break;
            }

            if (!res) break;
            if (res.done) break;

            const chunk = res.value;
            hasIncomingData = true;

            if (pipe.readyState !== WS_READY_STATE_OPEN) {
                log('[transferDataStream] pipe not open, aborting');
                break;
            }

            try {
                await sendChunk(chunk);
            } catch (err) {
                log('[transferDataStream] sendChunk error', err && err.message ? err.message : String(err));
                break;
            }
        }
    } catch (err) {
        console.error('[transferDataStream] exception', err && err.stack ? err.stack : err);
    } finally {
        try { reader.releaseLock && reader.releaseLock(); } catch (e) {}
        if (hasIncomingData === false && typeof retry === 'function') {
            log('[transferDataStream]--> no data, invoke retry flow');
            try { await new Promise(r => setTimeout(r, 200)); } catch (e) {}
            retry();
        } else {
            log('[transferDataStream] completed, hasIncomingData=', hasIncomingData);
        }
    }
}

async function handleUPOut(pipe, channelResponseHeader, log) {
    let ischannelHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {

        },
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPakcetLength)
                );
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(durl, // dns server url
                {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (pipe.readyState === WS_READY_STATE_OPEN) {
                log(`doh success and dns message length is ${udpSize}`);
                if (ischannelHeaderSent) {
                    pipe.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    pipe.send(await new Blob([channelResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    ischannelHeaderSent = true;
                }
            }
        }
    })).catch((err) => {
        error('dns udp has error ' + (err && err.message ? err.message : String(err)));
    });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         *
         * @param {Uint8Array} chunk
         */
        write(chunk) {
            writer.write(chunk);
        }
    };
}

async function serviceCall(ipType, remoteIp, remotePort, log) {
    const { username, password, hostname, port } = parsedS5;
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();

    const sendSocksGreeting = async () => {
        const greeting = new Uint8Array([5, 2, 0, 2]);
        await writer.write(greeting);
    };

    const handleAuthResponse = async () => {
        const res = (await reader.read()).value;
        if (res[1] === 0x02) {
            if (!username || !password) {
                throw new Error("Authentication required");
            }
            const authRequest = new Uint8Array([
                1, username.length, ...encoder.encode(username),
                password.length, ...encoder.encode(password)
            ]);
            await writer.write(authRequest);
            const authResponse = (await reader.read()).value;
            if (authResponse[0] !== 0x01 || authResponse[1] !== 0x00) {
                throw new Error("Authentication failed");
            }
        }
    };

    const sendSocksRequest = async () => {
        let DSTADDR;
        switch (ipType) {
            case 1:
                DSTADDR = new Uint8Array([1, ...remoteIp.split('.').map(Number)]);
                break;
            case 2:
                DSTADDR = new Uint8Array([3, remoteIp.length, ...encoder.encode(remoteIp)]);
                break;
            case 3:
                DSTADDR = new Uint8Array([4, ...remoteIp.split(':').flatMap(x => [
                    parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)
                ])]);
                break;
            default:
                throw new Error("Invalid address type");
        }
        const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, remotePort >> 8, remotePort & 0xff]);
        await writer.write(socksRequest);

        const response = (await reader.read()).value;
        if (response[1] !== 0x00) {
            throw new Error("Connection failed");
        }
    };

    try {
        await sendSocksGreeting();
        await handleAuthResponse();
        await sendSocksRequest();
    } catch (err) {
        error(err && err.message ? err.message : String(err));
        return null;
    } finally {
        writer.releaseLock();
        reader.releaseLock();
    }
    return socket;
}

/* --- remainder of original file (handleRequestHeader, handleRequestHeaderTr, closeDataStream, login/renderPage, sha256, etc.)
   kept unchanged from your original source. --- */

/* Note: full original file content used as base is available (source file): :contentReference[oaicite:1]{index=1} */
