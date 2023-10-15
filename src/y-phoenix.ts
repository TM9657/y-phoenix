/*
 * Copyright (c) TM9657 GmbH - 2023.
 * All rights reserved.
 *
 * Contact: info@tm9657.de
 *
 * Last changed: 22:3 10.10.2023 by FS
 */

import * as Y from "yjs"; // eslint-disable-line
import * as awarenessProtocol from "y-protocols/awareness";
import { Observable } from "lib0/observable";
import { Channel, Socket } from "@tm9657/socket-client/types/src/phoenix";
import { join } from "@tm9657/socket-client";
import jwtDecode from "jwt-decode";
import { fromUint8Array, toUint8Array } from "js-base64";
import debug from "debug";
const debugLog = debug("y-phoenix");

type IMessage = {
    sender: string;
    type: string;
    buffer: any;
    iv: any;
    clientID: string;
};

function numToUint8Array(num: number) {
    let arr = new Uint8Array(8);

    for (let i = 0; i < 8; i++) {
        arr[i] = num % 256;
        num = Math.floor(num / 256);
    }

    return arr;
}

export class PhoenixProvider extends Observable<string> {
    awareness: awarenessProtocol.Awareness;
    synced = false;
    /**
     * @param {Socket} channel
     * @param {string} roomname
     * @param {Y.Doc} doc
     * @param {object} opts
     * @param {boolean} [opts.connect]
     * @param {awarenessProtocol.Awareness} [opts.awareness]
     */
    private readonly roomName: string;
    private readonly token: string;
    private readonly doc: Y.Doc;
    private readonly socket: Socket;
    private readonly sub: string;
    private readonly password: string;
    private readonly debug: boolean;
    private readonly resyncSecs: number;
    private channel: Channel | null = null;
    private connectionState: 0 | 1 | 2;
    private key: CryptoKey | null = null;
    private clientID: string;
    private clients: Map<string, string> = new Map();

    constructor(
        socket: Socket,
        roomName: string,
        token: string,
        password: string,
        doc: Y.Doc,
        debug: boolean = false,
        resyncSecs: number = 60
    ) {
        super();
        this.resyncSecs = resyncSecs;
        this.debug = debug;
        if(debug) debugLog.enabled = true
        this.clientID = crypto.randomUUID();
        this.roomName = roomName;
        this.token = token;
        this.password = password;
        this.doc = doc;
        this.socket = socket;
        this.awareness = new awarenessProtocol.Awareness(this.doc);
        this.connectionState = 0;
        this.sub = (jwtDecode(token) as any).sub as string;

        this.doc.on("update", async (update: Uint8Array, origin: any) => {
            await this.updateDocHandler(update, origin);
        });

        this.awareness.on(
            "update",
            async ({ added, updated, removed }, _origin) => {
                await this.updateAwarenessHandler({ added, updated, removed }, _origin);
            }
        );

        this.connect();
        this.resync()
    }

    private async resync() {
        if(this.resyncSecs <= 0) return
        setTimeout(async () => {
            const stateVector = Y.encodeStateVector(this.doc);
            await this.broadcast(stateVector, "sync-request-1");
            this.resync()
        }, this.resyncSecs * 1000)
    }

    async broadcast(buf: Uint8Array, type) {
        if (!this.channel) {
            console.error("[Phoenix Connector] no channel for broadcast");
            return;
        }

        if (!this.key) {
            console.error("[Phoenix Connector] no key for broadcast");
            return;
        }

        debugLog("[broadcast] " + type)
        const random = crypto.getRandomValues(new Uint8Array(4));
        const date = numToUint8Array(Date.now());
        const iv = new Uint8Array([...random, ...date]);

        let encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            this.key,
            buf
        );

        const message = {
            buffer: fromUint8Array(new Uint8Array(encrypted)),
            iv: fromUint8Array(iv),
            clientID: this.clientID,
            type,
        };

        this.channel.push("msg", message);
    }

    async destroy() {
        // clearInterval(this._checkInterval)
        await this.disconnect();
        if (typeof window !== "undefined") {
            window.removeEventListener("unload", () => {
                this.unloadHandler();
            });
        }
        this.awareness.off(
            "update",
            async ({ added, updated, removed }, _origin) => {
                await this.updateAwarenessHandler({ added, updated, removed }, _origin);
            }
        );
        this.doc.off("update", async (update: Uint8Array, origin: any) => {
            await this.updateDocHandler(update, origin);
        });
        super.destroy();
    }

    async connect() {
        await this.setupKey();
        this.connectionState = 1;
        this.channel = await join(this.socket, this.roomName, this.token);
        this.connectionState = 2;
        await this.setupChannel();
    }

    private async disconnect() {
        await this.broadcast( awarenessProtocol.encodeAwarenessUpdate(
            this.awareness,
            [this.doc.clientID],
            new Map()
        ), "aware");
        this.channel?.leave();
    }

    private async updateDocHandler(update: Uint8Array, origin: any) {
        if (origin !== this) {
            debugLog("[updateDocHandler] broadcasting update from other origin")
            await this.broadcast(update, "doc");
            return;
        }
    }

    private async updateAwarenessHandler({ added, updated, removed }, origin) {
        const changedClients = added.concat(updated).concat(removed);
        debugLog("[updateAwarenessHandler] broadcasting update from awareness handler")
        await this.broadcast(
            awarenessProtocol.encodeAwarenessUpdate(this.awareness, changedClients),
            "aware"
        );
    }

    private async decryptMessage(message: string, iv: string) {
        if (!this.key) {
            throw Error("Key not initialized, dropping message");
        }

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: toUint8Array(iv) },
            this.key,
            toUint8Array(message)
        );

        return decrypted;
    }

    private unloadHandler() {
        awarenessProtocol.removeAwarenessStates(
            this.awareness,
            [this.doc.clientID],
            "window unload"
        );
    }

    private async receiveMessage(message: {
        sender: any;
        buffer: any;
        iv: any;
    }): Promise<Uint8Array> {
        const buffer = message.buffer;
        const iv = message.iv;
        let decrypted = await this.decryptMessage(buffer, iv);
        let arrayDecrypted = new Uint8Array(decrypted);
        
        return arrayDecrypted;
    }

    private async interpretMessage(message: IMessage) {
        switch (message.type) {
            case "doc":
                debugLog("[interpretMessage] interpreting doc update")
                Y.applyUpdate(this.doc, message.buffer, this);
                return;
            case "sync-request-1":
                debugLog("[interpretMessage] interpreting sync request 1")
                const stateVector = Y.encodeStateVector(this.doc);
                let diff_init = Y.encodeStateAsUpdateV2(this.doc, message.buffer);
                await this.broadcast(stateVector, "sync-answer-1");
                await this.broadcast(diff_init, "sync-answer-2");
                return;
            case "sync-answer-1":
                debugLog("[interpretMessage] interpreting sync answer 1")
                let diff_return = Y.encodeStateAsUpdateV2(this.doc, message.buffer);
                await this.broadcast(diff_return, "sync-answer-2");
                return;

            case "sync-answer-2":
                debugLog("[interpretMessage] interpreting sync answer 2")
                Y.applyUpdateV2(this.doc, message.buffer, this);
                return;
            case "aware":
                debugLog("[interpretMessage] interpreting awareness update")
                awarenessProtocol.applyAwarenessUpdate(
                    this.awareness,
                    message.buffer,
                    this
                );
        }
    }

    private async setupChannel() {
        if (!this.channel) {
            throw Error("Could not setup channel. Check your credentials!");
        }

        this.channel.on("msg", async (message: IMessage) => {
            try {
                // ignore our own messages
                if (this.clientID === message.clientID) return;
                if (!this.clients.has(message.clientID))
                    this.clients.set(message.clientID, message.sender);

                if (this.clients.get(message.clientID) !== message.sender) {
                    console.warn("Client changed sub, dropping message");
                    return;
                }

                const received = await this.receiveMessage(message);
                await this.interpretMessage({ ...message, buffer: received });
            } catch (e) {
                console.log("Could not decrypt message, dropping message", e);
                console.dir(message);
                return;
            }
        });

        this.channel.onError((error: any) => {
            this.emit("connection-error", [error, this]);
        });

        this.channel.onClose(() => {
            awarenessProtocol.removeAwarenessStates(
                this.awareness,
                Array.from(this.awareness.getStates().keys()).filter(
                    (client) => client !== this.doc.clientID
                ),
                this
            );
            this.emit("status", [
                {
                    status: "disconnected",
                },
            ]);
        });

        this.emit("status", [
            {
                status: "connected",
            },
        ]);

        const stateVector = Y.encodeStateVector(this.doc);
        await this.broadcast(stateVector, "sync-request-1");
        const encodedAwState = awarenessProtocol.encodeAwarenessUpdate(
            this.awareness,
            Array.from(this.awareness.getStates().keys())
        );
        await this.broadcast(encodedAwState, "aware");
    }

    private async setupKey() {
        const hashedPassword = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(this.password)
        );
        this.key = await crypto.subtle.importKey(
            "raw",
            hashedPassword,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );
    }
}
