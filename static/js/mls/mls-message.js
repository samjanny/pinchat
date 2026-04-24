/**
 * PinChat MLS — MLSMessage framing (RFC 9420 §15.1).
 *
 *   enum {
 *       reserved(0),
 *       mls_public_message(1),
 *       mls_private_message(2),
 *       mls_welcome(3),
 *       mls_group_info(4),
 *       mls_key_package(5),
 *       (65535)
 *   } WireFormat;
 *
 *   struct {
 *       ProtocolVersion version = mls10;    // u16
 *       WireFormat wire_format;             // u16
 *       select (MLSMessage.wire_format) {
 *           case mls_public_message:  PublicMessage public_message;
 *           case mls_private_message: PrivateMessage private_message;
 *           case mls_welcome:         Welcome welcome;
 *           case mls_group_info:      GroupInfo group_info;
 *           case mls_key_package:     KeyPackage key_package;
 *       };
 *   } MLSMessage;
 *
 * This module only implements the *outer* framing — a
 * `{version, wireFormat, body: Uint8Array}` triple. Each wire-format
 * owner (key-package.js, welcome.js, etc.) parses and re-serializes the
 * body bytes separately. The caller chooses the inner decoder based on
 * the wire_format value.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.MLSMessage = factory(root.MLS.Codec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    const PROTOCOL_VERSION_MLS10 = 0x0001;

    const WireFormat = Object.freeze({
        RESERVED: 0,
        MLS_PUBLIC_MESSAGE: 1,
        MLS_PRIVATE_MESSAGE: 2,
        MLS_WELCOME: 3,
        MLS_GROUP_INFO: 4,
        MLS_KEY_PACKAGE: 5,
    });

    /**
     * Parse the MLSMessage framing. Returns `{version, wireFormat, body}`
     * where `body` is a view over the remaining bytes. Throws if the
     * version is not mls10.
     */
    function parseMLSMessage(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const version = decoder.readU16();
        if (version !== PROTOCOL_VERSION_MLS10) {
            throw new Error(`mls_message: unsupported version 0x${version.toString(16)}`);
        }
        const wireFormat = decoder.readU16();
        const body = decoder.readBytes(decoder.remaining());
        return { version, wireFormat, body };
    }

    /**
     * Wrap a serialized inner body with the MLSMessage outer framing.
     * Returns the combined bytes.
     */
    function serializeMLSMessage(wireFormat, bodyBytes) {
        const encoder = new Codec.Encoder();
        encoder.writeU16(PROTOCOL_VERSION_MLS10);
        encoder.writeU16(wireFormat);
        encoder.writeBytes(bodyBytes);
        return encoder.bytes();
    }

    return Object.freeze({
        PROTOCOL_VERSION_MLS10,
        WireFormat,
        parseMLSMessage,
        serializeMLSMessage,
    });
});
