"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const { safeSetHeader } = require("../fixes/crlf_access_log_fix.js");

describe("CRLF Injection Access Log Fix", () => {
    it("should strip \\r and \\n and use encodeURIComponent", () => {
        let headers = {};
        const res = {
            setHeader: (name, value) => {
                headers[name] = value;
            }
        };
        
        safeSetHeader(res, "Mozilla/5.0\r\nX-Hacked: true\r\n");
        assert.equal(headers["X-Log"], encodeURIComponent("Mozilla/5.0X-Hacked: true"));
    });

    it("should handle undefined user agent safely", () => {
        let headers = {};
        const res = {
            setHeader: (name, value) => {
                headers[name] = value;
            }
        };
        
        safeSetHeader(res, undefined);
        assert.equal(headers["X-Log"], "");
    });
});
