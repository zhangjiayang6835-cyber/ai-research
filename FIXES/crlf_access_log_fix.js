"use strict";

function safeSetHeader(res, userAgent) {
    if (typeof userAgent !== "string") {
        userAgent = String(userAgent || "");
    }
    // 移除含 \r \n 的输入
    userAgent = userAgent.replace(/[\r\n]/g, "");
    
    // 使用 encodeURIComponent 编码
    const safeUserAgent = encodeURIComponent(userAgent);
    
    // 写入响应头
    res.setHeader("X-Log", safeUserAgent);
}

module.exports = { safeSetHeader };
