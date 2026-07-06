// Disable WebRTC to prevent internal network reconnaissance
// Use with caution: this may break legitimate WebRTC features
if (window.RTCPeerConnection || window.webkitRTCPeerConnection) {
    // Override constructor to block connection attempts
    var originalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    window.RTCPeerConnection = function(config) {
        var pc = new originalRTCPeerConnection(config);
        // Block ICE candidates that reveal private IPs
        pc.createDataChannel('block');
        var originalCreateOffer = pc.createOffer.bind(pc);
        pc.createOffer = function() {
            var offer = originalCreateOffer();
            offer.then(function(sdp) {
                // Modify SDP to remove private IP candidates (simplified)
                sdp.sdp = sdp.sdp.replace(/a=candidate:[^\r\n]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^\r\n]*/g, '');
                return sdp;
            });
            return offer;
        };
        return pc;
    };
    window.RTCPeerConnection.prototype = originalRTCPeerConnection.prototype;
}

// Additionally, disable navigator.mediaDevices.enumerateDevices() if needed
if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    var originalEnumerateDevices = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
    navigator.mediaDevices.enumerateDevices = function() {
        return originalEnumerateDevices().then(function(devices) {
            return devices.filter(function(device) {
                // Optionally filter out local network devices
                return device.kind !== 'audioinput' && device.kind !== 'videoinput';
            });
        });
    };
}