// Prevent WebRTC from leaking internal IP addresses
(function() {
  if (typeof RTCPeerConnection !== 'undefined') {
    const originalCreateDataChannel = RTCPeerConnection.prototype.createDataChannel;
    RTCPeerConnection.prototype.createDataChannel = function() {
      // Disable data channels used for IP leak
      return null;
    };
    const originalSetLocalDescription = RTCPeerConnection.prototype.setLocalDescription;
    RTCPeerConnection.prototype.setLocalDescription = function() {
      // Suppress ICE candidates to prevent IP gathering
      return Promise.resolve();
    };
    // Override getStats to remove candidate-pair IP info
    const originalGetStats = RTCPeerConnection.prototype.getStats;
    RTCPeerConnection.prototype.getStats = function() {
      return originalGetStats.apply(this, arguments).then((stats) => {
        const newStats = new Map();
        stats.forEach((report) => {
          if (report.type !== 'candidate-pair' && report.type !== 'local-candidate' && report.type !== 'remote-candidate') {
            newStats.set(report.id, report);
          }
        });
        return newStats;
      });
    };
  }
  // Also override the deprecated mozRTCPeerConnection if present
  if (typeof mozRTCPeerConnection !== 'undefined') {
    // Similar overrides for Firefox legacy
  }
  // Override global IP lookup functions
  if (typeof window.RTCPeerConnection === 'function') {
    Object.defineProperty(window, 'RTCPeerConnection', {
      get: function() {
        return function() {
          // Return a dummy that does nothing
          return {
            createDataChannel: () => null,
            setLocalDescription: () => Promise.resolve(),
            getStats: () => Promise.resolve(new Map()),
            onicecandidate: null,
            close: () => {}
          };
        };
      }
    });
  }
})();
