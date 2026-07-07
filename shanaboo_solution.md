 ```diff
--- a/rate_limit.py
+++ b/rate_limit.py
@@ -1,4 +1,7 @@
 import time
+import threading
+from functools import wraps
+
 
 class RateLimiter:
     """
@@ -6,11 +9,13 @@ class RateLimiter:
     支持按用户、IP、API端点进行精细化限流控制。
     """
 
-    def __init__(self, max_requests=100, window_seconds=60):
+    def __init__(self, max_requests=100, window_seconds=60, lock_timeout=10):
         self.max_requests = max_requests
         self.window_seconds = window_seconds
+        self.lock_timeout = lock_timeout
         # 存储结构: {key: [(timestamp1, count1), (timestamp2, count2), ...]}
         self._storage = {}
+        self._locks = {}
+        self._global_lock = threading.Lock()
 
     def _clean_expired(self, key):
         """清理过期的请求记录"""
@@ -21,6 +26,50 @@ class RateLimiter:
         self._storage[key] = [record for record in records if record[0] > cutoff]
         return self._storage[key]
 
+    def _acquire_lock(self, key, timeout=None):
+        """
+        获取指定key的锁，防止竞态条件。
+        返回是否成功获取锁。
+        """
+        timeout = timeout or self.lock_timeout
+        with self._global_lock:
+            if key not in self._locks:
+                self._locks[key] = threading.Lock()
+            lock = self._locks[key]
+
+        # 使用非阻塞方式尝试获取锁，避免无限等待
+        acquired = lock.acquire(blocking=True, timeout=timeout)
+        return acquired
+
+    def _release_lock(self, key):
+        """释放指定key的锁"""
+        with self._栓_global_lock:
+            if key in self._locks:
+                try:
+                    self._locks[key].release()
+                except RuntimeError:
+                    # 锁未被当前线程持有，忽略
+                    pass
+
+    def is_allowed_atomic(self, key):
+        """
+        线程安全的限流检查，防止竞态窗口导致的数据盲注。
+        使用原子操作确保检查-更新过程不可中断。
+        """
+        if not self._acquire_lock(key):
+            # 无法获取锁，拒绝请求以防止竞态条件
+            return False
+
+        try:
+            now = time.time()
+            records = self._clean_expired(key)
+
+            total = sum(record[1] for record in records)
+
+            if total >= self.max_requests:
+                return False
+
+            # 原子地增加计数
+            if records and records[-1][0] == now:
+                # 合并同一秒的记录，减少存储
+                records[-1] = (now, records[-1][1] + 1)
+            else:
+                records.append((now, 1))
+
+            return True
+        finally:
+            self._release_lock(key)
+
     def is_allowed(self, key):
         """
         检查指定key的请求是否允许通过。
@@ -28,6 +77,10 @@ class RateLimiter:
         :param key: 限流标识，如用户ID、IP地址或API端点
         :return: True if allowed, False if rate limited
         """
+        # 使用原子版本替代非安全版本
+        return self.is_allowed_atomic(key)
+
+    def is_allowed_legacy(self, key):
+        """原始非线程安全版本，保留用于测试对比"""
         now = time.time()
         records = self._clean_expired(key)
 
@@ -42,6 +95,7 @@ class RateLimiter:
 
         return True
 
+
 class TokenBucketRateLimiter:
     """
     令牌桶限流器 - 支持突发流量和平滑限流
@@ -49,6 +103,8 @@ class TokenBucketRateLimiter:
 
     def __init__(self, rate=10, capacity=100):
         self.rate = rate
+        self.capacity = capacity
+        self._lock = threading.Lock()
         self.capacity = capacity
         self.tokens = capacity
         self.last_update = time.time()
@@ -61,6 +117,20 @@ class TokenBucketRateLimiter:
         self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
         self.last_update = now
 
+    def consume_atomic(self, tokens=1):
+        """线程安全的令牌消费"""
+        with self._lock:
+            self._add_tokens()
+
+            if self.tokens >= tokens:
+                self.tokens -= tokens
+                return True
+            return False
+
     def consume(self, tokens=1):
+        """线程安全的令牌消费接口"""
+        return self.consume_atomic(tokens)
+
+    def consume_legacy(self, tokens=1):
+        """原始非线程安全版本"""
         self._add_tokens()
 
         if self.tokens >= tokens:
@@ -69,6 +139,7 @@ class TokenBucketRateLimiter:
 
         return False
 
+
 class SlidingWindowRateLimiter:
     """
     滑动窗口限流器 - 精确控制请求速率
@@ -77,6 +148,8 @@ class SlidingWindowRateLimiter:
     def __init__(self, max_requests=100, window_seconds=60):
         self.max_requests = max_requests
         self.window_seconds = window_seconds
+        self._lock = threading.Lock()
         self.windows = {}
 
     def _get_current_window(self):
@@ -88,6 +161,22 @@ class SlidingWindowRateLimiter:
         return self.windows.get(window_key, 0)
 
     def is_allowed(self, key):
+        """线程安全的滑动窗口限流检查"""
+        with self._lock:
+            current_window = self._get_current_window()
+            count = self._get_window_count(key, current_window)
+
+            if count >= self.max_requests:
+                return False
+
+            if key not in self.windows:
+                self.windows[key] = {}
+
+            self.windows[key][current_window] = count + 1
+            return True
+
+    def is_allowed_legacy(self, key):
+        """原始非线程安全版本"""
         current_window = self._get_current_window()
         count = self._get_window_count(key, current_window)
 
@@ -99,3 +188,42
+    def is_allowed(self, key):
+        """线程安全的滑动窗口限流检查"""
+        with self._lock:
+            current_window = self._get_current_window()
+            count = self._get_window_count(key, current_window)
+
+            if count >= self.max_requests:
+                return False
+
+            if key not in self.windows:
+                self.windows[key] = {}
+
+            self.windows[key][current_window] = count + 1
+            return