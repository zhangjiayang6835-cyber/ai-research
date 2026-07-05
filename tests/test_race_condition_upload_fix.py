from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fixes.race_condition_upload_fix import AtomicUploadStore, UnsafeUpload, UploadConflict


class AtomicUploadStoreTests(unittest.TestCase):
    def test_rejects_path_traversal_and_unsafe_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = AtomicUploadStore(temp_dir, allowed_extensions={".txt"})

            for name in ("../secret.txt", "subdir/file.txt", r"subdir\file.txt", "", "..", "bad\x00.txt"):
                with self.subTest(name=name):
                    with self.assertRaises(UnsafeUpload):
                        store.save(name, b"payload")

    def test_enforces_size_and_extension_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = AtomicUploadStore(temp_dir, max_bytes=4, allowed_extensions={"txt"})

            with self.assertRaises(UnsafeUpload):
                store.save("payload.bin", b"ok")
            with self.assertRaises(UnsafeUpload):
                store.save("payload.txt", b"toolong")
            with self.assertRaises(UnsafeUpload):
                store.save("payload.txt", b"")

    def test_single_winner_for_concurrent_same_name_uploads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = AtomicUploadStore(temp_dir, allowed_extensions={".txt"})

            def attempt(index: int) -> bytes | str:
                payload = f"payload-{index}".encode()
                try:
                    return store.save("shared.txt", payload).read_bytes()
                except UploadConflict:
                    return "conflict"

            with ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(attempt, range(12)))

            winners = [item for item in results if isinstance(item, bytes)]
            self.assertEqual(len(winners), 1)
            self.assertEqual(results.count("conflict"), 11)
            final_payload = Path(temp_dir, "shared.txt").read_bytes()
            self.assertIn(final_payload, winners)
            self.assertFalse(list(Path(temp_dir).glob("*.uploading")))

    def test_overwrite_still_publishes_complete_new_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = AtomicUploadStore(temp_dir, allowed_extensions={".txt"})
            target = store.save("note.txt", b"first")

            same_target = store.save("note.txt", b"second", overwrite=True)

            self.assertEqual(target, same_target)
            self.assertEqual(same_target.read_bytes(), b"second")

    def test_distinct_uploads_do_not_block_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = AtomicUploadStore(temp_dir, allowed_extensions={".txt"})

            with ThreadPoolExecutor(max_workers=4) as pool:
                paths = list(pool.map(lambda i: store.save(f"file-{i}.txt", b"x"), range(4)))

            self.assertEqual(len({path.name for path in paths}), 4)
            self.assertEqual(sorted(path.name for path in Path(temp_dir).iterdir()), [
                "file-0.txt",
                "file-1.txt",
                "file-2.txt",
                "file-3.txt",
            ])


if __name__ == "__main__":
    unittest.main()

