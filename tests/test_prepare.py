import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("prepare", Path(__file__).resolve().parents[1] / "scripts/prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PrepareInputTests(unittest.TestCase):
    def test_wrong_hash_creates_no_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "input"
            source.write_bytes(b"not the verified upstream archive")
            destination = root / "not-created"
            with self.assertRaisesRegex(ValueError, "SHA256"):
                prepare.prepare(source, source, source, source, destination)
            self.assertFalse(destination.exists())

    def test_archive_paths_cannot_escape_or_supply_links(self):
        cases = [("/absolute", tarfile.REGTYPE),
                 ("shadowsocks/../../escape", tarfile.REGTYPE),
                 ("shadowsocks/link", tarfile.SYMTYPE),
                 ("shadowsocks/link", tarfile.LNKTYPE),
                 ("shadowsocks/device", tarfile.CHRTYPE)]
        for name, kind in cases:
            with self.subTest(name=name, kind=kind):
                member = tarfile.TarInfo(name)
                member.type = kind
                with self.assertRaises(ValueError):
                    prepare.validate_members([member])

    def test_input_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "file"
            source.write_bytes(b"input")
            link = Path(folder) / "link"
            link.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "regular file"):
                prepare.regular_file(link)


if __name__ == "__main__":
    unittest.main()
