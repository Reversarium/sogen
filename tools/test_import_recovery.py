"""Safety and PE reconstruction checks using synthetic trace evidence."""

import copy
from pathlib import Path
import struct
import tempfile
import unittest

from recover_imports import RecoveryError, imports_from_file, pe_headers, rebuild, recover


def sample(prefix=False, length=6):
    base = 0x140000000
    image = bytearray(0x2000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, base)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", image, optional + 108, 16)
    struct.pack_into("<8sIIIIIIHHI", image, optional + 240, b".code\0\0\0",
                     0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    code = bytes.fromhex("50e800000000" if prefix else "e80000000090")
    image[0x1000:0x1006] = code
    state = dict(gpr=[0] * 16, xmm=[[0, 0] for _ in range(16)], stack="00" * 256,
                 stack_base=0x8000, stack_end=0xA000)
    state["gpr"][4] = 0x9000
    before = dict(event="instruction", sequence=1, thread=8, address=base + 0x1000,
                  size=1 if prefix else 5, mnemonic="push" if prefix else "call",
                  bytes=code[:1 if prefix else 5].hex(), **copy.deepcopy(state))
    api = dict(event="api", sequence=4, thread=8, address=0x180001000,
               module="example.dll", name="Example", **copy.deepcopy(state))
    api["from"] = base + 0x1010
    api["gpr"][4] -= 8
    api["stack"] = struct.pack("<Q", base + 0x1000 + length).hex() + state["stack"]
    events = [
        dict(event="start", image_base=base, image_size=len(image), address=base + 0x1000),
        dict(event="export", address=api["address"], module=api["module"], name=api["name"], ordinal=1),
        before,
    ]
    if prefix:
        call = copy.deepcopy(before)
        call.update(address=base + 0x1001, size=5, bytes=code[1:].hex(), mnemonic="call", sequence=2)
        call["gpr"][4] -= 8
        events.append(call)
    events.extend([
        dict(event="write", sequence=3, thread=8, ip=base + 0x1000, address=0x8FF8, size=8),
        api,
        dict(event="result", completed=True, started=True, candidate_count=1),
    ])
    return events, image


class RecoveryTests(unittest.TestCase):
    def test_direct_call_and_push_call_rebuild_to_same_import(self):
        for prefix in (False, True):
            with self.subTest(prefix=prefix):
                events, image = sample(prefix)
                report = recover(events, image)
                output = rebuild(image, report)
                repair = report["repairs"][0]
                self.assertEqual(repair["site_rva"], 0x1000)
                self.assertTrue(repair["replacement"].startswith("ff15"))
                self.assertEqual(pe_headers(output)["entry"], 0x1000)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "result.exe"
                    path.write_bytes(output)
                    imports = imports_from_file(path)
                self.assertEqual([(item["module"], item["name"]) for item in imports],
                                 [("example.dll", "Example")])

    def test_five_byte_call_uses_iat_tail_thunk(self):
        events, image = sample(length=5)
        report = recover(events, image)
        output = rebuild(image, report)
        self.assertEqual(report["repairs"][0]["length"], 5)
        self.assertTrue(report["repairs"][0]["replacement"].startswith("e8"))
        self.assertIn(b"\xff\x25", output)

    def test_existing_import_slots_are_retained_and_rebound(self):
        events, image = sample()
        optional = pe_headers(image)["optional"]
        struct.pack_into("<II", image, optional + 120, 0x1080, 40)
        struct.pack_into("<IIIII", image, 0x1080, 0x10C0, 0, 0, 0x10B0, 0x10E0)
        image[0x10B0:0x10B8] = b"old.dll\0"
        struct.pack_into("<Q", image, 0x10C0, 0x10D0)
        image[0x10D0:0x10DD] = b"\0\0Unobserved\0"
        struct.pack_into("<Q", image, 0x10E0, 0x180003000)
        report = recover(events, image)
        output = rebuild(image, report)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.exe"
            path.write_bytes(output)
            imports = imports_from_file(path)
        self.assertIn(dict(module="old.dll", name="Unobserved", iat_rva=0x10E0), imports)

    def test_changed_argument_is_rejected(self):
        events, image = sample()
        events[-2]["gpr"][1] = 99
        with self.assertRaisesRegex(RecoveryError, "No transparent"):
            recover(events, image)

    def test_changed_nonvolatile_vector_is_rejected(self):
        events, image = sample()
        events[-2]["xmm"][6][0] = 99
        with self.assertRaises(RecoveryError):
            recover(events, image)

    def test_writes_to_global_or_caller_frame_are_rejected(self):
        for address, size in ((0x140001080, 8), (0x9000, 8), (0x8FF8, 16)):
            with self.subTest(address=address, size=size):
                events, image = sample()
                events[-3].update(address=address, size=size)
                with self.assertRaises(RecoveryError):
                    recover(events, image)

    def test_changed_caller_stack_is_rejected(self):
        events, image = sample()
        stack = bytearray.fromhex(events[-2]["stack"])
        stack[48] = 1
        events[-2]["stack"] = stack.hex()
        with self.assertRaises(RecoveryError):
            recover(events, image)

    def test_unknown_export_is_rejected(self):
        events, image = sample()
        events[-2]["name"] = "Unverified"
        with self.assertRaises(RecoveryError):
            recover(events, image)

    def test_incomplete_and_ambiguous_traces_are_rejected(self):
        for update in (dict(completed=False), dict(candidate_count=2)):
            with self.subTest(update=update):
                events, image = sample()
                events[-1].update(update)
                with self.assertRaises(RecoveryError):
                    recover(events, image)

    def test_missing_first_instruction_is_rejected(self):
        events, image = sample()
        events[0]["address"] -= 5
        with self.assertRaisesRegex(RecoveryError, "missed"):
            recover(events, image)

    def test_changed_site_is_rejected(self):
        events, image = sample()
        image[0x1000] = 0x90
        with self.assertRaises(RecoveryError):
            recover(events, image)

    def test_image_report_mismatch_is_rejected(self):
        events, image = sample()
        report = recover(events, image)
        image[0x1080] = 1
        with self.assertRaises(RecoveryError):
            rebuild(image, report)

    def test_runtime_polymorphic_site_is_rejected(self):
        events, image = sample()
        second = copy.deepcopy(events[2:-1])
        second[-1].update(name="Different", address=0x180002000)
        for event in second:
            event["sequence"] += 10
        events[-1:-1] = [
            dict(event="export", module="example.dll", name="Different", address=0x180002000, ordinal=2),
            *second,
        ]
        with self.assertRaisesRegex(RecoveryError, "Polymorphic"):
            recover(events, image)

    def test_initialized_tls_is_not_silently_removed(self):
        events, image = sample()
        header = pe_headers(image)
        struct.pack_into("<II", image, header["optional"] + 112 + 9 * 8, 0x1080, 40)
        report = recover(events, image)
        with self.assertRaisesRegex(RecoveryError, "directory 9"):
            rebuild(image, report)

    def test_one_success_does_not_hide_an_unresolved_observation(self):
        events, image = sample()
        second = copy.deepcopy(events[2:-1])
        second[-1]["gpr"][1] = 99
        for event in second:
            event["sequence"] += 10
        events[-1:-1] = second
        with self.assertRaisesRegex(RecoveryError, "unresolved observation"):
            recover(events, image)

    def test_variable_size_state_writes_are_rejected(self):
        events, image = sample()
        state_save = copy.deepcopy(events[2])
        state_save.update(address=0x140001080, sequence=2, size=3, mnemonic="xsave", bytes="0fae20")
        events[-2:-2] = [state_save]
        with self.assertRaises(RecoveryError):
            recover(events, image)


if __name__ == "__main__":
    unittest.main()
