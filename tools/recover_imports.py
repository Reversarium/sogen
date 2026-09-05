"""Recover observed transparent x64 import calls and rebuild a mapped PE image.

Inputs are sogen --import-trace evidence, never an original binary or expected RVA.
"""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import struct


class RecoveryError(ValueError):
    pass


def unpack(data, fmt, offset):
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error as error:
        raise RecoveryError(f"Truncated PE structure at {offset:#x}") from error


def align(value, alignment):
    if alignment <= 0 or alignment & (alignment - 1):
        raise RecoveryError("Invalid PE alignment")
    return (value + alignment - 1) & -alignment


def pe_headers(data):
    pe = unpack(data, "<I", 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise RecoveryError("Invalid PE signature")
    machine, count = unpack(data, "<HH", pe + 4)
    optional_size = unpack(data, "<H", pe + 20)[0]
    optional = pe + 24
    if machine != 0x8664 or optional_size < 240 or unpack(data, "<H", optional)[0] != 0x20B:
        raise RecoveryError("Only x64 PE32+ images are supported")
    table = optional + optional_size
    sections = []
    for index in range(count):
        offset = table + index * 40
        name, virtual_size, rva, raw_size, raw = unpack(data, "<8sIIII", offset)
        flags = unpack(data, "<I", offset + 36)[0]
        sections.append(dict(name=name, virtual_size=virtual_size, rva=rva,
                             raw_size=raw_size, raw=raw, flags=flags, header=offset))
    directories = [unpack(data, "<II", optional + 112 + index * 8) for index in range(16)]
    return dict(pe=pe, optional=optional, table=table, sections=sections, directories=directories,
                image_base=unpack(data, "<Q", optional + 24)[0],
                image_size=unpack(data, "<I", optional + 56)[0],
                entry=unpack(data, "<I", optional + 16)[0],
                section_alignment=unpack(data, "<I", optional + 32)[0],
                file_alignment=unpack(data, "<I", optional + 36)[0])


def read_c_string(data, offset):
    if not 0 <= offset < len(data):
        raise RecoveryError("String RVA outside image")
    end = data.find(b"\0", offset, min(len(data), offset + 4096))
    if end < 0:
        raise RecoveryError("Unterminated PE string")
    return data[offset:end].decode("ascii")


def imports_from_file(path):
    raw = path.read_bytes()
    header = pe_headers(raw)
    if header["image_size"] > 512 * 1024 * 1024:
        raise RecoveryError("PE image too large")
    image = bytearray(header["image_size"])
    size_headers = unpack(raw, "<I", header["optional"] + 60)[0]
    if size_headers > len(raw) or size_headers > len(image):
        raise RecoveryError("Invalid PE header size")
    image[:size_headers] = raw[:size_headers]
    for section in header["sections"]:
        rva, size, offset = section["rva"], section["raw_size"], section["raw"]
        if rva + size > len(image) or offset + size > len(raw):
            raise RecoveryError("Invalid section data")
        image[rva:rva + size] = raw[offset:offset + size]
    result = []
    directory, size = header["directories"][1]
    for offset in range(directory, directory + size, 20):
        ilt, _, _, name, iat = unpack(image, "<IIIII", offset)
        if not any((ilt, name, iat)):
            break
        module = read_c_string(image, name).lower()
        index = 0
        while True:
            value = unpack(image, "<Q", (ilt or iat) + index * 8)[0]
            if not value:
                break
            symbol = f"#{value & 0xFFFF}" if value >> 63 else read_c_string(image, value + 2)
            result.append({"module": module, "name": symbol, "iat_rva": iat + index * 8})
            index += 1
    return result


def context_mismatches(before, api):
    errors = []
    if before["gpr"][4] - 8 != api["gpr"][4]:
        errors.append("stack_pointer")
    # Microsoft x64: argument registers and nonvolatile registers are API inputs.
    required_gpr = (1, 2, 3, 5, 6, 7, 8, 9, 12, 13, 14, 15)
    if any(before["gpr"][index] != api["gpr"][index] for index in required_gpr):
        errors.append("argument_or_nonvolatile_gpr")
    if any(before["xmm"][index] != api["xmm"][index] for index in (*range(4), *range(6, 16))):
        errors.append("argument_or_nonvolatile_xmm")
    before_stack = bytes.fromhex(before["stack"])
    api_stack = bytes.fromhex(api["stack"])
    count = min(len(before_stack), len(api_stack) - 8)
    if count < 32 or before_stack[:count] != api_stack[8:8 + count]:
        errors.append("caller_stack")
    return errors


def recover(events, image):
    if not events or events[0].get("event") != "start":
        raise RecoveryError("Missing entry snapshot")
    start = events[0]
    result = events[-1]
    if result.get("event") != "result" or not result.get("completed") or not result.get("started"):
        raise RecoveryError("Incomplete trace")
    if result.get("candidate_count") != 1:
        raise RecoveryError("Ambiguous entry handoff")
    if len(image) != start["image_size"]:
        raise RecoveryError("Image size does not match trace")
    instructions = [(index, event) for index, event in enumerate(events) if event["event"] == "instruction"]
    if not instructions or instructions[0][1]["address"] != start["address"]:
        raise RecoveryError("Trace missed the first handoff instruction")
    exports = defaultdict(set)
    for event in events:
        if event["event"] == "export":
            exports[event["address"]].add((event["module"].lower(),
                                          event["name"] or f"#{event['ordinal']}"))
    repairs = {}
    unresolved = []
    observations = []
    for api_index, api in enumerate(events):
        if api["event"] not in ("api", "escape"):
            continue
        stack = bytes.fromhex(api["stack"])
        if len(stack) < 8:
            unresolved.append({"sequence": api["sequence"], "reason": "unreadable_api_stack"})
            continue
        continuation = int.from_bytes(stack[:8], "little")
        possible_sites = sorted({event["address"] - start["image_base"]
                                 for index, event in instructions
                                 if index < api_index and event["thread"] == api["thread"]
                                 and continuation - event["address"] in (5, 6)})
        identity = (api["module"].lower(), api["name"])
        if identity not in exports[api["address"]]:
            unresolved.append({"sequence": api["sequence"], "address": api["address"],
                               "reason": "not_a_named_export", "from": api["from"],
                               "possible_site_rvas": possible_sites})
            continue
        candidates = []
        reasons = set()
        for begin_index, before in instructions:
            span = continuation - before["address"]
            if begin_index >= api_index or before["thread"] != api["thread"] or span not in (5, 6):
                continue
            segment = events[begin_index:api_index]
            if any(event["event"] in ("api", "escape") for event in segment):
                continue
            errors = context_mismatches(before, api)
            if errors:
                reasons.update(errors)
                continue
            cursor = before["address"]
            prefix = []
            call = None
            for event in segment:
                if event["event"] != "instruction":
                    continue
                if event["thread"] != api["thread"] or event["address"] != cursor:
                    break
                prefix.append(event)
                cursor += event["size"]
                if event["mnemonic"] == "call":
                    call = event
                    break
                if event["mnemonic"].startswith("j") or event["mnemonic"] in ("ret", "syscall", "int"):
                    break
            if call is None or cursor > continuation:
                reasons.add("no_contiguous_call")
                continue
            # A replacement may consume skipped bytes only if they were never executed.
            if any(cursor <= event["address"] < continuation for _, event in instructions):
                reasons.add("executed_padding")
                continue
            bad_writes = [event for event in segment if event["event"] == "write" and not (
                event["thread"] == api["thread"] and before["stack_base"] <= event["address"]
                and event["address"] + event["size"] <= before["gpr"][4])]
            if bad_writes:
                reasons.add("write_outside_private_stack")
                continue
            if any(event["event"] == "instruction" and event["mnemonic"] in ("syscall", "sysenter", "int")
                   for event in segment):
                reasons.add("system_transition_inside_wrapper")
                continue
            if any(event["event"] == "instruction" and
                   (event["mnemonic"].startswith(("xsave", "fxsave")) or event["mnemonic"] in ("fsave", "fnsave"))
                   for event in segment):
                reasons.add("unmodeled_state_save_write")
                continue
            rva = before["address"] - start["image_base"]
            if rva < 0 or rva + span > len(image):
                reasons.add("site_outside_image")
                continue
            if any(image[event["address"] - start["image_base"]:
                         event["address"] - start["image_base"] + event["size"]] != bytes.fromhex(event["bytes"])
                   for event in prefix):
                reasons.add("call_site_changed_after_snapshot")
                continue
            item = dict(site_rva=rva, length=span, module=identity[0], name=identity[1],
                        target=api["address"], continuation_rva=continuation - start["image_base"],
                        original=image[rva:rva + span].hex(), call_rva=call["address"] - start["image_base"],
                        sequence=before["sequence"], api_sequence=api["sequence"],
                        wrapper_instructions=sum(event["event"] == "instruction" for event in segment),
                        private_stack_writes=sum(event["event"] == "write" for event in segment),
                        compared_stack_bytes=min(len(bytes.fromhex(before["stack"])), len(stack) - 8),
                        all_gpr_except_rsp_equal=all(a == b for i, (a, b) in enumerate(zip(before["gpr"], api["gpr"])) if i != 4),
                        all_xmm_equal=before["xmm"] == api["xmm"],
                        returned=any(event["thread"] == api["thread"] and event["address"] == continuation
                                     for index, event in instructions if index > api_index))
            candidates.append(item)
        if not candidates:
            unresolved.append(dict(sequence=api["sequence"], module=api["module"], name=api["name"],
                                   address=api["address"], continuation=continuation,
                                   possible_site_rvas=possible_sites,
                                   reason=sorted(reasons) or ["no_observed_call_with_reproducible_continuation"]))
            continue
        # Prefer the smallest equivalent replacement; reject conflicting observations of one site.
        candidates.sort(key=lambda item: (item["length"], -item["sequence"]))
        accepted = candidates[0]
        key = accepted["site_rva"]
        if key in repairs and any(repairs[key][field] != accepted[field]
                                  for field in ("length", "module", "name", "original")):
            raise RecoveryError(f"Polymorphic or changing import site at {key:#x}")
        repairs[key] = accepted
        observations.append(accepted)
    ordered = sorted(repairs.values(), key=lambda item: item["site_rva"])
    for transition in unresolved:
        if set(transition.get("possible_site_rvas", [])) & repairs.keys():
            raise RecoveryError("An accepted site also has an unresolved observation")
    for repair in ordered:
        previous_by_thread = {}
        for _, event in instructions:
            previous = previous_by_thread.get(event["thread"])
            offset = event["address"] - start["image_base"] - repair["site_rva"]
            if 0 < offset < repair["length"] and not (
                previous and previous["sequence"] + 1 == event["sequence"]
                and previous["address"] + previous["size"] == event["address"]
                and previous["address"] >= start["image_base"] + repair["site_rva"]):
                raise RecoveryError("Another execution path enters the interior of a repair")
            previous_by_thread[event["thread"]] = event
    for left, right in zip(ordered, ordered[1:]):
        if left["site_rva"] + left["length"] > right["site_rva"]:
            raise RecoveryError("Overlapping repairs")
    if not ordered:
        raise RecoveryError("No transparent import calls were recovered")
    return dict(schema=1, status="observed_calls_recovered", coverage="observed_transparent_calls_only",
                image_base=start["image_base"],
                entry_rva=start["address"] - start["image_base"],
                image_sha256=hashlib.sha256(image).hexdigest(), repairs=ordered,
                accepted_observations=len(observations), unresolved_transitions=unresolved,
                trace_result=result)


def rebuild(image, report):
    header = pe_headers(image)
    if len(image) != header["image_size"] or hashlib.sha256(image).hexdigest() != report["image_sha256"]:
        raise RecoveryError("Recovery report does not match image")
    for index in (9, 13, 14):
        if any(header["directories"][index]):
            raise RecoveryError(f"Standalone dump initialization is unsupported for directory {index}")
    section_alignment, file_alignment = header["section_alignment"], header["file_alignment"]
    section_rva = align(len(image), section_alignment)
    retained = []
    retained_slots = []
    directory, directory_size = header["directories"][1]
    for offset in range(directory, directory + directory_size, 20):
        ilt, _, _, name, iat = unpack(image, "<IIIII", offset)
        if not any((ilt, name, iat)):
            break
        if not ilt or not iat or not name:
            raise RecoveryError("Cannot preserve an import descriptor without a separate lookup table")
        module = read_c_string(image, name).lower()
        index = 0
        while True:
            value = unpack(image, "<Q", ilt + index * 8)[0]
            if not value:
                break
            symbol = f"#{value & 0xFFFF}" if value >> 63 else read_c_string(image, value + 2)
            retained_slots.append(dict(module=module, name=symbol, iat_rva=iat + index * 8))
            index += 1
        if iat + (index + 1) * 8 > len(image):
            raise RecoveryError("Existing IAT outside mapped image")
        retained.append((ilt, 0, 0, name, iat))
    groups = defaultdict(list)
    for repair in report["repairs"]:
        symbol = (repair["name"], repair["target"])
        if symbol not in groups[repair["module"]]:
            groups[repair["module"]].append(symbol)
    groups = dict(sorted(groups.items()))
    descriptor_count = len(retained) + len(groups) + 1
    payload = bytearray(descriptor_count * 20)
    for index, descriptor in enumerate(retained):
        struct.pack_into("<IIIII", payload, index * 20, *descriptor)

    def append(data, alignment=1):
        payload.extend(b"\0" * (align(len(payload), alignment) - len(payload)))
        offset = len(payload)
        payload.extend(data)
        return section_rva + offset

    tables = {}
    for module, symbols in groups.items():
        module_rva = append(module.encode("ascii") + b"\0")
        names = [append(b"\0\0" + name.encode("ascii") + b"\0", 2) for name, _ in symbols]
        ilt = append(b"".join(struct.pack("<Q", rva) for rva in [*names, 0]), 8)
        tables[module] = (module_rva, names, ilt)
    iat_begin = align(len(payload), 8) + section_rva
    slots = {}
    for index, (module, symbols) in enumerate(groups.items()):
        module_rva, names, ilt = tables[module]
        iat = append(b"".join(struct.pack("<Q", rva) for rva in [*names, 0]), 8)
        struct.pack_into("<IIIII", payload, (index + len(retained)) * 20, ilt, 0, 0, module_rva, iat)
        for symbol_index, (name, _) in enumerate(symbols):
            slots[(module, name)] = iat + symbol_index * 8
    if retained_slots:
        iat_begin = min(iat_begin, min(item["iat_rva"] for item in retained_slots))
    iat_size = section_rva + len(payload) - iat_begin
    patched = bytearray(image)
    for repair in report["repairs"]:
        rva, length = repair["site_rva"], repair["length"]
        slot = slots[(repair["module"], repair["name"])]
        if patched[rva:rva + length].hex() != repair["original"]:
            raise RecoveryError("Patch bytes no longer match")
        if length == 6:
            replacement = b"\xff\x15" + struct.pack("<i", slot - (rva + 6))
        elif length == 5:
            thunk = align(len(payload), 2) + section_rva
            append(b"\xff\x25" + struct.pack("<i", slot - (thunk + 6)), 2)
            replacement = b"\xe8" + struct.pack("<i", thunk - (rva + 5))
        else:
            raise RecoveryError("Unsupported replacement width")
        patched[rva:rva + length] = replacement
        repair["replacement"] = replacement.hex()
        repair["iat_rva"] = slot

    sections = header["sections"]
    if not sections or len(sections) >= 96:
        raise RecoveryError("Cannot add a PE section")
    headers_size = align(header["table"] + (len(sections) + 1) * 40, file_alignment)
    if headers_size > min(section["rva"] for section in sections):
        raise RecoveryError("No virtual space for expanded section headers")
    output = bytearray(patched[:headers_size])
    for section in sections:
        size = max(section["virtual_size"], section["raw_size"])
        if section["rva"] + size > len(patched):
            raise RecoveryError("Section outside mapped image")
        raw_size = align(size, file_alignment)
        raw = len(output)
        content = patched[section["rva"]:section["rva"] + size]
        output.extend(content + b"\0" * (raw_size - size))
        struct.pack_into("<II", output, section["header"] + 16, raw_size, raw)
    new_header = header["table"] + len(sections) * 40
    raw_size = align(len(payload), file_alignment)
    struct.pack_into("<8sIIIIIIHHI", output, new_header, b".sogen\0\0", len(payload), section_rva,
                     raw_size, len(output), 0, 0, 0, 0, 0xE0000060)
    output.extend(payload + b"\0" * (raw_size - len(payload)))
    optional = header["optional"]
    struct.pack_into("<H", output, header["pe"] + 6, len(sections) + 1)
    struct.pack_into("<I", output, optional + 16, report["entry_rva"])
    struct.pack_into("<Q", output, optional + 24, report["image_base"])
    struct.pack_into("<I", output, optional + 56, align(section_rva + len(payload), section_alignment))
    struct.pack_into("<I", output, optional + 60, headers_size)
    struct.pack_into("<I", output, optional + 64, 0)
    for index in (4, 6, 11):
        struct.pack_into("<II", output, optional + 112 + index * 8, 0, 0)
    struct.pack_into("<II", output, optional + 120, section_rva, descriptor_count * 20)
    struct.pack_into("<II", output, optional + 112 + 12 * 8, iat_begin, iat_size)
    report["rebuilt_imports"] = [dict(module=module, name=name, iat_rva=slot)
                               for (module, name), slot in sorted(slots.items())]
    report["retained_imports"] = retained_slots
    report["output_sha256"] = hashlib.sha256(output).hexdigest()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    events = [json.loads(line) for line in (args.capture / "trace.jsonl").read_text().splitlines()]
    image = (args.capture / "image.bin").read_bytes()
    report = recover(events, image)
    output = rebuild(image, report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    report_path = args.output.with_suffix(".imports.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report['repairs'])} sites, {len(report['rebuilt_imports'])} imports; "
          f"{len(report['unresolved_transitions'])} other transitions left unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
