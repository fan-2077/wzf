"""Immutable, local public-evidence pages; no actor, AIOS, model, or native I/O.

Publisher inputs are trusted-runtime declarations, not proof that native capture
or settlement occurred. Only the supplied bytes and local sealed storage are
checked here. The reader never grants freshness or a business precondition.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading


CHUNK_BYTES = 6144
FRAME_BYTES = 65536
KINDS = ("document", "stdout", "stderr")
HEX = re.compile(r"[0-9a-f]{64}\Z")
HANDLE = re.compile(r"ep1:([0-9a-f]{64}):(document|stdout|stderr)\Z")
IDENTITY_FIELDS = frozenset(("attempt_id", "physical_scope_id", "ledger_epoch",
    "namespace_uid", "role", "launch_context_sha256", "derived_payload_binding_sha256",
    "clock_identity", "incident_visible_mono", "original_budgets"))
BINDING_FIELDS = frozenset(("identity", "action_id", "capture_sha256", "capture_complete",
    "settlement_status", "source_complete", "semantic_validation_status", "coverage",
    "consistency_class", "database_generation", "queue_generation", "services_generation",
    "document_source_kind", "document_sha256", "document_bytes", "stdout_sha256",
    "stdout_bytes", "stderr_sha256", "stderr_bytes"))
SOURCE_LIMITS = {
    "source_attestation": "publisher_assertion_not_independently_verified",
    "capture_digest_verified": False,
    "native_capture_verified": False,
    "settlement_verified": False,
    "source_completeness_verified": False,
    "semantic_validation_verified": False,
    "document_capture_relationship_verified": False,
    "currentness_assessed": False,
    "write_precondition_eligible": False,
    "model_received": None,
    "model_understood": None,
    "business_result": None,
}
REQUEST_FIELDS = frozenset(("evidence_handle", "expected_document_sha256", "offset", "count"))
PAGE_FIELDS = frozenset(("schema", "evidence_handle", "content_kind", "document_sha256",
    "total_bytes", "offset", "requested_count", "returned_bytes", "fragment", "fragment_sha256",
    "encoding", "next_offset", "page_complete", "document_end", "transport_complete",
    "source_complete", "source_binding", "source_limits", "integrity_scope"))
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class EvidenceError(ValueError):
    """A fixed public diagnostic; callers must not substitute success or retry work."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _json_value(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        require(math.isfinite(value), "nonfinite_metadata")
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    require(type(value) is dict and all(type(key) is str for key in value), "invalid_metadata_type")
    for item in value.values():
        _json_value(item)


def canonical(value):
    _json_value(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise EvidenceError("metadata_not_canonical_json") from error


def _decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_field")
            result[key] = value
        return result
    def bad_number(_):
        raise EvidenceError("nonfinite_metadata")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=bad_number)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError("invalid_json_frame") from error


def _copy_json(value):
    return _decode(canonical(value))


def _text(value):
    return type(value) is str and bool(value) and "\x00" not in value


def _sha(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def _integer(value):
    return type(value) is int and value >= 0


def validate_identity(identity):
    require(type(identity) is dict and set(identity) == IDENTITY_FIELDS, "identity_fields_invalid")
    for key in IDENTITY_FIELDS - {"original_budgets", "incident_visible_mono"}:
        require(_text(identity[key]), "identity_value_invalid")
    require(identity["role"] == "single", "trusted_role_must_be_single")
    for key in ("launch_context_sha256", "derived_payload_binding_sha256"):
        require(_sha(identity[key]), "identity_digest_invalid")
    mono = identity["incident_visible_mono"]
    require(type(mono) in (int, float) and math.isfinite(mono) and mono >= 0,
            "incident_clock_identity_invalid")
    require(type(identity["original_budgets"]) is dict and identity["original_budgets"],
            "original_budget_identity_missing")
    return _copy_json(identity)


def validate_binding(binding, identity):
    require(type(binding) is dict and set(binding) == BINDING_FIELDS, "source_binding_fields_invalid")
    require(canonical(validate_identity(binding["identity"])) == canonical(identity), "source_identity_mismatch")
    require(_text(binding["action_id"]) and _sha(binding["capture_sha256"]), "capture_reference_invalid")
    require(binding["capture_complete"] is True and binding["source_complete"] is True,
            "incomplete_source_not_publishable")
    require(binding["settlement_status"] == "settled", "unsettled_source_not_publishable")
    require(type(binding["semantic_validation_status"]) is str and
            binding["semantic_validation_status"] in {"passed", "failed", "unknown", "not_performed"},
            "semantic_status_invalid")
    require(type(binding["coverage"]) is dict and _text(binding["consistency_class"]),
            "source_coverage_invalid")
    require(type(binding["document_source_kind"]) is str and binding["document_source_kind"] in
            {"decoded_public_bytes", "parsed_public_bytes", "public_original_bytes"}, "document_source_kind_invalid")
    for key in ("database_generation", "queue_generation", "services_generation"):
        require(_integer(binding[key]), "source_generation_invalid")
    for kind in KINDS:
        require(_sha(binding[kind + "_sha256"]) and _integer(binding[kind + "_bytes"]),
                "source_content_digest_invalid")
    return _copy_json(binding)


def _open_directory(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "trusted_store_path_must_be_absolute")
    descriptor = os.open("/", _DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            following = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_directory(descriptor, mode):
    info = os.fstat(descriptor)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == mode, "store_directory_identity_or_mode_invalid")


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_nlink, info.st_mode)


def _open_file(directory, name, expected_size=None, mode=0o400):
    descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == mode, "sealed_regular_file_required")
        require(expected_size is None or info.st_size == expected_size, "sealed_file_length_changed")
        return descriptor, info
    except BaseException:
        os.close(descriptor)
        raise


def _read_exact(descriptor, size, offset):
    result = bytearray()
    while len(result) < size:
        block = os.pread(descriptor, size - len(result), offset + len(result))
        require(block, "sealed_file_short_read")
        result.extend(block)
    return bytes(result)


def _read_file(directory, name):
    descriptor, before = _open_file(directory, name)
    try:
        raw = _read_exact(descriptor, before.st_size, 0)
        require(_file_identity(before) == _file_identity(os.fstat(descriptor)), "sealed_file_changed_during_read")
        return raw
    finally:
        os.close(descriptor)


def _write_file(directory, name, raw):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _manifest(binding, contents):
    streams = {kind: {"bytes": len(raw), "sha256": digest(raw),
                     "chunk_sha256": [digest(raw[start:start + CHUNK_BYTES])
                                      for start in range(0, len(raw), CHUNK_BYTES)]}
               for kind, raw in contents.items()}
    return {"schema": "b1-public-evidence-manifest-v1", "source_binding": binding,
            "chunk_bytes": CHUNK_BYTES, "streams": streams, "source_limits": SOURCE_LIMITS}


def _validate_manifest(raw, bundle, identity):
    require(digest(raw) == bundle, "sealed_manifest_digest_mismatch")
    value = _decode(raw)
    require(type(value) is dict and set(value) == {"schema", "source_binding", "chunk_bytes", "streams", "source_limits"}
            and value["schema"] == "b1-public-evidence-manifest-v1"
            and type(value["chunk_bytes"]) is int and value["chunk_bytes"] == CHUNK_BYTES
            and canonical(value["source_limits"]) == canonical(SOURCE_LIMITS) and canonical(value) + b"\n" == raw,
            "sealed_manifest_profile_invalid")
    binding = validate_binding(value["source_binding"], identity)
    require(type(value["streams"]) is dict and set(value["streams"]) == set(KINDS), "sealed_stream_set_invalid")
    for kind, item in value["streams"].items():
        require(type(item) is dict and set(item) == {"bytes", "sha256", "chunk_sha256"}
                and _integer(item["bytes"]) and _sha(item["sha256"])
                and type(item["chunk_sha256"]) is list
                and len(item["chunk_sha256"]) == (item["bytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES
                and all(_sha(part) for part in item["chunk_sha256"]), "sealed_stream_profile_invalid")
        require(item["bytes"] == binding[kind + "_bytes"] and item["sha256"] == binding[kind + "_sha256"],
                "sealed_stream_binding_mismatch")
        if item["bytes"] == 0:
            require(item["sha256"] == digest(b""), "empty_stream_digest_mismatch")
    return value


def _page(bundle, kind, manifest, offset, count, fragment):
    item = manifest["streams"][kind]
    end = offset + len(fragment)
    return {"schema": "b1-public-evidence-page-v1", "evidence_handle": "ep1:" + bundle + ":" + kind,
        "content_kind": kind, "document_sha256": item["sha256"], "total_bytes": item["bytes"],
        "offset": offset, "requested_count": count, "returned_bytes": len(fragment),
        "fragment": base64.b64encode(fragment).decode("ascii"), "fragment_sha256": digest(fragment),
        "encoding": "base64", "next_offset": end if end < item["bytes"] else None,
        "page_complete": True, "document_end": end == item["bytes"], "transport_complete": None,
        "source_complete": True, "source_binding": manifest["source_binding"],
        "source_limits": SOURCE_LIMITS, "integrity_scope": "manifest_and_requested_blocks_only"}


def _frame(value):
    raw = canonical(value) + b"\n"
    require(len(raw) <= FRAME_BYTES, "response_frame_exceeds_65536")
    return raw


def _check_page_frame_capacity(bundle, manifest):
    # Use at least the largest possible decimal offsets and a full-size base64
    # fragment. This is a conservative frame check, not a total-reading budget.
    for kind, item in manifest["streams"].items():
        largest = max(0, item["bytes"])
        value = _page(bundle, kind, manifest, largest, CHUNK_BYTES, b"\xff" * min(CHUNK_BYTES, largest))
        value["next_offset"] = largest if len(str(largest)) >= 4 else None
        _frame(value)


class _Store:
    def __init__(self, root, expected_identity):
        self._identity = validate_identity(expected_identity)
        self._root = self._objects = None
        try:
            self._root = _open_directory(root)
            _private_directory(self._root, 0o700)
            raw = _read_file(self._root, "IDENTITY.json")
            require(raw == canonical(self._identity) + b"\n", "store_identity_mismatch")
            self._objects = os.open("objects", _DIR_FLAGS, dir_fd=self._root)
            _private_directory(self._objects, 0o700)
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in ("_objects", "_root"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _open_bundle(self, bundle):
        try:
            descriptor = os.open(bundle, _DIR_FLAGS, dir_fd=self._objects)
        except FileNotFoundError as error:
            raise EvidenceError("unknown_evidence_handle") from error
        try:
            _private_directory(descriptor, 0o500)
            require(set(os.listdir(descriptor)) == {"manifest.json", "document.bin", "stdout.bin", "stderr.bin"},
                    "sealed_object_members_changed")
            manifest = _validate_manifest(_read_file(descriptor, "manifest.json"), bundle, self._identity)
            return descriptor, manifest
        except BaseException:
            os.close(descriptor)
            raise


def create_store(root, identity):
    """Trusted-host setup only. It never replaces or initializes an existing root."""
    identity = validate_identity(identity)
    path = Path(root)
    require(path.is_absolute() and path.name and ".." not in path.parts, "trusted_store_path_must_be_absolute")
    parent = _open_directory(path.parent)
    descriptor = None
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        descriptor = os.open(path.name, _DIR_FLAGS, dir_fd=parent)
        _private_directory(descriptor, 0o700)
        _write_file(descriptor, "IDENTITY.json", canonical(identity) + b"\n")
        os.mkdir("objects", 0o700, dir_fd=descriptor)
        lock = os.open("publish.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        try:
            os.fsync(lock)
        finally:
            os.close(lock)
        os.fsync(descriptor)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


class TrustedPublisher(_Store):
    """Internal byte registration. Never expose this class as a model tool."""
    def __init__(self, root, expected_identity):
        self._pending = self._lock = None
        self._thread_lock = threading.Lock()
        super().__init__(root, expected_identity)
        try:
            # A sealed (0500) directory can be renamed within its current
            # parent. Moving it to a different parent needs write permission
            # to update '..'. Non-handle stage names share the same parent.
            self._pending = os.dup(self._objects)
            _private_directory(self._pending, 0o700)
            self._lock = os.open("publish.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root)
            info = os.fstat(self._lock)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600, "publisher_lock_invalid")
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in ("_pending", "_lock"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)
        super().close()

    def _verify_existing(self, bundle, expected_manifest):
        directory, manifest = self._open_bundle(bundle)
        try:
            require(canonical(manifest) == canonical(expected_manifest), "existing_object_manifest_conflict")
            for kind, item in manifest["streams"].items():
                file, before = _open_file(directory, kind + ".bin", item["bytes"])
                try:
                    whole = hashlib.sha256()
                    for index, expected in enumerate(item["chunk_sha256"]):
                        offset = index * CHUNK_BYTES
                        raw = _read_exact(file, min(CHUNK_BYTES, item["bytes"] - offset), offset)
                        require(digest(raw) == expected, "existing_object_chunk_changed")
                        whole.update(raw)
                    require(whole.hexdigest() == item["sha256"] and
                            _file_identity(before) == _file_identity(os.fstat(file)), "existing_object_bytes_changed")
                finally:
                    os.close(file)
        finally:
            os.close(directory)

    def _cleanup_pending(self, name, directory, created):
        observed = os.stat(name, dir_fd=self._pending, follow_symlinks=False)
        actual = os.fstat(directory)
        require((observed.st_dev, observed.st_ino) == (actual.st_dev, actual.st_ino), "own_pending_directory_replaced")
        require(set(os.listdir(directory)) <= set(created), "own_pending_has_unexpected_members")
        os.fchmod(directory, 0o700)
        for filename in created:
            try:
                os.unlink(filename, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.rmdir(name, dir_fd=self._pending)
        os.fsync(self._pending)

    def publish_capture(self, *, document_bytes, stdout_bytes, stderr_bytes, source_binding):
        binding = validate_binding(source_binding, self._identity)
        contents = {"document": document_bytes, "stdout": stdout_bytes, "stderr": stderr_bytes}
        for kind, raw in contents.items():
            require(type(raw) is bytes, "original_content_must_be_bytes")
            require(len(raw) == binding[kind + "_bytes"] and digest(raw) == binding[kind + "_sha256"],
                    "supplied_content_binding_mismatch")
        manifest = _manifest(binding, contents)
        raw_manifest = canonical(manifest) + b"\n"
        bundle = digest(raw_manifest)
        _check_page_frame_capacity(bundle, manifest)
        name = "stage-" + secrets.token_hex(16)
        directory, created, moved = None, [], False
        os.mkdir(name, 0o700, dir_fd=self._pending)
        try:
            directory = os.open(name, _DIR_FLAGS, dir_fd=self._pending)
            for kind, raw in contents.items():
                filename = kind + ".bin"
                created.append(filename)
                _write_file(directory, filename, raw)
            created.append("manifest.json")
            _write_file(directory, "manifest.json", raw_manifest)
            os.fchmod(directory, 0o500)
            os.fsync(directory)
            with self._thread_lock:
                fcntl.flock(self._lock, fcntl.LOCK_EX)
                try:
                    try:
                        os.stat(bundle, dir_fd=self._objects, follow_symlinks=False)
                    except FileNotFoundError:
                        os.rename(name, bundle, src_dir_fd=self._pending, dst_dir_fd=self._objects)
                        moved = True
                        os.fsync(self._objects)
                    else:
                        # The cooperating publisher lock makes check+rename exclusive;
                        # no existing directory, including an empty one, is replaced.
                        self._verify_existing(bundle, manifest)
                finally:
                    fcntl.flock(self._lock, fcntl.LOCK_UN)
        finally:
            if directory is not None:
                try:
                    if not moved:
                        self._cleanup_pending(name, directory, created)
                finally:
                    os.close(directory)
        return {"schema": "b1-public-evidence-publication-v1", "bundle_sha256": bundle,
            "contents": {kind: {"evidence_handle": "ep1:" + bundle + ":" + kind,
                "document_sha256": item["sha256"], "total_bytes": item["bytes"]}
                for kind, item in manifest["streams"].items()},
            "source_limits": _copy_json(SOURCE_LIMITS),
            "local_integrity": "all_three_input_byte_strings_hashed_and_atomically_published"}


class EvidenceReader(_Store):
    """Read-only capability surface: exactly four request fields, no path inputs."""
    def read_page(self, request):
        require(type(request) is dict and set(request) == REQUEST_FIELDS, "page_request_fields_invalid")
        handle, expected = request["evidence_handle"], request["expected_document_sha256"]
        match = HANDLE.fullmatch(handle) if type(handle) is str else None
        require(match is not None and _sha(expected), "page_handle_or_digest_invalid")
        offset, count = request["offset"], request["count"]
        require(_integer(offset) and type(count) is int and 1 <= count <= CHUNK_BYTES, "page_range_invalid")
        bundle, kind = match.groups()
        directory, manifest = self._open_bundle(bundle)
        try:
            item = manifest["streams"][kind]
            require(item["sha256"] == expected, "expected_document_digest_mismatch")
            require(offset <= item["bytes"], "page_offset_out_of_bounds")
            length = min(count, item["bytes"] - offset)
            file, before = _open_file(directory, kind + ".bin", item["bytes"])
            try:
                blocks = []
                if length:
                    first, last = offset // CHUNK_BYTES, (offset + length - 1) // CHUNK_BYTES
                    for index in range(first, last + 1):
                        start = index * CHUNK_BYTES
                        raw = _read_exact(file, min(CHUNK_BYTES, item["bytes"] - start), start)
                        require(digest(raw) == item["chunk_sha256"][index], "requested_content_block_changed")
                        blocks.append(raw)
                    raw = b"".join(blocks)
                    fragment = raw[offset - first * CHUNK_BYTES:offset - first * CHUNK_BYTES + length]
                else:
                    fragment = b""
                require(_file_identity(before) == _file_identity(os.fstat(file)), "sealed_content_changed_during_read")
            finally:
                os.close(file)
            return _frame(_page(bundle, kind, manifest, offset, count, fragment))
        finally:
            os.close(directory)


class DocumentAssembler:
    """Local sequential byte assembly, not evidence of model delivery or understanding."""
    def __init__(self, evidence_handle, expected_document_sha256):
        match = HANDLE.fullmatch(evidence_handle) if type(evidence_handle) is str else None
        require(match is not None and _sha(expected_document_sha256), "assembly_handle_or_digest_invalid")
        self._handle, self._sha, self._kind = evidence_handle, expected_document_sha256, match[2]
        self._metadata = self._total = None
        self._data = bytearray()
        self._complete = False

    def add(self, frame):
        require(type(frame) is bytes and len(frame) <= FRAME_BYTES and frame.endswith(b"\n"), "assembly_frame_invalid")
        value = _decode(frame)
        require(type(value) is dict and set(value) == PAGE_FIELDS and canonical(value) + b"\n" == frame,
                "assembly_page_fields_invalid")
        require(value["schema"] == "b1-public-evidence-page-v1" and value["evidence_handle"] == self._handle
                and value["content_kind"] == self._kind and value["document_sha256"] == self._sha,
                "assembly_document_binding_changed")
        require(canonical(value["source_limits"]) == canonical(SOURCE_LIMITS) and value["source_complete"] is True
                and value["page_complete"] is True and value["transport_complete"] is None
                and value["integrity_scope"] == "manifest_and_requested_blocks_only", "assembly_claim_scope_changed")
        require(_integer(value["total_bytes"]) and _integer(value["offset"]) and _integer(value["returned_bytes"])
                and type(value["requested_count"]) is int and 1 <= value["requested_count"] <= CHUNK_BYTES,
                "assembly_range_invalid")
        require(not self._complete and value["offset"] == len(self._data)
                and value["offset"] <= value["total_bytes"], "assembly_page_sequence_gap_or_replay")
        require(value["encoding"] == "base64" and type(value["fragment"]) is str and _sha(value["fragment_sha256"]),
                "assembly_fragment_invalid")
        try:
            raw = base64.b64decode(value["fragment"], validate=True)
        except (ValueError, UnicodeError) as error:
            raise EvidenceError("assembly_fragment_invalid") from error
        require(len(raw) == value["returned_bytes"] == min(value["requested_count"], value["total_bytes"] - value["offset"])
                and digest(raw) == value["fragment_sha256"], "assembly_fragment_digest_or_length_mismatch")
        end = value["offset"] + len(raw)
        require(type(value["document_end"]) is bool and value["document_end"] == (end == value["total_bytes"])
                and (value["next_offset"] is None or _integer(value["next_offset"]))
                and value["next_offset"] == (end if end < value["total_bytes"] else None), "assembly_continuation_invalid")
        metadata = canonical(value["source_binding"])
        binding = value["source_binding"]
        validate_binding(binding, validate_identity(binding.get("identity") if type(binding) is dict else None))
        require(binding[self._kind + "_sha256"] == self._sha and binding[self._kind + "_bytes"] == value["total_bytes"],
                "assembly_source_content_binding_changed")
        if self._metadata is None:
            self._metadata, self._total = metadata, value["total_bytes"]
        else:
            require(metadata == self._metadata and value["total_bytes"] == self._total, "assembly_source_binding_changed")
        self._data.extend(raw)
        if end == self._total:
            require(digest(self._data) == self._sha, "assembled_document_digest_mismatch")
            self._complete = True
        return self.status()

    def status(self):
        return {"received_bytes": len(self._data), "total_bytes": self._total,
                "transport_complete": self._complete, "scope": "local_assembler_bytes_only",
                "source_limits": _copy_json(SOURCE_LIMITS)}

    def finish(self):
        require(self._complete, "document_transport_incomplete")
        return bytes(self._data)
