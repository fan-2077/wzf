"""Real local-file tests only. No fixed-container, actor, AIOS, or model claim."""
from concurrent.futures import ThreadPoolExecutor
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import public_evidence as evidence


def fixture_clock_identity():
    return {"schema": "b0-monotonic-clock-identity-v1",
        "boot_id": "00000000-0000-0000-0000-000000000001", "time_namespace": "time:[1]",
        "timens_offsets_sha256": evidence.digest(b"controlled local clock offsets only")}


def fixture_identity():
    return {"attempt_id": "controlled-local-attempt-a", "physical_scope_id": "controlled-local-scope",
        "ledger_epoch": "controlled-local-ledger", "namespace_uid": "controlled-local-namespace",
        "role": "single", "launch_context_sha256": evidence.digest(b"local fixture launch identity"),
        "derived_payload_binding_sha256": evidence.digest(b"local fixture source identity"),
        "clock_identity": fixture_clock_identity(), "incident_visible_mono": 0.0,
        "original_budgets": {"fixture_only": "no_incident_or_model_budget_selected"}}


def fixture_binding(identity, document, stdout, stderr, generation=0):
    value = {"identity": copy.deepcopy(identity), "action_id": "controlled-fixture-action-" + str(generation),
        "capture_sha256": evidence.digest(b"unprovided original capture; declaration only"),
        "capture_complete": True, "settlement_status": "settled", "source_complete": True,
        "semantic_validation_status": "not_performed", "coverage": {"local_fixture": True, "business": False},
        "consistency_class": "controlled_local_fixture_only", "database_generation": generation,
        "queue_generation": generation, "services_generation": generation,
        "document_source_kind": "public_original_bytes"}
    for name, raw in (("document", document), ("stdout", stdout), ("stderr", stderr)):
        value[name + "_bytes"] = len(raw)
        value[name + "_sha256"] = evidence.digest(raw)
    return value


class EvidencePagesTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / "validation" / "tmp"
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="owned-", dir=parent)
        self.base = Path(self.temp.name)
        self.store = self.base / "store"
        self.identity = fixture_identity()
        evidence.create_store(self.store, self.identity)
        self.publisher = evidence.TrustedPublisher(self.store, self.identity)
        self.reader = evidence.EvidenceReader(self.store, self.identity)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.publisher.close)
        self.addCleanup(self.reader.close)

    def publish(self, document, stdout=b"controlled local stdout\n", stderr=b"", generation=0):
        binding = fixture_binding(self.identity, document, stdout, stderr, generation)
        publication = self.publisher.publish_capture(document_bytes=document, stdout_bytes=stdout,
            stderr_bytes=stderr, source_binding=binding)
        return publication, binding

    def request(self, publication, kind="document", offset=0, count=evidence.CHUNK_BYTES):
        item = publication["contents"][kind]
        return {"evidence_handle": item["evidence_handle"], "expected_document_sha256": item["document_sha256"],
                "offset": offset, "count": count}

    def assemble(self, publication, kind="document"):
        item = publication["contents"][kind]
        assembly = evidence.DocumentAssembler(item["evidence_handle"], item["document_sha256"])
        offset, pages = 0, []
        while True:
            frame = self.reader.read_page(self.request(publication, kind, offset))
            self.assertLessEqual(len(frame), evidence.FRAME_BYTES)
            page = json.loads(frame)
            self.assertIsNone(page["transport_complete"])
            pages.append(page)
            status = assembly.add(frame)
            if page["next_offset"] is None:
                break
            offset = page["next_offset"]
        self.assertIs(status["transport_complete"], True)
        self.assertEqual(status["scope"], "local_assembler_bytes_only")
        self.assertIsNone(status["source_limits"]["model_received"])
        self.assertIsNone(status["source_limits"]["business_result"])
        return assembly.finish(), pages

    def assert_code(self, code, callable, *args, **kwargs):
        with self.assertRaises(evidence.EvidenceError) as caught:
            callable(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_clock_dictionary_shape_schema_rejections_before_store_creation(self):
        cases = [("string", "controlled-local-clock-only", "clock_identity_fields_invalid"),
            ("none", None, "clock_identity_fields_invalid"),
            ("list", [], "clock_identity_fields_invalid"),
            ("bool", True, "clock_identity_fields_invalid")]
        for field in sorted(evidence.CLOCK_FIELDS):
            missing = fixture_clock_identity()
            del missing[field]
            cases.append(("missing_" + field, missing, "clock_identity_fields_invalid"))
        extra = fixture_clock_identity()
        extra["caller_clock_override"] = "forbidden"
        cases.append(("extra", extra, "clock_identity_fields_invalid"))
        wrong_schema = fixture_clock_identity()
        wrong_schema["schema"] = "caller-defined-clock"
        cases.append(("schema", wrong_schema, "clock_identity_schema_invalid"))
        for label, clock, code in cases:
            with self.subTest(case=label):
                identity = fixture_identity()
                identity["clock_identity"] = clock
                destination = self.base / ("bad-clock-" + label)
                self.assert_code(code, evidence.create_store, destination, identity)
                self.assertFalse(destination.exists())

    def test_clock_dictionary_boot_namespace_and_digest_rejections_before_store_creation(self):
        cases = {
            "boot_id": ("clock_boot_identity_invalid", [None, 1, "", "g" * 36,
                "00000000-0000-0000-0000-00000000000A", "0" * 35]),
            "time_namespace": ("clock_time_namespace_invalid", [None, 1, "pid:[1]",
                "time:[]", "time:[x]", "time:[1]\n"]),
            "timens_offsets_sha256": ("clock_timens_digest_invalid", [None, 1,
                "a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n"]),
        }
        for field, (code, values) in cases.items():
            for index, value in enumerate(values):
                with self.subTest(field=field, value=value):
                    identity = fixture_identity()
                    identity["clock_identity"][field] = value
                    destination = self.base / ("bad-" + field + "-" + str(index))
                    self.assert_code(code, evidence.create_store, destination, identity)
                    self.assertFalse(destination.exists())

    def test_real_public_clock_projection_publish_read_assemble_preserves_binding(self):
        clock_file = ROOT / "tests" / "fixtures" / "b0-public-clock-identity.json"
        clock_raw = clock_file.read_bytes()
        self.assertEqual(evidence.digest(clock_raw),
            "d175b69ab38774ad02fbda70c67574e603d94f4d22ddfc7ecd7851a559132b34")
        clock = json.loads(clock_raw)
        identity = fixture_identity()
        identity["clock_identity"] = copy.deepcopy(clock)
        copied = evidence.validate_identity(identity)
        self.assertEqual(copied["clock_identity"], clock)
        self.assertIsNot(copied["clock_identity"], identity["clock_identity"])
        # Only the clock came from the real public artifact. The single role,
        # attempt, budget, capture and settlement below are controlled fixtures.
        store = self.base / "real-public-clock-controlled-store"
        evidence.create_store(store, identity)
        document = (ROOT / "tests" / "fixtures" / "b1-public-document-01.json").read_bytes()
        stdout, stderr = b"controlled fixture stdout\n", b""
        binding = fixture_binding(identity, document, stdout, stderr)
        with evidence.TrustedPublisher(store, identity) as publisher, evidence.EvidenceReader(store, identity) as reader:
            publication = publisher.publish_capture(document_bytes=document, stdout_bytes=stdout,
                stderr_bytes=stderr, source_binding=binding)
            identity["clock_identity"]["boot_id"] = "00000000-0000-0000-0000-000000000002"
            self.assert_code("store_identity_mismatch", evidence.EvidenceReader, store, identity)
            item = publication["contents"]["document"]
            assembler = evidence.DocumentAssembler(item["evidence_handle"], item["document_sha256"])
            offset, pages = 0, 0
            while True:
                frame = reader.read_page(self.request(publication, offset=offset))
                page = json.loads(frame)
                self.assertEqual(page["source_binding"]["identity"]["clock_identity"], clock)
                self.assertEqual(page["source_binding"]["identity"]["role"], "single")
                self.assertIs(page["source_limits"]["native_capture_verified"], False)
                self.assertIs(page["source_limits"]["write_precondition_eligible"], False)
                self.assertIsNone(page["source_limits"]["model_received"])
                status = assembler.add(frame)
                pages += 1
                if page["next_offset"] is None:
                    break
                offset = page["next_offset"]
            self.assertEqual(pages, 3)
            self.assertEqual(assembler.finish(), document)
            self.assertIs(status["transport_complete"], True)
            self.assertIsNone(status["source_limits"]["business_result"])

    def mutate_file(self, path, raw):
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)

    def pending_paths(self):
        return list((self.store / "objects").glob("stage-*"))

    def published_paths(self):
        return [path for path in (self.store / "objects").iterdir() if evidence.HEX.fullmatch(path.name)]

    def test_archived_public_documents_reassemble_exact_original_bytes(self):
        sources = json.loads((ROOT / "FIXTURE_SOURCE_BINDING.json").read_bytes())
        expected_pages = [1, 3]
        for index, source in enumerate(sources["files"]):
            with self.subTest(document=source["installed_fixture"]):
                raw = (ROOT / source["installed_fixture"]).read_bytes()
                self.assertEqual(len(raw), source["bytes"])
                self.assertEqual(evidence.digest(raw), source["sha256"])
                published, _ = self.publish(raw, generation=index)
                assembled, pages = self.assemble(published)
                self.assertEqual(assembled, raw)
                self.assertEqual(len(pages), expected_pages[index])
                self.assertFalse(pages[0]["source_limits"]["native_capture_verified"])
                self.assertEqual(pages[0]["source_binding"]["semantic_validation_status"], "not_performed")

    def test_binary_over_one_mebibyte_tail_and_empty_stderr(self):
        raw = bytes(range(256)) * 4097 + b"\x00\xff\xe4\xb8\xad\n\n"
        self.assertGreater(len(raw), 1024 * 1024)
        stdout, stderr = b"raw stdout\x00\xff\n\n", b""
        published, _ = self.publish(raw, stdout, stderr)
        assembled, pages = self.assemble(published)
        self.assertEqual(assembled, raw)
        self.assertEqual(pages[-1]["returned_bytes"], len(raw) % evidence.CHUNK_BYTES)
        self.assertEqual(self.assemble(published, "stdout")[0], stdout)
        empty, empty_pages = self.assemble(published, "stderr")
        self.assertEqual(empty, b"")
        self.assertEqual(empty_pages[0]["returned_bytes"], 0)
        self.assertEqual(empty_pages[0]["fragment_sha256"], hashlib.sha256(b"").hexdigest())

    def test_wrong_identity_digest_and_extra_path_fields_are_rejected(self):
        published, binding = self.publish(b"original")
        wrong = copy.deepcopy(self.identity)
        wrong["attempt_id"] = "different-attempt"
        self.assert_code("store_identity_mismatch", evidence.EvidenceReader, self.store, wrong)
        foreign = self.base / "foreign"
        evidence.create_store(foreign, wrong)
        with evidence.EvidenceReader(foreign, wrong) as reader:
            self.assert_code("unknown_evidence_handle", reader.read_page, self.request(published))
        request = self.request(published)
        request["expected_document_sha256"] = "0" * 64
        self.assert_code("expected_document_digest_mismatch", self.reader.read_page, request)
        for extra in ("path", "attempt_id", "role", "database_generation", "budget", "callback"):
            request = {**self.request(published), extra: "not-an-authority"}
            self.assert_code("page_request_fields_invalid", self.reader.read_page, request)
        binding["identity"] = wrong
        self.assert_code("source_identity_mismatch", self.publisher.publish_capture,
            document_bytes=b"original", stdout_bytes=b"controlled local stdout\n", stderr_bytes=b"", source_binding=binding)

    def test_ranges_reject_bool_negative_zero_count_and_out_of_bounds(self):
        published, _ = self.publish(b"abc")
        cases = [("offset", True), ("offset", False), ("offset", -1), ("offset", 0.0),
                 ("count", True), ("count", False), ("count", -1), ("count", 0),
                 ("count", 6145), ("count", "1"), ("offset", []), ("count", {})]
        for key, bad in cases:
            with self.subTest(key=key, value=bad):
                request = self.request(published)
                request[key] = bad
                self.assert_code("page_range_invalid", self.reader.read_page, request)
        self.assert_code("page_offset_out_of_bounds", self.reader.read_page, self.request(published, offset=4))
        tail = json.loads(self.reader.read_page(self.request(published, offset=2)))
        self.assertEqual(tail["returned_bytes"], 1)
        self.assertEqual(base64.b64decode(tail["fragment"]), b"c")
        end = json.loads(self.reader.read_page(self.request(published, offset=3)))
        self.assertEqual(end["returned_bytes"], 0)
        self.assertIsNone(end["transport_complete"])

    def test_incomplete_unsettled_and_byte_mismatch_cannot_publish(self):
        binding = fixture_binding(self.identity, b"abc", b"stdout", b"")
        cases = [("source_complete", False, "incomplete_source_not_publishable"),
                 ("capture_complete", False, "incomplete_source_not_publishable"),
                 ("source_complete", 1, "incomplete_source_not_publishable"),
                 ("settlement_status", "unknown", "unsettled_source_not_publishable"),
                 ("document_bytes", 4, "supplied_content_binding_mismatch"),
                 ("stderr_sha256", "0" * 64, "supplied_content_binding_mismatch")]
        for key, value, code in cases:
            with self.subTest(field=key):
                changed = copy.deepcopy(binding)
                changed[key] = value
                self.assert_code(code, self.publisher.publish_capture, document_bytes=b"abc",
                    stdout_bytes=b"stdout", stderr_bytes=b"", source_binding=changed)
        self.assertEqual(list((self.store / "objects").iterdir()), [])
        self.assertEqual(self.pending_paths(), [])

    def test_historical_generations_remain_readable_without_freshness(self):
        first, old_binding = self.publish(b"old bytes", generation=2)
        old_frame = self.reader.read_page(self.request(first))
        second, _ = self.publish(b"new bytes", generation=3)
        self.assertNotEqual(first["bundle_sha256"], second["bundle_sha256"])
        self.assertEqual(self.reader.read_page(self.request(first)), old_frame)
        old = json.loads(old_frame)
        self.assertEqual(old["source_binding"], old_binding)
        self.assertEqual(old["source_binding"]["database_generation"], 2)
        self.assertFalse(old["source_limits"]["write_precondition_eligible"])
        self.assertFalse(old["source_limits"]["currentness_assessed"])
        self.assertFalse(old["source_limits"]["capture_digest_verified"])
        self.assertNotEqual(old_binding["capture_sha256"], old_binding["stdout_sha256"])
        self.assertEqual(self.assemble(second)[0], b"new bytes")

    def test_cross_block_page_checks_both_whole_touched_blocks(self):
        raw = b"a" * evidence.CHUNK_BYTES + b"b" * evidence.CHUNK_BYTES + b"c"
        published, _ = self.publish(raw)
        request = self.request(published, offset=evidence.CHUNK_BYTES - 3, count=10)
        page = json.loads(self.reader.read_page(request))
        self.assertEqual(base64.b64decode(page["fragment"]), raw[evidence.CHUNK_BYTES - 3:evidence.CHUNK_BYTES + 7])
        path = self.store / "objects" / published["bundle_sha256"] / "document.bin"
        changed = bytearray(raw)
        changed[2 * evidence.CHUNK_BYTES - 1] ^= 1  # Outside the requested slice, inside its second block.
        self.mutate_file(path, changed)
        self.assert_code("requested_content_block_changed", self.reader.read_page, request)

    def test_unread_block_boundary_and_duplicate_full_verification(self):
        raw = b"a" * evidence.CHUNK_BYTES + b"b" * evidence.CHUNK_BYTES
        published, binding = self.publish(raw)
        path = self.store / "objects" / published["bundle_sha256"] / "document.bin"
        changed = raw[:-1] + b"!"
        self.mutate_file(path, changed)
        first = json.loads(self.reader.read_page(self.request(published, count=1)))
        self.assertEqual(base64.b64decode(first["fragment"]), b"a")
        self.assertEqual(first["integrity_scope"], "manifest_and_requested_blocks_only")
        self.assertIsNone(first["transport_complete"])
        self.assert_code("requested_content_block_changed", self.reader.read_page,
                         self.request(published, offset=evidence.CHUNK_BYTES, count=1))
        self.assert_code("existing_object_chunk_changed", self.publisher.publish_capture,
            document_bytes=raw, stdout_bytes=b"controlled local stdout\n", stderr_bytes=b"", source_binding=binding)
        self.assertEqual(path.read_bytes(), changed)
        self.assertEqual(self.pending_paths(), [])

    def test_symlink_length_and_manifest_tampering_fail_closed(self):
        for mutation in ("symlink", "length", "manifest"):
            with self.subTest(mutation=mutation):
                published, _ = self.publish(mutation.encode(), generation=len(mutation))
                directory = self.store / "objects" / published["bundle_sha256"]
                content = directory / "document.bin"
                if mutation == "symlink":
                    outside = self.base / "outside.txt"
                    outside.write_bytes(b"not public evidence")
                    directory.chmod(0o700)
                    content.unlink()
                    content.symlink_to(outside)
                    directory.chmod(0o500)
                    with self.assertRaises(OSError):
                        self.reader.read_page(self.request(published))
                    self.assertEqual(outside.read_bytes(), b"not public evidence")
                elif mutation == "length":
                    self.mutate_file(content, b"short")
                    self.assert_code("sealed_file_length_changed", self.reader.read_page, self.request(published))
                else:
                    self.mutate_file(directory / "manifest.json", (directory / "manifest.json").read_bytes() + b" ")
                    self.assert_code("sealed_manifest_digest_mismatch", self.reader.read_page, self.request(published))

    def test_directory_descriptor_survives_parent_path_replacement(self):
        published, _ = self.publish(b"original anchored bytes")
        moved = self.base / "original-store-moved"
        self.store.rename(moved)
        evidence.create_store(self.store, self.identity)
        self.assertEqual(self.assemble(published)[0], b"original anchored bytes")
        with evidence.EvidenceReader(self.store, self.identity) as replacement:
            self.assert_code("unknown_evidence_handle", replacement.read_page, self.request(published))

    def test_concurrent_republish_and_reads_preserve_original_inode(self):
        raw = b"concurrent immutable evidence" * 400
        published, binding = self.publish(raw)
        directory = self.store / "objects" / published["bundle_sha256"]
        inode = directory.stat().st_ino
        with evidence.TrustedPublisher(self.store, self.identity) as another:
            def job(index):
                if index % 3 == 0:
                    return self.reader.read_page(self.request(published))
                publisher = self.publisher if index % 3 == 1 else another
                value = publisher.publish_capture(document_bytes=raw, stdout_bytes=b"controlled local stdout\n",
                    stderr_bytes=b"", source_binding=binding)
                self.assertEqual(value, published)
                return value
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(job, range(18)))
        self.assertEqual(len(results), 18)
        self.assertEqual(directory.stat().st_ino, inode)
        self.assertEqual(len(list((self.store / "objects").iterdir())), 1)
        self.assertEqual(self.pending_paths(), [])

    def test_failed_publish_cleans_only_its_own_pending_directory(self):
        orphan = self.store / "objects" / "stage-existing-orphan"
        orphan.mkdir(mode=0o700)
        (orphan / "unrelated.txt").write_bytes(b"keep old partial publication")
        with patch.object(evidence.os, "rename", side_effect=OSError("controlled rename failure")):
            with self.assertRaises(OSError):
                self.publish(b"new failed publication")
        self.assertEqual((orphan / "unrelated.txt").read_bytes(), b"keep old partial publication")
        self.assertEqual([p.name for p in self.pending_paths()], [orphan.name])
        self.assertEqual(self.published_paths(), [])
        malformed = {"evidence_handle": "pending/stage-existing-orphan", "expected_document_sha256": "0" * 64,
                     "offset": 0, "count": 1}
        self.assert_code("page_handle_or_digest_invalid", self.reader.read_page, malformed)

    def crash_worker(self, when):
        raw, stdout, stderr = b"controlled subprocess original bytes", b"fixture stdout\n", b""
        binding = fixture_binding(self.identity, raw, stdout, stderr)
        script = """
import base64,json,os,sys
sys.path.insert(0,sys.argv[1])
import public_evidence as e
v=json.loads(sys.stdin.buffer.read())
p=e.TrustedPublisher(sys.argv[2],v['binding']['identity'])
rename=e.os.rename
def crash(src,dst,**kwargs):
    if sys.argv[3]=='after': rename(src,dst,**kwargs)
    print(dst,flush=True)
    os._exit(73)
e.os.rename=crash
p.publish_capture(document_bytes=base64.b64decode(v['document']),stdout_bytes=base64.b64decode(v['stdout']),stderr_bytes=b'',source_binding=v['binding'])
"""
        payload = {"document": base64.b64encode(raw).decode(), "stdout": base64.b64encode(stdout).decode(), "binding": binding}
        result = subprocess.run([sys.executable, "-B", "-c", script, str(ROOT), str(self.store), when],
            input=evidence.canonical(payload), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        bundle = result.stdout.decode().strip()
        self.assertRegex(bundle, r"^[0-9a-f]{64}$")
        return bundle, raw, stdout, stderr, binding

    def test_process_crash_before_atomic_rename_is_not_public(self):
        bundle, raw, stdout, stderr, binding = self.crash_worker("before")
        request = {"evidence_handle": "ep1:" + bundle + ":document",
                   "expected_document_sha256": evidence.digest(raw), "offset": 0, "count": 6144}
        self.assert_code("unknown_evidence_handle", self.reader.read_page, request)
        orphans = {p.name for p in self.pending_paths()}
        self.assertEqual(len(orphans), 1)
        published = self.publisher.publish_capture(document_bytes=raw, stdout_bytes=stdout, stderr_bytes=stderr, source_binding=binding)
        self.assertEqual(published["bundle_sha256"], bundle)
        self.assertEqual(self.assemble(published)[0], raw)
        self.assertEqual({p.name for p in self.pending_paths()}, orphans)

    def test_process_crash_after_rename_reuses_verified_complete_object(self):
        bundle, raw, stdout, stderr, binding = self.crash_worker("after")
        directory = self.store / "objects" / bundle
        inode = directory.stat().st_ino
        published = self.publisher.publish_capture(document_bytes=raw, stdout_bytes=stdout, stderr_bytes=stderr, source_binding=binding)
        self.assertEqual(published["bundle_sha256"], bundle)
        self.assertEqual(directory.stat().st_ino, inode)
        self.assertEqual(self.assemble(published)[0], raw)

    def test_oversized_metadata_rejected_and_existing_directory_never_replaced(self):
        binding = fixture_binding(self.identity, b"abc", b"stdout", b"")
        binding["coverage"] = {"large_public_metadata": "x" * 65536}
        self.assert_code("response_frame_exceeds_65536", self.publisher.publish_capture,
            document_bytes=b"abc", stdout_bytes=b"stdout", stderr_bytes=b"", source_binding=binding)
        self.assertEqual(self.pending_paths(), [])
        binding = fixture_binding(self.identity, b"abc", b"stdout", b"")
        # A pre-existing invalid directory is not silently overwritten, either.
        manifest = evidence._manifest(binding, {"document": b"abc", "stdout": b"stdout", "stderr": b""})
        bundle = evidence.digest(evidence.canonical(manifest) + b"\n")
        occupied = self.store / "objects" / bundle
        occupied.mkdir(mode=0o500)
        before = occupied.stat().st_ino
        self.assert_code("sealed_object_members_changed", self.publisher.publish_capture,
            document_bytes=b"abc", stdout_bytes=b"stdout", stderr_bytes=b"", source_binding=binding)
        self.assertEqual(occupied.stat().st_ino, before)
        self.assertEqual(list(occupied.iterdir()), [])

    def test_assembler_rejects_tail_only_changed_binding_and_changed_full_hash(self):
        raw = b"a" * evidence.CHUNK_BYTES + b"tail"
        published, _ = self.publish(raw)
        item = published["contents"]["document"]
        assembly = evidence.DocumentAssembler(item["evidence_handle"], item["document_sha256"])
        tail = self.reader.read_page(self.request(published, offset=evidence.CHUNK_BYTES))
        self.assert_code("assembly_page_sequence_gap_or_replay", assembly.add, tail)
        self.assert_code("document_transport_incomplete", assembly.finish)
        first = self.reader.read_page(self.request(published))
        assembly.add(first)
        changed = json.loads(tail)
        changed["source_binding"]["database_generation"] += 1
        self.assert_code("assembly_source_binding_changed", assembly.add, evidence.canonical(changed) + b"\n")
        changed = json.loads(tail)
        fragment = b"FAIL"
        changed["fragment"] = base64.b64encode(fragment).decode()
        changed["fragment_sha256"] = evidence.digest(fragment)
        self.assert_code("assembled_document_digest_mismatch", assembly.add, evidence.canonical(changed) + b"\n")
        self.assertFalse(assembly.status()["transport_complete"])


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
    def addSuccess(self, test):
        self.records.append({"test": test.id(), "status": "passed"})
        super().addSuccess(test)
    def addFailure(self, test, err):
        self.records.append({"test": test.id(), "status": "failed"})
        super().addFailure(test, err)
    def addError(self, test, err):
        self.records.append({"test": test.id(), "status": "error"})
        super().addError(test, err)
    def addSkip(self, test, reason):
        self.records.append({"test": test.id(), "status": "skipped", "reason": reason})
        super().addSkip(test, reason)
    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.records.append({"test": test.id(), "subtest": subtest.id(),
                "status": "failed" if issubclass(err[0], test.failureException) else "error"})
        super().addSubTest(test, subtest, err)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidencePagesTests)
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    with sqlite3.connect(":memory:") as connection:
        sqlite_source_id = connection.execute("SELECT sqlite_source_id()").fetchone()[0]
    report = {"schema": "b1-evidence-pages-local-test-result-v1",
        "passed": result.wasSuccessful() and not result.skipped, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "tests": result.records, "runtime": {"python": sys.version, "implementation": platform.python_implementation(),
        "executable": sys.executable, "resolved_executable": str(Path(sys.executable).resolve()),
        "sqlite_version": sqlite3.sqlite_version, "sqlite_source_id": sqlite_source_id, "uid": os.getuid(), "gid": os.getgid()},
        "qualification_scope": "controlled_local_files_and_subprocess_crash_only",
        "fixed_python_3_11_runtime_qualified": False, "aios_qualified": False, "actor_integrated": False,
        "model_calls": 0, "native_business_calls": 0, "business_result": None}
    print(json.dumps(report, sort_keys=True, ensure_ascii=False), flush=True)
    raise SystemExit(0 if report["passed"] is True else 1)
