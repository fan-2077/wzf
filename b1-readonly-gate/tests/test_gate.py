"""Local fixtures only: no model, AIOS service, native incident, or network call.

Real generated Cerebrum query/response classes and send_request are used in the
schema/transport fixture. Transport returns explicit fixture bodies, so these
tests cannot establish a real model qualification or recovery result.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import b1_metering as metering
from build_overlay import build, verified_base, BASE_MANIFEST_SHA256, sha


def query():
    return {"request_id": uuid.uuid4().hex,
        "messages": [{"role": "user", "content": "EXPLICIT LOCAL FIXTURE ONLY"}],
        "temperature": 0.0, "max_new_tokens": 192, "message_return_type": "json",
        "response_format": {"type": "json_object"},
        "action_type": "chat_with_json_output", "tools": []}


class AccountingFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="b1-accounting-fixture-")
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(os.environ, {"G1_LOG_DIR": str(self.root), "G1_ATTEMPT_ID": "fixture-not-a-model-run"})
        self.environment.start()
        self.ledger = metering.Ledger.create(self.root / "b1-metering", "fixture-not-a-model-run")

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def start(self, value=None):
        value = value or query()
        rid = self.ledger.reserve(value)
        self.ledger.record_sdk_start(rid, "llm", metering.canonical({"fixture": True, "query_data": value}))
        self.ledger.begin_dispatch(value)
        body = {"model": metering.MODEL_NAME, "messages": value["messages"],
            "max_tokens": value["max_new_tokens"], "temperature": value["temperature"],
            "response_format": value["response_format"]}
        self.ledger.wire_request(rid, metering.canonical(body))
        return rid

    def complete(self, usage=None):
        rid = self.start()
        payload = {"id": "fixture-response", "model": metering.MODEL_NAME,
            "object": "chat.completion", "choices": [{"finish_reason": "stop"}], "fixture": True}
        if usage is not None:
            payload["usage"] = usage
        self.ledger.wire_response(rid, metering.canonical(payload), 200)
        self.ledger.record_sdk_end(rid, metering.canonical({"fixture": True}), 200)
        return rid

    def test_three_completed_reservations_exhaust_fourth(self):
        for _ in range(3):
            self.complete({"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27})
        with self.assertRaisesRegex(ValueError, "aggregate_model_budget_exhausted"):
            self.ledger.reserve(query())
        summary = self.ledger.summary()
        self.assertEqual(summary["reserved_output_tokens"], 576)
        self.assertEqual(summary["usage_totals"]["total_tokens"]["complete_total"], 81)
        self.assertTrue(summary["raw_model_io_complete"])
        self.assertTrue(summary["usage_complete"])

    def test_disconnect_remains_unknown_across_ledger_reopen(self):
        rid = self.start()
        self.ledger.uncertain(rid, TimeoutError("explicit fixture disconnect"))
        reopened = metering.Ledger(self.root / "b1-metering")
        with self.assertRaisesRegex(ValueError, "prior_model_execution_unresolved"):
            reopened.reserve(query())
        summary = reopened.summary()
        self.assertEqual(summary["reserved_model_requests"], 1)
        self.assertEqual(summary["reserved_output_tokens"], 192)
        self.assertEqual(summary["states"]["unknown"], 1)
        self.assertEqual(summary["reservations_ever_refunded"], 0)
        self.assertFalse(summary["raw_model_io_complete"])
        self.assertIsNone(summary["usage_totals"]["completion_tokens"]["complete_total"])

    def test_missing_usage_stays_unknown_despite_complete_body(self):
        rid = self.complete()
        summary = self.ledger.summary()
        self.assertTrue(summary["raw_model_io_complete"])
        self.assertFalse(summary["usage_complete"])
        self.assertEqual(summary["usage_totals"]["total_tokens"]["unknown_requests"], 1)
        self.assertIsNone(summary["usage_totals"]["total_tokens"]["complete_total"])
        self.assertIsNone(json.loads(self.ledger.receipt(rid)["usage_json"])["raw"])

    def test_known_backend_response_not_erased_by_client_disconnect(self):
        rid = self.complete({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3})
        self.ledger.uncertain(rid, ConnectionError("explicit late client disconnect"))
        record = self.ledger.receipt(rid)
        self.assertEqual(record["state"], "response_received")
        self.assertEqual(json.loads(record["usage_json"])["counts"]["total_tokens"], 3)
        self.assertEqual(self.ledger.summary()["reserved_output_tokens"], 192)

    def test_changed_request_and_duplicate_dispatch_rejected(self):
        value = query()
        rid = self.ledger.reserve(value)
        self.ledger.record_sdk_start(rid, "llm", metering.canonical({"fixture": True}))
        changed = dict(value, max_new_tokens=191)
        with self.assertRaisesRegex(ValueError, "model_reservation_missing_changed_or_consumed"):
            self.ledger.begin_dispatch(changed)
        self.ledger.begin_dispatch(value)
        with self.assertRaisesRegex(ValueError, "model_reservation_missing_changed_or_consumed"):
            self.ledger.begin_dispatch(value)

    def test_raw_body_tampering_invalidates_evidence(self):
        rid = self.complete()
        (self.root / "b1-metering/model" / rid / "response.json").write_bytes(b"{}")
        summary = self.ledger.summary()
        self.assertFalse(summary["raw_model_io_complete"])
        self.assertEqual(summary["evidence_errors"], [{"request_id": rid, "kind": "model", "part": "response"}])

    def test_provider_output_overrun_is_visible(self):
        rid = self.complete({"prompt_tokens": 1, "completion_tokens": 193, "total_tokens": 194})
        self.assertEqual(self.ledger.summary()["usage_budget_violations"],
            [{"request_id": rid, "kind": "output_exceeds_reservation"}])

    def test_actual_httpx_hooks_preserve_application_bodies_with_fixture_transport(self):
        import httpx
        value = query()
        rid = self.ledger.reserve(value)
        self.ledger.record_sdk_start(rid, "llm", metering.canonical({"fixture": True}))
        self.ledger.begin_dispatch(value)
        request_body = json.dumps({"model": metering.MODEL_NAME, "messages": value["messages"],
            "max_tokens": 192, "temperature": 0.0, "response_format": {"type": "json_object"}}, indent=2).encode()
        response_body = b'{ "id": "explicit-fixture", "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14} }'
        metering.LOCAL.request_id = rid
        try:
            with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=response_body)),
                    trust_env=False, event_hooks={"request": [metering._wire_request], "response": [metering._wire_response]}) as client:
                reply = client.post(metering.MODEL_ORIGIN + "/chat/completions", content=request_body,
                    headers={"X-B1-Request-ID": rid, "Content-Type": "application/json"})
                self.assertEqual(reply.content, response_body)
        finally:
            metering.LOCAL.request_id = None
        self.assertEqual((self.root / "b1-metering/model" / rid / "request.json").read_bytes(), request_body)
        self.assertEqual((self.root / "b1-metering/model" / rid / "response.json").read_bytes(), response_body)
        self.assertEqual(json.loads(self.ledger.receipt(rid)["usage_json"])["counts"]["total_tokens"], 14)
        # There is still no real SDK/kernel response, so this fixture cannot pass the gate.
        self.assertFalse(self.ledger.summary()["raw_model_io_complete"])

    def test_invalid_usage_never_coerced_to_zero_or_integer(self):
        value = metering.normalize_usage({"prompt_tokens": True, "completion_tokens": -1, "total_tokens": 1.2})
        self.assertEqual(value["counts"], {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None})
        inconsistent = metering.normalize_usage({"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 999})
        self.assertEqual(inconsistent["status"], "inconsistent_provider_usage")

    def test_remote_and_redirect_destinations_rejected_before_network(self):
        with self.assertRaisesRegex(ValueError, "readonly_gate_permits_only_pinned_local_model"):
            metering.build_local_client("https://example.invalid/v1", "fixture-no-key")
        with self.assertRaisesRegex(ValueError, "readonly_sdk_destination_invalid"):
            metering.sdk_post("https://example.invalid", "/query", {})


class OriginalSDKOverlayFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="b1-overlay-fixture-")
        cls.destination = Path(cls.temporary.name) / "generated"
        cls.base = HERE.parent / "g1-smoke"
        cls.branch = "sre-b1-readonly-20261119"
        cls.result = build(cls.base, cls.destination, cls.branch)
        cls.paths = [str(cls.destination / "payload/sdk"), str(cls.destination / "payload/integration"),
                     str(cls.destination)]
        sys.path[:0] = cls.paths
        cls.apis = importlib.import_module("cerebrum.llm.apis")
        cls.communication = importlib.import_module("cerebrum.utils.communication")
        cls.client = importlib.import_module("g1_sdk_client")

    @classmethod
    def tearDownClass(cls):
        for path in cls.paths:
            sys.path.remove(path)
        cls.temporary.cleanup()

    def test_full_frozen_manifest_unchanged_and_generated_package_bound(self):
        verified_base(self.base)
        self.assertEqual(sha(self.base / "PACKAGE_MANIFEST.json"), BASE_MANIFEST_SHA256)
        manifest = json.loads((self.destination / "PACKAGE_MANIFEST.json").read_text())
        actual = {str(path.relative_to(self.destination)) for path in self.destination.rglob("*")
                  if path.is_file() and path != self.destination / "PACKAGE_MANIFEST.json"}
        self.assertEqual(actual, set(manifest["files"]))
        for name, expected in manifest["files"].items():
            self.assertEqual(sha(self.destination / name), expected)
        self.assertFalse(self.result["model_api_called"])
        self.assertFalse(self.result["remote_executed"])

    def test_original_sdk_fields_and_send_request_with_fixture_transport(self):
        import requests
        with tempfile.TemporaryDirectory(prefix="b1-sdk-fixture-") as folder:
            with patch.dict(os.environ, {"G1_LOG_DIR": folder, "G1_ATTEMPT_ID": "fixture-sdk"}):
                ledger = metering.Ledger.create(Path(folder) / "b1-metering", "fixture-sdk")
                value = self.apis.LLMQuery(**query())
                rid = ledger.reserve(value)
                raw_usage = {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25,
                             "prompt_tokens_details": {"cached_tokens": 3}}
                response_object = self.apis.LLMResponse(request_id=rid, response_message='{"fixture":true}',
                    usage=raw_usage, model_metadata={"fixture": True}, finished=True)
                response_body = metering.canonical({"response": response_object.model_dump()})
                captured = []

                def fixture_send(session, prepared, **options):
                    captured.append((prepared, options, session.trust_env))
                    response = requests.Response()
                    response.status_code = 200
                    response._content = response_body
                    response.request = prepared
                    return response

                with patch.object(requests.Session, "send", fixture_send):
                    result = self.communication.send_request("fixture-only", value, base_url=metering.KERNEL_ORIGIN)
                self.assertEqual(result["response"]["request_id"], rid)
                self.assertEqual(result["response"]["usage"], raw_usage)
                self.assertEqual(len(captured), 1)
                self.assertFalse(captured[0][1]["allow_redirects"])
                self.assertFalse(captured[0][2])
                saved = (Path(folder) / "b1-metering/sdk" / rid / "request.json").read_bytes()
                self.assertEqual(saved, captured[0][0].body)
                self.assertEqual(json.loads(saved)["query_data"]["request_id"], rid)
                self.assertEqual((Path(folder) / "b1-metering/sdk" / rid / "response.json").read_bytes(), response_body)
                # The fixture has no backend result: it must never qualify as a model run.
                self.assertFalse(ledger.summary()["raw_model_io_complete"])

    def test_feedback_echo_rejects_stale_document_even_with_correct_shape(self):
        feedback = {"document_sha256": "a" * 64, "row_counts": {"issues": 30, "notifications": 30}}
        self.client.verify_echo({"observed_sha256": "a" * 64,
            "observed_row_counts": {"issues": 30, "notifications": 30}}, feedback)
        with self.assertRaisesRegex(ValueError, "actual_feedback_binding"):
            self.client.verify_echo({"observed_sha256": "b" * 64,
                "observed_row_counts": {"issues": 30, "notifications": 30}}, feedback)

    def test_actual_host_guards_accept_new_ref_reject_old_ref_without_infrastructure(self):
        runner = importlib.import_module("run_remote_smoke")
        native = importlib.import_module("native_g1_entry")
        cleanup = importlib.import_module("cleanup_owned")
        exporter = importlib.import_module("export_owned_evidence")
        sealer = importlib.import_module("seal_remote_evidence")

        class StopBeforeNativeOutput(RuntimeError):
            """Stop after the actual native guard, before any native resources."""

        with tempfile.TemporaryDirectory(prefix="b1-host-guard-fixture-") as folder:
            base_env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": "fan-2077/wzf",
                "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKSPACE": folder,
                "RUNNER_TEMP": folder, "G1_RESULTS": str(Path(folder) / "native-fixture")}
            for accepted, ref in ((True, "refs/heads/" + self.branch),
                                  (False, "refs/heads/sre-g1-connection-20261116")):
                with self.subTest(ref=ref), patch.dict(os.environ, dict(base_env, GITHUB_REF=ref)):
                    if accepted:
                        runner.configure()  # Actual guard and package verification; no deployment.
                        self.assertEqual(runner.infra.REF, ref)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "GITHUB_REF"):
                            runner.configure()
                    with patch.object(Path, "mkdir", side_effect=StopBeforeNativeOutput):
                        expected = StopBeforeNativeOutput if accepted else RuntimeError
                        with self.assertRaises(expected) as caught:
                            asyncio.run(native.main())
                        if not accepted:
                            self.assertIn("GITHUB_REF", str(caught.exception))
                    with patch.object(cleanup, "names", return_value=[]), \
                         patch.object(cleanup.HostIngressGuard, "active_listeners", return_value=[]):
                        if accepted:
                            claim = cleanup.claim(Path(folder) / "fixture-ownership.json",
                                work=Path(folder) / "fixture-work", cluster="fixture-not-created")
                            self.assertEqual(claim["identity"]["GITHUB_REF"], ref)
                        else:
                            with self.assertRaisesRegex(RuntimeError, "reviewed hosted run"):
                                cleanup.claim(Path(folder) / "must-not-exist.json",
                                    work=Path(folder) / "fixture-work", cluster="fixture-not-created")
                    if accepted:
                        context = exporter.context(uid=1001, gid=1001)
                        self.assertEqual(context["identity"]["GITHUB_REF"], ref)
                        self.assertFalse(context["diagnostic"])
                    else:
                        with self.assertRaises(exporter.ExportError):
                            exporter.context(uid=1001, gid=1001)
        verdict = sealer.build_verdict({}, {})
        self.assertEqual(verdict["scope"], "unscored B1 readonly multi-turn feedback engineering qualification")
        self.assertFalse(verdict["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
