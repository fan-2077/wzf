"""Connection-double tests + separate critical real Unix socket tests.

Owner, SQLite and controlled child processes are real. All other transport
tests use an explicitly scripted connection double, never a claimed IPC run.
No model, native recovery, AIOS service or remote service is executed.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import session_client as client_module
from session_client import (ClientError, HostConfiguration, SessionClient,
                            canonical, digest, IDENTITY_SCHEMA, RESPONSE_SCHEMA, RESPONSE_LIMIT)
from session_owner import SessionOwner
from sdk_tool import Tool, TOOL_NAME, TOOL_OPERATIONS, TOOL_PARAMETER_SCHEMA

RID = "1" * 32
PARENT = "a" * 32


def identity_binding():
    return {"attempt_id": "local-controlled-attempt", "physical_scope_id": "local-fixture-scope",
            "ledger_epoch": "local-ledger-epoch", "namespace_uid": "local-namespace-uid",
            "role": "single", "launch_context_sha256": "c" * 64,
            "derived_payload_binding_sha256": "d" * 64}


def start(rid=RID, parent=PARENT):
    return {"operation": "start", "request_id": rid, "parent_model_request_id": parent}


def poll(helper_id, rid=RID):
    return {"operation": "poll", "request_id": rid, "helper_id": helper_id}


class RecordingOwner(SessionOwner):
    def handle(self, request, *, raw=None):
        self.observed_requests.append(raw)
        response = super().handle(request, raw=raw)
        if self.drop_next_response:
            self.drop_next_response = False
            raise ConnectionResetError("fixture_dropped_reply_after_real_owner_acceptance")
        delay, self.delay_next_response = self.delay_next_response, 0
        if delay:
            time.sleep(delay)
        return response


class ConnectionDouble:
    """A byte-stream/timeout double; this is not an operating-system socket."""
    def __init__(self, responder, expected_path):
        self.responder, self.expected_path = responder, str(expected_path)
        self.timeout, self.buffer, self.parts, self.failure = None, b"", iter(()), None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        if path != self.expected_path:
            raise AssertionError("client changed host-owned endpoint")

    def sendall(self, raw):
        try:
            self.parts = iter(self.responder(raw))
        except OSError as error:
            # Model a reply loss after the owner's acceptance, not a resend.
            self.failure = error

    def recv(self, maximum):
        if self.failure is not None:
            raise self.failure
        while not self.buffer:
            item = next(self.parts, b"")
            if isinstance(item, tuple):
                _, delay = item
                time.sleep(min(delay, self.timeout))
                if delay >= self.timeout:
                    raise TimeoutError("scripted receive timeout")
                continue
            self.buffer = item
            if not item:
                return b""
        result, self.buffer = self.buffer[:maximum], self.buffer[maximum:]
        return result


def double_socket(responder, path):
    def create(family, kind):
        if (family, kind) != (socket.AF_UNIX, socket.SOCK_STREAM):
            raise AssertionError("client changed transport kind")
        return ConnectionDouble(responder, path)
    return mock.patch.object(client_module.socket, "socket", side_effect=create)


class LocalOwner:
    """Real owner/SQLite/child; connection double unless real_socket=True."""
    def __init__(self, root, *, real_socket=False):
        self.root = root
        self.real_socket = real_socket
        self.gate = root / "release-fixture-child"
        self.result = root / "fixture-result.json"
        self.children = []
        self.launches = 0
        self.errors = []

        def launch(_reservation, stdout, stderr):
            self.launches += 1
            code = (
                "import json,pathlib,sys,time\n"
                "result,gate=map(pathlib.Path,sys.argv[1:3])\n"
                "deadline=time.monotonic()+10\n"
                "while not gate.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                "result.write_text(json.dumps({'attempt_id':sys.argv[3],'status':'fixture_completed'}))\n"
            )
            child = subprocess.Popen([sys.executable, "-B", "-c", code, str(self.result),
                                      str(self.gate), identity_binding()["attempt_id"]],
                                     stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     close_fds=True, start_new_session=True)
            self.children.append(child)
            return child

        self.owner = RecordingOwner(root / "owner", identity_binding(), launch, result_path=self.result)
        self.owner.observed_requests = []
        self.owner.drop_next_response = False
        self.owner.delay_next_response = 0
        self.configuration = HostConfiguration(self.owner.root / "session_identity.json",
                                               self.owner.socket_path, root / "receipts", 2.0)

    def __enter__(self):
        if not self.real_socket:
            def respond(raw):
                response = self.owner.handle(json.loads(raw), raw=raw)
                return [canonical(response) + b"\n"]
            self.connection_patch = double_socket(respond, self.owner.socket_path)
            self.connection_constructor = self.connection_patch.start()
            return self
        def serve():
            try:
                self.owner.serve_forever()
            except BaseException as error:
                self.errors.append(error)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 2
        while not self.owner.socket_path.exists() and time.monotonic() < deadline:
            time.sleep(.005)
        if not self.owner.socket_path.exists():
            self.owner.close()
            raise AssertionError("fixture owner did not bind socket")
        return self

    def finish_child(self):
        self.gate.write_text("release only the controlled fixture child")
        for child in self.children:
            child.wait(timeout=3)

    def __exit__(self, *_):
        try:
            self.finish_child()
        finally:
            self.owner.stop()
            if self.real_socket:
                self.thread.join(timeout=3)
            self.owner.close()
            if not self.real_socket:
                self.connection_patch.stop()
            for child in self.children:
                if child.poll() is None:
                    child.kill()  # Fixture teardown only; never a client action.
                    child.wait(timeout=3)
        if (self.real_socket and self.thread.is_alive()) or self.errors:
            raise AssertionError(("fixture owner thread failure", self.errors))


@contextmanager
def fault_endpoint(root, handler, timeout=.06):
    """Scripted byte/timeout double, not actual IPC or a macro execution."""
    socket_path = root / "fault.sock"
    binding = identity_binding()
    helper = "full-" + digest(canonical(binding))
    identity_path = root / "identity.json"
    identity_path.write_bytes(canonical({"schema": IDENTITY_SCHEMA, "helper_id": helper,
        "identity_binding": binding, "socket_path": str(socket_path)}) + b"\n")
    configuration = HostConfiguration(identity_path, socket_path, root / "receipts", timeout)
    requests = []
    def respond(raw):
        requests.append(raw)
        return handler(raw)
    with double_socket(respond, socket_path):
        yield SessionClient(configuration), helper, requests


class SDKFixtureCase(unittest.TestCase):
    real_socket = False

    def setUp(self):
        if self.real_socket:
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            except PermissionError as error:
                detail = f"actual Unix IPC unavailable: {type(error).__name__} errno={error.errno}"
                if os.environ.get("B1_REQUIRE_REAL_IPC") == "1":
                    self.fail(detail + "; B1_REQUIRE_REAL_IPC=1 forbids skipping")
                self.skipTest(detail + "; integration remains pending")
            else:
                probe.close()
        self.temporary = tempfile.TemporaryDirectory(prefix="b1sdk-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def receipt(self, client, response):
        directory = client.configuration.receipts_directory / "exchanges" / response["exchange_id"]
        return (directory / "request.bin").read_bytes(), (directory / "response.bin").read_bytes(), json.loads(
            (directory / "metadata.json").read_bytes())

    def owner_fixture(self):
        return LocalOwner(self.root, real_socket=self.real_socket)


class SDKConnectionDoubleTests(SDKFixtureCase):
    def test_tool_entry_start_and_polls_share_one_real_owner_and_unique_raw_receipts(self):
        with self.owner_fixture() as fixture:
            configuration = fixture.configuration
            environment = {"B1_COMMON_SESSION_IDENTITY_PATH": str(configuration.identity_path),
                           "B1_COMMON_SESSION_SOCKET_PATH": str(configuration.socket_path),
                           "B1_COMMON_SESSION_RECEIPTS_DIR": str(configuration.receipts_directory)}
            with mock.patch.dict(os.environ, environment):
                responses = [json.loads(Tool().run(start()))]
                responses.extend(json.loads(Tool().run(poll(fixture.owner.helper_id))) for _ in range(3))
                fixture.finish_child()
                responses.append(json.loads(Tool().run(poll(fixture.owner.helper_id))))
            self.assertEqual(1, fixture.launches)
            self.assertEqual(["start", "poll", "poll", "poll", "poll"],
                             [json.loads(raw)["operation"] for raw in fixture.owner.observed_requests])
            self.assertEqual(len(responses), len({item["exchange_id"] for item in responses}))
            client = SessionClient(configuration)
            for index, response in enumerate(responses):
                raw_request, raw_response, metadata = self.receipt(client, response)
                self.assertEqual(raw_request, fixture.owner.observed_requests[index])
                self.assertEqual(json.loads(raw_response), response["owner_response"])
                self.assertEqual(digest(raw_request), metadata["request_sha256"])
                self.assertEqual(digest(raw_response), metadata["response_sha256"])
                self.assertEqual(RID, metadata["request_id"])
                self.assertEqual(RID, metadata["owner_original_request_id"])
                self.assertEqual(PARENT, metadata["parent_model_request_id"])
                self.assertFalse(metadata["model_causality_verified"])
                self.assertEqual("caller_declaration_only", response["parent_attribution"])
                self.assertTrue(response["capture_complete"])
                self.assertIsNone(response["business_success"])
                self.assertIsNone(response["original_host_evaluation_result"])
            final = responses[-1]["owner_response"]["session"]
            self.assertEqual("process_exited", final["state"])
            self.assertEqual(0, final["process"]["returncode"])
            self.assertEqual("fixture_completed", final["controller_reported_status"])
            self.assertIsNone(final["business_success"])
            self.assertIsNone(final["original_host_evaluation_result"])
            self.assertEqual(1, final["launch_reservations"])

    def test_accepted_start_reply_loss_is_poll_only_even_with_new_client_instance(self):
        with self.owner_fixture() as fixture:
            fixture.owner.drop_next_response = True
            first = SessionClient(fixture.configuration).invoke(start())
            self.assertEqual("unknown", first["transport_state"])
            self.assertEqual(fixture.owner.helper_id, first["helper_id"])
            self.assertEqual(RID, first["request_id"])
            self.assertEqual("poll", first["next_allowed_operation"])
            self.assertIsNone(fixture.children[0].poll())
            retry = SessionClient(fixture.configuration).invoke(start())
            self.assertEqual("poll", retry["wire_operation"])
            self.assertEqual("running", retry["owner_response"]["session"]["state"])
            self.assertEqual(1, fixture.launches)
            self.assertEqual(["start", "poll"], [json.loads(raw)["operation"]
                             for raw in fixture.owner.observed_requests])

    def test_poll_before_start_never_registers_reservation_or_starts_child(self):
        with self.owner_fixture() as fixture:
            response = SessionClient(fixture.configuration).invoke(poll(fixture.owner.helper_id))
            session = response["owner_response"]["session"]
            self.assertEqual("ready", session["state"])
            self.assertEqual("not_registered", session["request_binding"])
            self.assertEqual(0, session["launch_reservations"])
            self.assertEqual(0, fixture.launches)
            self.assertFalse((fixture.configuration.receipts_directory / "dispatch-claims" / (RID + ".json")).exists())

    def test_request_binding_conflict_and_new_id_cannot_spawn_another_macro(self):
        with self.owner_fixture() as fixture:
            client = SessionClient(fixture.configuration)
            client.invoke(start())
            with self.assertRaisesRegex(ClientError, "request_id_conflict"):
                client.invoke(start(parent="b" * 32))
            self.assertEqual(1, len(fixture.owner.observed_requests))
            new_request = client.invoke(start(rid="2" * 32))
            owner = new_request["owner_response"]
            self.assertEqual("already_reserved_other_request", owner["disposition"])
            self.assertEqual("other_request", owner["session"]["request_binding"])
            self.assertEqual(RID, owner["session"]["original_request_id"])
            self.assertEqual(1, fixture.launches)
            _, _, metadata = self.receipt(client, new_request)
            self.assertEqual("2" * 32, metadata["request_id"])
            self.assertEqual(RID, metadata["owner_original_request_id"])

    def test_concurrent_same_start_is_one_start_and_remaining_polls(self):
        with self.owner_fixture() as fixture:
            with ThreadPoolExecutor(max_workers=4) as pool:
                replies = list(pool.map(lambda _: SessionClient(fixture.configuration).invoke(start()), range(4)))
            self.assertEqual(1, fixture.launches)
            self.assertEqual(1, sum(item["wire_operation"] == "start" for item in replies))
            self.assertEqual(3, sum(item["wire_operation"] == "poll" for item in replies))
            self.assertEqual(4, len({item["exchange_id"] for item in replies}))

    def test_partial_reply_timeout_retains_exact_bytes_and_does_not_retry(self):
        partial = b'{"schema":"partial'
        def handler(_raw):
            return [partial, ("delay", .25)]
        with fault_endpoint(self.root, handler) as (client, helper, requests):
            result = client.invoke(start())
            _, raw_response, metadata = self.receipt(client, result)
            self.assertEqual(partial, raw_response)
            self.assertEqual("unknown", result["transport_state"])
            self.assertEqual("TimeoutError", result["error"]["type"])
            self.assertEqual(helper, result["helper_id"])
            self.assertEqual(1, len(requests))
            self.assertEqual(digest(partial), metadata["response_sha256"])
            self.assertFalse(metadata["response_frame_validated"])
            self.assertEqual(0, metadata["automatic_retries"])
            self.assertFalse(metadata["budget_refund"])

    def test_slow_dribble_cannot_reset_exchange_deadline(self):
        def handler(_raw):
            for _ in range(50):
                yield b"x"
                yield ("delay", .02)
        with fault_endpoint(self.root, handler, timeout=.1) as (client, _helper, requests):
            before = time.monotonic()
            result = client.invoke(start())
            elapsed = time.monotonic() - before
            self.assertLess(elapsed, .7)
            self.assertEqual("TimeoutError", result["error"]["type"])
            self.assertEqual(1, len(requests))
            _, raw_response, _ = self.receipt(client, result)
            self.assertGreater(len(raw_response), 0)
            self.assertLess(len(raw_response), 50)

    def test_oversize_and_multiple_frame_replies_are_unknown_with_raw_prefix_retained(self):
        for name, raw, code in (("oversize", b"x" * (RESPONSE_LIMIT + 10), "owner_response_size_limit"),
                                ("multiple", b"{}\n{}\n", "owner_response_frame_incomplete_or_multiple")):
            with self.subTest(name=name):
                directory = self.root / name
                directory.mkdir()
                with fault_endpoint(directory, lambda _raw: [raw]) as (client, _, _):
                    response = client.invoke(start())
                    _, captured, metadata = self.receipt(client, response)
                    self.assertEqual(code, response["error"]["code"])
                    self.assertEqual(raw[:RESPONSE_LIMIT + 1], captured)
                    self.assertFalse(metadata["response_frame_validated"])

    def test_post_dispatch_receipt_failure_keeps_stable_handle_and_poll_only(self):
        with self.owner_fixture() as fixture:
            real_write = client_module.write_once
            def failing_write(path, raw):
                if path.name == "response.bin":
                    raise OSError("fixture full disk")
                return real_write(path, raw)
            client = SessionClient(fixture.configuration)
            with mock.patch.object(client_module, "write_once", side_effect=failing_write):
                response = client.invoke(start())
            self.assertEqual(fixture.owner.helper_id, response["helper_id"])
            self.assertEqual(RID, response["request_id"])
            self.assertFalse(response["capture_complete"])
            self.assertEqual([{"stage": "response", "type": "OSError"}], response["evidence_errors"])
            self.assertEqual("poll", client.invoke(start())["wire_operation"])
            self.assertEqual(1, fixture.launches)

    def test_host_only_controls_and_second_submit_are_not_tool_arguments(self):
        with self.owner_fixture() as fixture:
            client = SessionClient(fixture.configuration)
            invalid = [None, [], {"operation": []}, {"operation": {}}, {"operation": "submit"},
                       poll("full-" + "0" * 64), {**start(), "role": "script"},
                       {**start(), "endpoint": "/tmp/other.sock"}, {**start(), "path": "/oracle"},
                       {**start(), "budget": 999}, {**start(), "clock": 0},
                       {**start(), "parameters": {"command": "anything"}}]
            for parameters in invalid:
                with self.subTest(parameters=parameters):
                    with self.assertRaises(ClientError):
                        client.invoke(parameters)
                    with mock.patch.object(HostConfiguration, "from_environment", return_value=fixture.configuration):
                        result = json.loads(Tool().run(parameters))
                    self.assertEqual("ClientError", result["error"]["type"])
                    self.assertIsNone(result["business_success"])
            fixture.connection_constructor.assert_not_called()
            self.assertEqual([], fixture.owner.observed_requests)
            self.assertEqual(0, fixture.launches)
            self.assertIn("start_poll", TOOL_NAME)
            self.assertEqual("business_write_full_macro", TOOL_OPERATIONS["start"])
            self.assertEqual("read_only_session_status", TOOL_OPERATIONS["poll"])
            self.assertEqual(2, len(TOOL_PARAMETER_SCHEMA["oneOf"]))

    def test_response_handle_is_opaque_and_never_causes_arbitrary_file_read(self):
        secret = self.root / "private-fixture-file"
        secret.write_text("must never be read by a response-driven path")
        def handler(raw):
            request = json.loads(raw)
            response = {"schema": RESPONSE_SCHEMA, "ok": True, "operation": request["operation"],
                "request_id": request["request_id"], "helper_id": request["helper_id"],
                "disposition": "status", "error": None,
                "session": {"state": "unknown", "launch_reservations": 1,
                    "request_binding": "original", "original_request_id": RID,
                    "automatic_retries": 0, "helper_model_calls": 0,
                    "business_success": None, "original_host_evaluation_result": None,
                    "controller_result_handle": {"relative_path": str(secret)}}}
            return [canonical(response) + b"\n"]
        with fault_endpoint(self.root, handler) as (client, helper, _):
            read = client_module.read_regular
            observed = []
            def capture_read(path, limit):
                observed.append(path)
                return read(path, limit)
            with mock.patch.object(client_module, "read_regular", side_effect=capture_read):
                response = client.invoke(poll(helper))
            self.assertNotIn(secret, observed)
            self.assertEqual("response_received", response["transport_state"])
            self.assertNotIn(secret.read_text(), json.dumps(response))
            self.assertFalse(response["model_causality_verified"])


class RealUnixSDKSessionTests(SDKFixtureCase):
    """The same critical actions, using real AF_UNIX and owner.serve_forever.

    No connection patch is installed. A supported CI must set
    B1_REQUIRE_REAL_IPC=1 so an unavailable transport is a failure, not a skip.
    """
    real_socket = True
    test_actual_tool_start_polls_unique_raw_receipts = (
        SDKConnectionDoubleTests.test_tool_entry_start_and_polls_share_one_real_owner_and_unique_raw_receipts)
    test_actual_accepted_start_reply_loss_then_poll_original = (
        SDKConnectionDoubleTests.test_accepted_start_reply_loss_is_poll_only_even_with_new_client_instance)
    test_actual_concurrent_same_start_is_one_launch = (
        SDKConnectionDoubleTests.test_concurrent_same_start_is_one_start_and_remaining_polls)
    test_actual_request_binding_conflict_and_new_id_no_second_launch = (
        SDKConnectionDoubleTests.test_request_binding_conflict_and_new_id_cannot_spawn_another_macro)
    test_actual_poll_before_start_no_reservation = (
        SDKConnectionDoubleTests.test_poll_before_start_never_registers_reservation_or_starts_child)

    def test_actual_read_timeout_does_not_cancel_or_repeat_running_child(self):
        with self.owner_fixture() as fixture:
            fixture.owner.delay_next_response = .3
            configured = fixture.configuration
            short = SessionClient(HostConfiguration(configured.identity_path, configured.socket_path,
                                                     configured.receipts_directory, .1))
            lost = short.invoke(start())
            self.assertEqual("unknown", lost["transport_state"])
            self.assertEqual("TimeoutError", lost["error"]["type"])
            self.assertEqual(fixture.owner.helper_id, lost["helper_id"])
            self.assertEqual(RID, lost["request_id"])
            retry = SessionClient(configured).invoke(start())
            self.assertEqual("poll", retry["wire_operation"])
            self.assertEqual("running", retry["owner_response"]["session"]["state"])
            self.assertEqual(1, fixture.launches)
            self.assertIsNone(fixture.children[0].poll())
            self.assertEqual(["start", "poll"], [json.loads(raw)["operation"]
                             for raw in fixture.owner.observed_requests])
            _, raw_response, metadata = self.receipt(short, lost)
            self.assertEqual(b"", raw_response)
            self.assertFalse(metadata["response_frame_validated"])
            self.assertEqual(0, metadata["automatic_retries"])
            self.assertFalse(metadata["budget_refund"])


if __name__ == "__main__":
    unittest.main()
