"""Version 2 shared SQLite action registry; never executes business operations.

Untrusted model tools may expose reserve(), poll(), and database_state() only.
TrustedAdapter is a privileged in-process adapter API. Its secret is a guard
against accidental API exposure, NOT a sandbox against filesystem/Python access.
The real adapter must verify target evidence before calling these methods.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
from typing import Any


class RegistryError(Exception):
    pass


class Conflict(RegistryError):
    pass


class InvalidState(RegistryError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200 or "\x00" in value:
        raise ValueError("Expected a nonempty bounded identifier")
    return value


def sha256_text(value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Expected lowercase SHA-256")
    return value


@dataclass(frozen=True)
class DispatchDecision:
    granted: bool
    launch_token: str | None
    action: dict


SCHEMA = """
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE attempts(id TEXT PRIMARY KEY,scope TEXT NOT NULL,state TEXT NOT NULL,ledger TEXT NOT NULL);
CREATE UNIQUE INDEX active_scope ON attempts(scope) WHERE state='active';
CREATE TABLE databases(attempt TEXT NOT NULL,dbkey TEXT NOT NULL,epoch INTEGER NOT NULL,valid INTEGER NOT NULL,
 target TEXT NOT NULL,PRIMARY KEY(attempt,dbkey),FOREIGN KEY(attempt) REFERENCES attempts(id));
CREATE TABLE aliases(attempt TEXT NOT NULL,ref TEXT NOT NULL,dbkey TEXT NOT NULL,
 PRIMARY KEY(attempt,ref),FOREIGN KEY(attempt,dbkey) REFERENCES databases(attempt,dbkey));
CREATE TABLE programs(attempt TEXT NOT NULL,operation TEXT NOT NULL,sha TEXT NOT NULL,enabled INTEGER NOT NULL,
 PRIMARY KEY(attempt,operation),FOREIGN KEY(attempt) REFERENCES attempts(id));
CREATE TABLE intents(attempt TEXT NOT NULL,ref TEXT NOT NULL,dbkey TEXT NOT NULL,kind TEXT NOT NULL,
 semantic_key TEXT NOT NULL,receipt_sha TEXT NOT NULL,extra_lock TEXT,
 PRIMARY KEY(attempt,ref),FOREIGN KEY(attempt,dbkey) REFERENCES databases(attempt,dbkey));
CREATE TABLE actions(attempt TEXT NOT NULL,id TEXT NOT NULL,role TEXT NOT NULL,operation TEXT NOT NULL,
 dbkey TEXT NOT NULL,intent_key TEXT,request TEXT NOT NULL,semantic_sha TEXT NOT NULL,
 execution TEXT NOT NULL,effect TEXT NOT NULL,expected_epoch INTEGER NOT NULL,dispatch_epoch INTEGER,
 launch_token TEXT,terminal_evidence TEXT,settlement_evidence TEXT,
 PRIMARY KEY(attempt,id),FOREIGN KEY(attempt,dbkey) REFERENCES databases(attempt,dbkey));
CREATE TABLE locks(attempt TEXT NOT NULL,resource TEXT NOT NULL,action TEXT NOT NULL,mode TEXT NOT NULL,
 PRIMARY KEY(attempt,resource,action),FOREIGN KEY(attempt,action) REFERENCES actions(attempt,id));
CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,attempt TEXT NOT NULL,action TEXT,
 kind TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE evidence(id TEXT PRIMARY KEY,attempt TEXT NOT NULL,action TEXT NOT NULL,kind TEXT NOT NULL,
 seq INTEGER NOT NULL,terminal_id TEXT,ledger TEXT,payload TEXT NOT NULL,
 FOREIGN KEY(attempt,action) REFERENCES actions(attempt,id));
CREATE TABLE audit_tickets(token TEXT PRIMARY KEY,attempt TEXT NOT NULL,action TEXT NOT NULL,
 terminal_id TEXT NOT NULL,ledger TEXT NOT NULL,begin_seq INTEGER NOT NULL,finished INTEGER NOT NULL,
 FOREIGN KEY(attempt,action) REFERENCES actions(attempt,id));
CREATE TABLE generations(attempt TEXT NOT NULL,dbkey TEXT NOT NULL,queue INTEGER NOT NULL,
 services INTEGER NOT NULL,PRIMARY KEY(attempt,dbkey),
 FOREIGN KEY(attempt,dbkey) REFERENCES databases(attempt,dbkey));
CREATE TABLE public_acceptances(scope TEXT NOT NULL,ledger TEXT NOT NULL,intent_key TEXT NOT NULL,
 evidence_id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(scope,ledger,intent_key));
"""

OPERATIONS = {"observe", "restore_database", "send_notification", "replay_issue",
              "service_control", "queue_prune", "final_submit"}
SETTLED = {"read_only", "settled_applied", "settled_not_applied", "partial_or_conflict"}


class ActionRegistry:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        if not self.path.is_file():
            raise FileNotFoundError(self.path)

    @classmethod
    def create(cls, path: str | Path, adapter_secret: str) -> "ActionRegistry":
        path = Path(path).absolute()
        if not isinstance(adapter_secret, str) or len(adapter_secret) < 24:
            raise ValueError("Adapter secret is too short")
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents overwriting an existing durable registry.
        with path.open("xb"):
            pass
        with closing(sqlite3.connect(path, isolation_level=None)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(SCHEMA)
            db.execute("INSERT INTO metadata VALUES('adapter_sha',?)", (hashlib.sha256(adapter_secret.encode()).hexdigest(),))
            db.execute("INSERT INTO metadata VALUES('schema_version','2')")
        return cls(path)

    def _connect(self, readonly=False):
        db = sqlite3.connect(self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True,
                             timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        if readonly:
            db.execute("PRAGMA query_only=ON")
        else:
            db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _tx(self):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _event(db, attempt, action, kind, data):
        return db.execute("INSERT INTO events(attempt,action,kind,data) VALUES(?,?,?,?)",
                          (attempt, action, kind, canonical(data))).lastrowid

    @staticmethod
    def _attempt(db, attempt, active=True):
        row = db.execute("SELECT * FROM attempts WHERE id=?", (attempt,)).fetchone()
        if row is None or (active and row["state"] != "active"):
            raise InvalidState("Unknown or inactive attempt")
        return row

    @staticmethod
    def _action(db, attempt, action):
        row = db.execute("SELECT * FROM actions WHERE attempt=? AND id=?", (attempt, action)).fetchone()
        if row is None:
            raise InvalidState("Unknown action")
        return row

    @staticmethod
    def _database(db, attempt, ref):
        row = db.execute("SELECT d.* FROM aliases a JOIN databases d ON d.attempt=a.attempt AND d.dbkey=a.dbkey "
                         "WHERE a.attempt=? AND a.ref=?", (attempt, ref)).fetchone()
        if row is None:
            raise InvalidState("Database reference was not declared by the trusted lifecycle adapter")
        return row

    @staticmethod
    def _public(row):
        out = dict(row)
        out.pop("launch_token", None)
        out["request"] = json.loads(out["request"])
        return out

    def adapter(self, secret: str) -> "TrustedAdapter":
        with closing(self._connect(readonly=True)) as db:
            expected = db.execute("SELECT value FROM metadata WHERE key='adapter_sha'").fetchone()[0]
        actual = hashlib.sha256(secret.encode()).hexdigest()
        if not hmac.compare_digest(expected, actual):
            raise PermissionError("Trusted adapter capability required")
        return TrustedAdapter(self, secret)

    def reserve(self, *, attempt_id: str, action_id: str, role: str, operation: str,
                database_ref: str, expected_epoch: int, intent_ref: str | None = None,
                parameters: dict | None = None) -> dict:
        for x in [attempt_id, action_id, role, database_ref]:
            identifier(x)
        if operation not in OPERATIONS or type(expected_epoch) is not int or expected_epoch < 0:
            raise ValueError("Unsupported operation or epoch")
        if parameters is None:
            parameters = {}
        if not isinstance(parameters, dict) or len(canonical(parameters).encode()) > 16384:
            raise ValueError("Parameters must be a bounded JSON object")
        with self._tx() as db:
            attempt = self._attempt(db, attempt_id)
            database = self._database(db, attempt_id, database_ref)
            program = db.execute("SELECT sha,enabled FROM programs WHERE attempt=? AND operation=?", (attempt_id, operation)).fetchone()
            if program is None or program["enabled"] != 1:
                raise InvalidState("Operation has no trusted program binding")
            intent = None
            if operation in {"send_notification", "replay_issue"}:
                intent = db.execute("SELECT * FROM intents WHERE attempt=? AND ref=?", (attempt_id, intent_ref)).fetchone()
                kind = "notification" if operation == "send_notification" else "issue"
                if intent is None or intent["kind"] != kind or intent["dbkey"] != database["dbkey"]:
                    raise InvalidState("Intent is not a matching trusted public-intent binding")
            elif intent_ref is not None:
                raise ValueError("This operation cannot have an intent")
            # User aliases and role are deliberately absent from semantic identity.
            request = {"operation": operation, "database_key": database["dbkey"], "target": json.loads(database["target"]),
                       "expected_epoch": expected_epoch, "program_sha256": program["sha"], "parameters": parameters,
                       "intent_key": intent["semantic_key"] if intent else None,
                       "receipt_sha256": intent["receipt_sha"] if intent else None}
            semantic_sha = digest(request)
            prior = db.execute("SELECT * FROM actions WHERE attempt=? AND id=?", (attempt_id, action_id)).fetchone()
            if prior is not None:
                if prior["semantic_sha"] != semantic_sha:
                    raise Conflict("Action id already bound to different semantic content")
                return self._public(prior)
            # A final submission is unique across reopened controller attempts
            # referring to the SAME physical/native scope. Even a known failed
            # oracle result has already consumed this side-effecting evaluation.
            submitted = db.execute(
                "SELECT a.id FROM actions a JOIN attempts t ON a.attempt=t.id "
                "WHERE t.scope=? AND a.operation='final_submit' AND a.dispatch_epoch IS NOT NULL LIMIT 1",
                (attempt["scope"],)).fetchone()
            if submitted is not None and operation != "observe":
                raise Conflict("Native final submission already dispatched for this physical scope")
            if database["epoch"] != expected_epoch:
                raise Conflict("Stale database epoch")
            if not database["valid"] and operation not in {"restore_database", "observe", "service_control"}:
                raise Conflict("Database identities are invalid until trusted postconditions settle recovery")
            intent_key = intent["semantic_key"] if intent else None
            if intent_key:
                if operation == "send_notification":
                    if db.execute("SELECT 1 FROM public_acceptances WHERE scope=? AND ledger=? AND intent_key=?",
                                  (attempt["scope"], attempt["ledger"], intent_key)).fetchone():
                        raise Conflict("Public audit has already observed this notification accepted")
                    # A database restore and even an explicitly closed/reopened
                    # attempt do not erase delivery history in the same ledger.
                    done = db.execute("SELECT a.effect,a.expected_epoch FROM actions a JOIN attempts t ON t.id=a.attempt "
                                      "WHERE t.scope=? AND t.ledger=? AND a.intent_key=?",
                                      (attempt["scope"], attempt["ledger"], intent_key)).fetchall()
                else:
                    done = db.execute("SELECT effect,expected_epoch FROM actions WHERE attempt=? AND intent_key=?",
                                      (attempt_id, intent_key)).fetchall()
                for old in done:
                    if old["effect"] in {"settled_applied", "partial_or_conflict", "observed_applied"} and (
                        operation == "send_notification" or old["expected_epoch"] == expected_epoch
                    ):
                        raise Conflict("Intent already has an applied or conflicting effect; no new duplicate action")
            locks = [("database:" + database["dbkey"], "X" if operation in {"restore_database", "final_submit"} else "S")]
            if operation == "service_control":
                arguments = parameters.get("arguments", parameters)
                if set(arguments) != {"service", "verb"} or arguments["service"] not in {"puma", "sidekiq"} or arguments["verb"] not in {"stop", "start"}:
                    raise ValueError("Service control requires exactly a fixed service and stop/start verb")
                locks.append(("service:" + database["dbkey"] + ":" + arguments["service"], "X"))
                # Queue snapshots and queue writes cannot overlap either writer
                # transition. Other independent intent operations remain possible.
                locks.append(("queue:" + database["dbkey"], "X"))
            elif operation in {"replay_issue", "send_notification", "queue_prune"}:
                locks.append(("queue:" + database["dbkey"], "X" if operation == "queue_prune" else "S"))
                locks.append(("service:" + database["dbkey"] + ":puma", "S"))
                locks.append(("service:" + database["dbkey"] + ":sidekiq", "S"))
            if operation == "final_submit":
                if db.execute("SELECT 1 FROM locks WHERE attempt=? LIMIT 1", (attempt_id,)).fetchone():
                    raise Conflict("All original actions must settle before final submission reservation")
                locks.append(("native-final:" + attempt["scope"], "X"))
            elif db.execute("SELECT 1 FROM locks WHERE attempt=? AND resource=?", (attempt_id, "native-final:" + attempt["scope"])).fetchone():
                raise Conflict("Original final evaluation is reserved or unresolved")
            if intent:
                locks.append(("intent:" + intent_key, "X"))
                if intent["extra_lock"]:
                    locks.append(("declared:" + intent["extra_lock"], "X"))
            for resource, mode in locks:
                old = db.execute("SELECT mode FROM locks WHERE attempt=? AND resource=?", (attempt_id, resource)).fetchall()
                if any(mode == "X" or row["mode"] == "X" for row in old):
                    raise Conflict("Conflicting resource has an unresolved action")
            db.execute("INSERT INTO actions(attempt,id,role,operation,dbkey,intent_key,request,semantic_sha,execution,effect,expected_epoch) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (attempt_id, action_id, role, operation, database["dbkey"], intent_key,
                       canonical(request), semantic_sha, "reserved", "no_effect_proven", expected_epoch))
            db.executemany("INSERT INTO locks VALUES(?,?,?,?)", [(attempt_id, r, action_id, m) for r, m in locks])
            self._event(db, attempt_id, action_id, "reserved", {"role": role, "semantic_sha": semantic_sha})
            return self._public(self._action(db, attempt_id, action_id))

    def poll(self, attempt_id: str, action_id: str) -> dict:
        with closing(self._connect(readonly=True)) as db:
            self._attempt(db, attempt_id, active=False)
            return self._public(self._action(db, attempt_id, action_id))

    def database_state(self, attempt_id: str, database_ref: str) -> dict:
        with closing(self._connect(readonly=True)) as db:
            self._attempt(db, attempt_id, active=False)
            row = self._database(db, attempt_id, database_ref)
            return {"epoch": row["epoch"], "valid": bool(row["valid"]), "database_key": row["dbkey"]}

    def generations(self, attempt_id: str, database_ref: str) -> dict:
        """Logical invalidation versions, never independent world-state proof."""
        with closing(self._connect(readonly=True)) as db:
            self._attempt(db, attempt_id, active=False)
            row = self._database(db, attempt_id, database_ref)
            generation = db.execute("SELECT queue,services FROM generations WHERE attempt=? AND dbkey=?",
                                    (attempt_id, row["dbkey"])).fetchone()
            return {"database": row["epoch"], "database_valid": bool(row["valid"]),
                    "queue": generation["queue"], "services": generation["services"]}


class TrustedAdapter:
    """Privileged verifier boundary. Never expose this object or secret to models.

    Evidence contents are adapter assertions, not verified observations in this
    prototype. No database/socket/process or business evidence is collected here.
    """
    def __init__(self, registry: ActionRegistry, secret: str):
        self.registry = registry
        self._secret = secret

    @contextmanager
    def _tx(self):
        # Check on every privileged call, including after process restart.
        self.registry.adapter(self._secret)
        with self.registry._tx() as db:
            yield db

    def create_attempt(self, attempt_id: str, *, scope_id: str, ledger_lifecycle: str,
                       databases: dict, programs: dict, enabled_operations: set | None = None) -> None:
        for x in [attempt_id, scope_id, ledger_lifecycle]:
            identifier(x)
        if not databases or set(programs) != OPERATIONS:
            raise ValueError("Declare database catalog and all supported program bindings")
        if enabled_operations is None:
            enabled_operations = OPERATIONS
        if not isinstance(enabled_operations, set) or not enabled_operations or not enabled_operations <= OPERATIONS:
            raise ValueError("Explicit supported operation enablement required")
        with self._tx() as db:
            try:
                db.execute("INSERT INTO attempts VALUES(?,?,'active',?)", (attempt_id, scope_id, ledger_lifecycle))
            except sqlite3.IntegrityError as error:
                raise Conflict("Attempt id exists or physical scope still has an active attempt") from error
            seen = {}
            for ref, definition in databases.items():
                identifier(ref)
                key = identifier(definition["database_key"])
                target = definition["target_identity"]
                if not isinstance(target, dict) or not target:
                    raise ValueError("Trusted target identity is required")
                target_text = canonical(target)
                if key in seen and seen[key] != target_text:
                    raise Conflict("Aliases for one database disagree on target identity")
                if key not in seen:
                    db.execute("INSERT INTO databases VALUES(?,?,0,1,?)", (attempt_id, key, target_text))
                    db.execute("INSERT INTO generations VALUES(?,?,0,0)", (attempt_id, key))
                    seen[key] = target_text
                db.execute("INSERT INTO aliases VALUES(?,?,?)", (attempt_id, ref, key))
            for operation, sha in programs.items():
                db.execute("INSERT INTO programs VALUES(?,?,?,?)", (attempt_id, operation, sha256_text(sha), int(operation in enabled_operations)))
            self.registry._event(db, attempt_id, None, "attempt_opened", {"scope": scope_id, "ledger": ledger_lifecycle})

    def declare_intent(self, attempt_id: str, intent_ref: str, *, database_ref: str, kind: str,
                       public_business_key: dict, receipt_sha256: str, serialization_key: str | None = None):
        identifier(intent_ref)
        if kind not in {"notification", "issue"} or not isinstance(public_business_key, dict) or not public_business_key:
            raise ValueError("Trusted complete public business key required")
        sha256_text(receipt_sha256)
        if serialization_key is not None:
            identifier(serialization_key)
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            database = self.registry._database(db, attempt_id, database_ref)
            key = digest({"database": database["dbkey"], "kind": kind, "business": public_business_key})
            values = (attempt_id, intent_ref, database["dbkey"], kind, key, receipt_sha256, serialization_key)
            prior = db.execute("SELECT * FROM intents WHERE attempt=? AND ref=?", (attempt_id, intent_ref)).fetchone()
            if prior is not None:
                if tuple(prior) != values:
                    raise Conflict("Public intent alias cannot be rebound")
                return
            # Aliases of one semantic intent cannot weaken the trusted lock binding.
            aliases = db.execute("SELECT receipt_sha,extra_lock FROM intents WHERE attempt=? AND semantic_key=?",
                                 (attempt_id, key)).fetchall()
            if any((x["receipt_sha"], x["extra_lock"]) != (receipt_sha256, serialization_key) for x in aliases):
                raise Conflict("Semantic intent aliases disagree on public evidence or serialization")
            db.execute("INSERT INTO intents VALUES(?,?,?,?,?,?,?)", values)
            self.registry._event(db, attempt_id, None, "intent_declared", {"ref": intent_ref, "semantic_key": key})

    def dispatch(self, attempt_id: str, action_id: str) -> DispatchDecision:
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] != "reserved":
                return DispatchDecision(False, None, self.registry._public(action))
            enabled = db.execute("SELECT enabled FROM programs WHERE attempt=? AND operation=?", (attempt_id, action["operation"])).fetchone()
            if enabled is None or enabled["enabled"] != 1:
                raise InvalidState("Operation is disabled in this original attempt")
            database = db.execute("SELECT * FROM databases WHERE attempt=? AND dbkey=?", (attempt_id, action["dbkey"])).fetchone()
            if database["epoch"] != action["expected_epoch"]:
                raise Conflict("Reserved action has a stale epoch")
            if not database["valid"] and action["operation"] not in {"restore_database", "observe", "service_control"}:
                raise Conflict("Database identity is invalid")
            if action["operation"] == "send_notification":
                attempt = self.registry._attempt(db, attempt_id)
                if db.execute("SELECT 1 FROM public_acceptances WHERE scope=? AND ledger=? AND intent_key=?",
                              (attempt["scope"], attempt["ledger"], action["intent_key"])).fetchone():
                    raise Conflict("Public acceptance arrived after reservation; sending is inhibited")
            if action["operation"] == "final_submit":
                attempt = self.registry._attempt(db, attempt_id)
                if db.execute("SELECT 1 FROM actions a JOIN attempts t ON a.attempt=t.id "
                              "WHERE t.scope=? AND a.operation='final_submit' AND a.dispatch_epoch IS NOT NULL",
                              (attempt["scope"],)).fetchone():
                    raise Conflict("Final evaluation already dispatched in this physical/native scope")
                if db.execute("SELECT 1 FROM locks WHERE attempt=? AND action<>? LIMIT 1",
                              (attempt_id, action_id)).fetchone():
                    raise Conflict("Other unsettled actions block final evaluation")
            epoch = database["epoch"]
            if action["operation"] == "restore_database":
                epoch += 1
                db.execute("UPDATE databases SET epoch=?,valid=0 WHERE attempt=? AND dbkey=?", (epoch, attempt_id, action["dbkey"]))
            if action["operation"] in {"restore_database", "service_control", "replay_issue", "queue_prune", "send_notification", "final_submit"}:
                db.execute("UPDATE generations SET queue=queue+1 WHERE attempt=? AND dbkey=?", (attempt_id, action["dbkey"]))
            if action["operation"] == "service_control":
                db.execute("UPDATE generations SET services=services+1 WHERE attempt=? AND dbkey=?", (attempt_id, action["dbkey"]))
            token = secrets.token_hex(24)
            db.execute("UPDATE actions SET execution='dispatching',effect='unknown',dispatch_epoch=?,launch_token=? WHERE attempt=? AND id=?",
                       (epoch, token, attempt_id, action_id))
            self.registry._event(db, attempt_id, action_id, "dispatch_permit_issued", {"dispatch_epoch": epoch})
            # Commit happens before the decision is returned. Repeated calls never
            # receive a second permit, even when the first reply was lost.
            return DispatchDecision(True, token, self.registry._public(self.registry._action(db, attempt_id, action_id)))

    def latch_public_acceptance(self, attempt_id: str, intent_ref: str, proof: dict):
        """Trusted verifier only: complete actual public audit proves acceptance.

        Unlike action effect settlement this records pre-existing accepted mail,
        including mail sent before this controller started. It does not certify
        stable exactly-once delivery or release any unresolved action lock.
        """
        required = {"evidence_id", "ledger_lifecycle", "complete", "capture_sha256", "delivery_ids"}
        if not isinstance(proof, dict) or set(proof) != required or proof["complete"] is not True:
            raise ValueError("Complete verified public acceptance proof required")
        identifier(proof["evidence_id"])
        sha256_text(proof["capture_sha256"])
        if not isinstance(proof["delivery_ids"], list) or not proof["delivery_ids"] or any(type(i) is not int or i < 1 for i in proof["delivery_ids"]):
            raise ValueError("At least one verified public delivery identity required")
        with self._tx() as db:
            attempt = self.registry._attempt(db, attempt_id)
            if proof["ledger_lifecycle"] != attempt["ledger"]:
                raise Conflict("Public acceptance belongs to a different ledger lifecycle")
            intent = db.execute("SELECT * FROM intents WHERE attempt=? AND ref=?", (attempt_id, intent_ref)).fetchone()
            if intent is None or intent["kind"] != "notification":
                raise InvalidState("Notification intent must be bound before public acceptance")
            db.execute("INSERT OR IGNORE INTO public_acceptances VALUES(?,?,?,?,?)",
                       (attempt["scope"], attempt["ledger"], intent["semantic_key"], proof["evidence_id"], canonical(proof)))
            self.registry._event(db, attempt_id, None, "public_acceptance_latched",
                                 {"intent_key": intent["semantic_key"], "evidence_id": proof["evidence_id"]})

    def mark_unknown(self, attempt_id: str, action_id: str, reason: str):
        identifier(reason)
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] not in {"dispatching", "running", "unknown"}:
                raise InvalidState("Only dispatched, nonterminal execution can become unknown")
            db.execute("UPDATE actions SET execution='unknown' WHERE attempt=? AND id=?", (attempt_id, action_id))
            self.registry._event(db, attempt_id, action_id, "execution_unknown", {"reason": reason})

    def final_evaluation_accepted(self, attempt_id: str, action_id: str, proof: dict):
        """Original HTTP acceptance is pending execution, never oracle success.

        Keep every lock and the one consumed permit. The original host records
        the later evaluator result separately; the agent has not observed it.
        """
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["operation"] != "final_submit" or action["execution"] not in {"dispatching", "unknown"}:
                raise InvalidState("Only the original dispatched final action can record acceptance")
            details = proof.get("details", {})
            if (details.get("submission_state") != "accepted_for_evaluation"
                    or details.get("state") != "accepted_pending_evaluation"
                    or details.get("business_success") is not None
                    or details.get("original_evaluation_terminal") is not False):
                raise ValueError("HTTP acceptance must not assert evaluator terminal or business success")
            identifier(details.get("native_call_id"))
            sha256_text(details.get("response_sha256"))
            eid = self._proof(db, attempt_id, action, "original_evaluation_accepted", proof)
            db.execute("UPDATE actions SET execution='running',effect='unknown' WHERE attempt=? AND id=?",
                       (attempt_id, action_id))
            return eid

    def _proof(self, db, attempt_id, action, kind, proof, *, terminal_id=None, ledger=None):
        if not isinstance(proof, dict) or set(proof) != {"evidence_id", "target_identity", "details"}:
            raise ValueError("Qualified adapter proof needs evidence_id, target_identity and details")
        identifier(proof["evidence_id"])
        if not isinstance(proof["details"], dict):
            raise ValueError("Proof details must be a JSON object")
        request = json.loads(action["request"])
        if canonical(proof["target_identity"]) != canonical(request["target"]):
            raise Conflict("Proof target does not match bound target")
        payload = {**proof, "semantic_sha": action["semantic_sha"], "dispatch_epoch": action["dispatch_epoch"]}
        seq = self.registry._event(db, attempt_id, action["id"], kind, {"evidence_id": proof["evidence_id"], "digest": digest(payload)})
        try:
            db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)", (proof["evidence_id"], attempt_id, action["id"], kind,
                       seq, terminal_id, ledger, canonical(payload)))
        except sqlite3.IntegrityError as error:
            raise Conflict("Evidence id already exists or binding is invalid") from error
        return proof["evidence_id"]

    def _latch_positive(self, db, attempt_id, action, proof):
        # The registry must not forget an already recorded positive assertion
        # merely because settlement is requested with an older negative proof.
        # Classification remains the trusted adapter's responsibility.
        if proof["details"].get("settled_effect") in {"settled_applied", "partial_or_conflict"}:
            db.execute("UPDATE actions SET effect='observed_applied' WHERE attempt=? AND id=?", (attempt_id, action["id"]))
            self.registry._event(db, attempt_id, action["id"], "positive_effect_latched", {"evidence_id": proof["evidence_id"]})

    def terminal(self, attempt_id: str, action_id: str, proof: dict):
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] not in {"dispatching", "running", "unknown"}:
                raise InvalidState("Terminal evidence requires a dispatched, nonterminal action")
            evidence_id = self._proof(db, attempt_id, action, "execution_terminal", proof)
            db.execute("UPDATE actions SET execution='terminal',terminal_evidence=? WHERE attempt=? AND id=?",
                       (evidence_id, attempt_id, action_id))
            # No lock is released. Execution termination is not effect settlement.

    def observe_applied(self, attempt_id: str, action_id: str, proof: dict):
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] == "reserved" or action["effect"] in SETTLED:
                raise InvalidState("Cannot observe an effect before dispatch or regress a settled action")
            self._proof(db, attempt_id, action, "effect_observed", proof)
            db.execute("UPDATE actions SET effect='observed_applied' WHERE attempt=? AND id=?", (attempt_id, action_id))

    def begin_audit(self, attempt_id: str, action_id: str, terminal_evidence_id: str, ledger_lifecycle: str) -> str:
        with self._tx() as db:
            attempt = self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] != "terminal" or action["terminal_evidence"] != terminal_evidence_id:
                raise InvalidState("Audit must follow this action's verified terminal evidence")
            if action["effect"] in SETTLED or attempt["ledger"] != ledger_lifecycle:
                raise Conflict("Settled action or different ledger lifecycle")
            token = secrets.token_hex(24)
            seq = self.registry._event(db, attempt_id, action_id, "audit_requested", {"terminal": terminal_evidence_id, "ledger": ledger_lifecycle})
            db.execute("INSERT INTO audit_tickets VALUES(?,?,?,?,?,?,0)", (token, attempt_id, action_id, terminal_evidence_id, ledger_lifecycle, seq))
            return token

    def finish_audit(self, ticket: str, proof: dict) -> str:
        with self._tx() as db:
            t = db.execute("SELECT * FROM audit_tickets WHERE token=?", (ticket,)).fetchone()
            if t is None or t["finished"]:
                raise InvalidState("Unknown or consumed causal audit ticket")
            attempt = self.registry._attempt(db, t["attempt"])
            action = self.registry._action(db, t["attempt"], t["action"])
            if attempt["ledger"] != t["ledger"] or action["terminal_evidence"] != t["terminal_id"] or action["effect"] in SETTLED:
                raise Conflict("Audit binding is no longer valid")
            details = proof.get("details", {})
            if details.get("capture_ticket") != ticket or details.get("complete") is not True:
                raise ValueError("Adapter must bind a complete capture to the issued causal ticket")
            sha256_text(details.get("capture_sha256"))
            eid = self._proof(db, t["attempt"], action, "public_audit", proof, terminal_id=t["terminal_id"], ledger=t["ledger"])
            self._latch_positive(db, t["attempt"], action, proof)
            db.execute("UPDATE audit_tickets SET finished=1 WHERE token=?", (ticket,))
            return eid

    def postcondition(self, attempt_id: str, action_id: str, proof: dict) -> str:
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] != "terminal" or action["operation"] == "send_notification" or action["effect"] in SETTLED:
                raise InvalidState("Postcondition needs terminal non-notification action")
            eid = self._proof(db, attempt_id, action, "postcondition", proof, terminal_id=action["terminal_evidence"])
            self._latch_positive(db, attempt_id, action, proof)
            return eid

    def settle(self, attempt_id: str, action_id: str, evidence_id: str):
        with self._tx() as db:
            attempt = self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] != "terminal" or action["effect"] in SETTLED:
                raise InvalidState("Cannot settle nonterminal or already settled action")
            evidence = db.execute("SELECT * FROM evidence WHERE id=? AND attempt=? AND action=?",
                                  (evidence_id, attempt_id, action_id)).fetchone()
            required = "public_audit" if action["operation"] == "send_notification" else "postcondition"
            if evidence is None or evidence["kind"] != required or evidence["terminal_id"] != action["terminal_evidence"]:
                raise Conflict("Effect evidence is not bound to this action's terminal record")
            if required == "public_audit" and evidence["ledger"] != attempt["ledger"]:
                raise Conflict("Ledger lifecycle mismatch")
            details = json.loads(evidence["payload"])["details"]
            effect = details.get("settled_effect")
            if effect not in SETTLED or (effect == "read_only") != (action["operation"] == "observe"):
                raise ValueError("Effect classification is incompatible with operation")
            if action["effect"] == "observed_applied" and effect == "settled_not_applied":
                raise Conflict("Observed application cannot become non-application")
            if action["operation"] == "restore_database":
                valid = details.get("database_valid")
                if type(valid) is not bool:
                    raise ValueError("Restore settlement requires trusted database validity result")
                db.execute("UPDATE databases SET valid=? WHERE attempt=? AND dbkey=? AND epoch=?",
                           (int(valid), attempt_id, action["dbkey"], action["dispatch_epoch"]))
            db.execute("UPDATE actions SET effect=?,settlement_evidence=? WHERE attempt=? AND id=?",
                       (effect, evidence_id, attempt_id, action_id))
            db.execute("DELETE FROM locks WHERE attempt=? AND action=?", (attempt_id, action_id))
            self.registry._event(db, attempt_id, action_id, "effect_settled", {"evidence": evidence_id, "effect": effect})

    def cancel_reserved(self, attempt_id: str, action_id: str, reason: str):
        identifier(reason)
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            action = self.registry._action(db, attempt_id, action_id)
            if action["execution"] != "reserved":
                raise InvalidState("Only a never-dispatched reservation may be cancelled")
            db.execute("UPDATE actions SET execution='not_dispatched',effect='settled_not_applied' WHERE attempt=? AND id=?",
                       (attempt_id, action_id))
            db.execute("DELETE FROM locks WHERE attempt=? AND action=?", (attempt_id, action_id))
            self.registry._event(db, attempt_id, action_id, "cancelled_before_dispatch", {"reason": reason})

    def close_attempt(self, attempt_id: str):
        with self._tx() as db:
            self.registry._attempt(db, attempt_id)
            if db.execute("SELECT 1 FROM locks WHERE attempt=? LIMIT 1", (attempt_id,)).fetchone():
                raise Conflict("Unresolved actions prevent closing or replacing this attempt")
            db.execute("UPDATE attempts SET state='closed' WHERE id=?", (attempt_id,))
            self.registry._event(db, attempt_id, None, "attempt_closed", {})
