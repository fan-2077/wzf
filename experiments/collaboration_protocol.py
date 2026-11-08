"""Event-triggered evidence-bound collaboration protocol (reference implementation).

This module is deterministic orchestration logic, not an LLM agent and not proof
of competition compliance. It counts a bidirectional pair only after the original
requester emits a new, evidence-backed revision after consuming the peer reply.
"""
from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    agent_type: str
    task_id: str
    environment_version: int
    evidence_refs: tuple[str, ...]
    subject_candidate_id: Optional[str]
    recommended_action_id: Optional[str]
    finding: str
    constraints_checked: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()
    revision_of: Optional[str] = None
    consumed_reply_ids: tuple[str, ...] = ()

@dataclass(frozen=True)
class ReviewRequest:
    request_id: str
    from_agent: str
    to_agent: str
    subject_artifact_id: str
    question: str
    evidence_refs: tuple[str, ...]
    expected_environment_version: int

@dataclass(frozen=True)
class ReviewReply:
    reply_id: str
    reply_to_request_id: str
    from_agent: str
    to_agent: str
    answer: str
    supporting_evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...] = ()
    recommended_change: Optional[str] = None

@dataclass
class CollaborationLedger:
    current_environment_version: int
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    requests: dict[str, ReviewRequest] = field(default_factory=dict)
    replies: dict[str, ReviewReply] = field(default_factory=dict)
    consumed: set[str] = field(default_factory=set)
    completed_pairs: set[tuple[str, str]] = field(default_factory=set)

    def add_artifact(self, artifact: Artifact) -> None:
        if not artifact.artifact_id or artifact.artifact_id in self.artifacts:
            raise ValueError("artifact_id missing or duplicated")
        if artifact.environment_version != self.current_environment_version:
            raise ValueError("artifact uses stale environment version")
        if not artifact.evidence_refs:
            raise ValueError("artifact must cite evidence")
        if not artifact.finding.strip():
            raise ValueError("artifact finding is empty")
        self.artifacts[artifact.artifact_id] = artifact

    def open_request(self, request: ReviewRequest) -> None:
        if not request.request_id or request.request_id in self.requests:
            raise ValueError("request_id missing or duplicated")
        if request.from_agent == request.to_agent:
            raise ValueError("self-review is not peer collaboration")
        subject = self.artifacts.get(request.subject_artifact_id)
        if subject is None or subject.agent_type != request.from_agent:
            raise ValueError("requester must own the subject artifact")
        if request.expected_environment_version != self.current_environment_version:
            raise ValueError("request is stale")
        if subject.environment_version != request.expected_environment_version:
            raise ValueError("subject artifact version mismatch")
        if not request.question.strip() or not request.evidence_refs:
            raise ValueError("request must contain a question and evidence")
        if not set(request.evidence_refs).issubset(subject.evidence_refs):
            raise ValueError("request cites evidence absent from subject artifact")
        self.requests[request.request_id] = request

    def submit_reply(self, reply: ReviewReply) -> None:
        if not reply.reply_id or reply.reply_id in self.replies:
            raise ValueError("reply_id missing or duplicated")
        req = self.requests.get(reply.reply_to_request_id)
        if req is None:
            raise ValueError("reply references unknown request")
        if reply.from_agent != req.to_agent or reply.to_agent != req.from_agent:
            raise ValueError("reply sender/recipient do not match request")
        if not reply.answer.strip() or not reply.supporting_evidence_refs:
            raise ValueError("reply must include answer and evidence")
        self.replies[reply.reply_id] = reply

    def consume_and_revise(self, new_artifact: Artifact) -> None:
        if not new_artifact.revision_of or new_artifact.revision_of not in self.artifacts:
            raise ValueError("revision must point to an existing artifact")
        old = self.artifacts[new_artifact.revision_of]
        if old.agent_type != new_artifact.agent_type:
            raise ValueError("only original requester can revise its artifact")
        if old.task_id != new_artifact.task_id:
            raise ValueError("revision task mismatch")
        if new_artifact.environment_version != self.current_environment_version:
            raise ValueError("revision uses stale environment version")
        if not new_artifact.consumed_reply_ids:
            raise ValueError("revision must identify consumed peer replies")
        for rid in new_artifact.consumed_reply_ids:
            reply = self.replies.get(rid)
            if reply is None:
                raise ValueError("revision references unknown reply")
            req = self.requests[reply.reply_to_request_id]
            if req.from_agent != new_artifact.agent_type or req.subject_artifact_id != old.artifact_id:
                raise ValueError("reply was not addressed to this artifact's requester")
            if rid in self.consumed:
                raise ValueError("reply already consumed")
        self.add_artifact(new_artifact)
        for rid in new_artifact.consumed_reply_ids:
            self.consumed.add(rid)
            req = self.requests[self.replies[rid].reply_to_request_id]
            self.completed_pairs.add((req.from_agent, req.to_agent))

    def advance_environment(self, new_version: int) -> None:
        if new_version <= self.current_environment_version:
            raise ValueError("environment version must increase")
        self.current_environment_version = new_version

    def is_current(self, artifact_id: str) -> bool:
        artifact = self.artifacts.get(artifact_id)
        return artifact is not None and artifact.environment_version == self.current_environment_version

    def valid_for_execution(self, artifact_id: str) -> bool:
        artifact = self.artifacts.get(artifact_id)
        return bool(artifact and self.is_current(artifact_id) and artifact.recommended_action_id
                    and artifact.evidence_refs and artifact.constraints_checked)
