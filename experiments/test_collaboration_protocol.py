import unittest
from collaboration_protocol import Artifact, ReviewRequest, ReviewReply, CollaborationLedger

def art(aid, role, version=1, revision=None, replies=(), action="plan-A"):
    return Artifact(aid, role, "task-1", version, ("sim://evidence/1",), "candidate-X",
                    action, "finding supported by observed evidence", ("route", "queue"),
                    (), revision, replies)

class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.ledger=CollaborationLedger(1)
        self.ledger.add_artifact(art("a1","route"))
        self.ledger.add_artifact(art("b1","signal",action="plan-B"))
        self.req=ReviewRequest("q1","route","signal","a1","Check route/signal compatibility",
                               ("sim://evidence/1",),1)
        self.ledger.open_request(self.req)

    def test_valid_reply_and_requester_revision_completes_pair(self):
        reply=ReviewReply("r1","q1","signal","route","Signal window conflicts with route",
                          ("sim://evidence/1",),("snapshot is time-bounded",),"revise route")
        self.ledger.submit_reply(reply)
        self.ledger.consume_and_revise(art("a2","route",revision="a1",replies=("r1",),action="plan-C"))
        self.assertIn(("route","signal"),self.ledger.completed_pairs)
        self.assertTrue(self.ledger.valid_for_execution("a2"))

    def test_reply_wrong_sender_rejected(self):
        with self.assertRaisesRegex(ValueError,"sender/recipient"):
            self.ledger.submit_reply(ReviewReply("r1","q1","network","route","x",("e",)))

    def test_self_review_rejected(self):
        with self.assertRaisesRegex(ValueError,"self-review"):
            self.ledger.open_request(ReviewRequest("q2","route","route","a1","check",("sim://evidence/1",),1))

    def test_request_must_cite_subject_evidence(self):
        with self.assertRaisesRegex(ValueError,"absent"):
            self.ledger.open_request(ReviewRequest("q2","route","signal","a1","check",("secret://not-present",),1))

    def test_unconsumed_reply_does_not_count_pair(self):
        self.ledger.submit_reply(ReviewReply("r1","q1","signal","route","No conflict",("sim://evidence/1",)))
        self.assertEqual(self.ledger.completed_pairs,set())

    def test_wrong_agent_cannot_revise(self):
        self.ledger.submit_reply(ReviewReply("r1","q1","signal","route","No conflict",("sim://evidence/1",)))
        with self.assertRaisesRegex(ValueError,"original requester"):
            self.ledger.consume_and_revise(art("b2","signal",revision="a1",replies=("r1",)))

    def test_revision_without_reply_rejected(self):
        with self.assertRaisesRegex(ValueError,"consumed peer replies"):
            self.ledger.consume_and_revise(art("a2","route",revision="a1"))

    def test_duplicate_reply_consumption_rejected(self):
        self.ledger.submit_reply(ReviewReply("r1","q1","signal","route","No conflict",("sim://evidence/1",)))
        self.ledger.consume_and_revise(art("a2","route",revision="a1",replies=("r1",)))
        with self.assertRaisesRegex(ValueError,"already consumed"):
            self.ledger.consume_and_revise(art("a3","route",revision="a2",replies=("r1",)))

    def test_environment_change_invalidates_old_artifacts(self):
        self.ledger.advance_environment(2)
        self.assertFalse(self.ledger.is_current("a1"))
        self.assertFalse(self.ledger.valid_for_execution("a1"))
        with self.assertRaisesRegex(ValueError,"stale environment"):
            self.ledger.add_artifact(art("a2","route",version=1))

    def test_missing_action_cannot_execute(self):
        self.ledger.add_artifact(art("a2","route",action=None))
        self.assertFalse(self.ledger.valid_for_execution("a2"))

    def test_duplicate_artifact_rejected(self):
        with self.assertRaisesRegex(ValueError,"duplicated"):
            self.ledger.add_artifact(art("a1","route"))

    def test_task_mismatch_rejected(self):
        bad=Artifact("a2","route","other-task",1,("sim://evidence/1",),"x","p","f",("route",),(), "a1",("r1",))
        self.ledger.submit_reply(ReviewReply("r1","q1","signal","route","No conflict",("sim://evidence/1",)))
        with self.assertRaisesRegex(ValueError,"task mismatch"):
            self.ledger.consume_and_revise(bad)

if __name__=="__main__": unittest.main()
