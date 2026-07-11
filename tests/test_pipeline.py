import unittest
from pathlib import Path
from cver.pipeline import CVERPipeline
from cver.models import Target

class PipelineTest(unittest.TestCase):
    def test_demo_pipeline(self):
        pipe = CVERPipeline("test")
        out = pipe.run(Target("demo/nginx:lab", "image", labels={"cver-lab":"true"}), "full-pipeline")
        self.assertTrue(out["findings"])
        self.assertTrue(out["exploitability_results"])
        self.assertIn("report", out)
        self.assertTrue(Path(out["report"]["json_path"]).exists())

    def test_policy_blocks_non_lab(self):
        pipe = CVERPipeline("test")
        out = pipe.run(Target("demo/nginx:lab", "image", labels={"cver-lab":"false"}), "redteam-only")
        self.assertTrue(any(d["decision"] == "deny" for d in out["redteam_campaign"]["policy_decisions"]))

if __name__ == "__main__":
    unittest.main()
