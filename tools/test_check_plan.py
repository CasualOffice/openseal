import importlib.util
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_plan", HERE / "check-plan.py")
check_plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_plan)

PLAN = "# R\n\n## Execution plan\n\n- Current: `VS-03`\n- Finishing (x): `VS-01`\n- Paused (y): `ML-02`\n\n## Next\n"


def tree(rows):
    root = pathlib.Path(tempfile.mkdtemp())
    (root / "docs").mkdir()
    (root / check_plan.ROADMAP).write_text(PLAN, encoding="utf8")
    (root / check_plan.TRACKER).write_text("\n".join(rows) + "\n", encoding="utf8")
    return root


class CheckPlan(unittest.TestCase):
    def test_an_in_progress_row_outside_the_plan_fails(self):
        problems, _ = check_plan.check(tree(["| UXW-02 | x | In progress | P1 | e | g |"]))
        self.assertEqual(problems, ["UXW-02 is In progress but not in the docs/06 Execution plan"])

    def test_planned_and_open_rows_pass(self):
        rows = ["| VS-03 | x | In progress | P1 | e | g |", "| VS-01 | x | In progress | P1 | e | g |",
                "| ML-02 | x | In progress | P1 | e | g |", "| UXW-02 | x | Open | P1 | e | g |"]
        self.assertEqual(check_plan.check(tree(rows))[0], [])


if __name__ == "__main__":
    unittest.main()
