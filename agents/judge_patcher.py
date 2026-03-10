from utils.schemas import BlueTeamDefense, JudgeVerdict, RedTeamFinding


def run_judge(
    findings: list[RedTeamFinding],
    defenses: list[BlueTeamDefense],
) -> list[JudgeVerdict]:
    """Stub judge: no LLM. Confirms findings unless defense claims false positive."""
    defense_map = {d.finding_id: d for d in defenses}

    verdicts = []
    for finding in findings:
        defense = defense_map.get(finding.finding_id)

        if defense is None:
            confirmed = True
            reasoning = "No defense submitted; vulnerability confirmed by default."
        elif defense.is_false_positive:
            confirmed = False
            reasoning = "Blue Team flagged as false positive; confirmed=False."
        else:
            confirmed = True
            reasoning = "Blue Team did not dispute; vulnerability confirmed."

        verdicts.append(
            JudgeVerdict(
                finding_id=finding.finding_id,
                confirmed=confirmed,
                reasoning=reasoning,
                patch=None,
            )
        )

    return verdicts
