from conftest import play_out, run


def test_set_config_validates_and_clamps(make_engine):
    async def go():
        eng, _ = make_engine()
        assert eng.set_config(difficulty="hard")["difficulty"] == "hard"
        assert eng.blue_action_points == 1
        assert eng.set_config(difficulty="easy")["difficulty"] == "easy"
        assert eng.blue_action_points == 3
        assert eng.set_config(difficulty="bogus")["difficulty"] == "easy"  # ignored
        assert eng.set_config(max_turns=999)["max_turns"] == 50            # clamped
        assert eng.set_config(max_turns=1)["max_turns"] == 5
        assert eng.set_config(false_positive_rate=5)["false_positive_rate"] == 0.5
    run(go())


def test_max_turns_controls_match_length(make_engine):
    async def go():
        eng, _ = make_engine()
        eng.set_config(max_turns=8)
        await eng.reset(6)
        assert eng.max_turns == 8
        await play_out(eng)
        assert eng.round <= 8
    run(go())


def test_difficulty_changes_blue_action_count(make_engine):
    async def go():
        eng, _ = make_engine(); eng.set_config(difficulty="hard"); await eng.reset(6)
        # hard -> BLUE plays 1 action per turn
        import asyncio
        await eng.start()
        await asyncio.sleep(0.05)
        await eng.stop()
        by_round = {}
        for t in eng.turns:
            if t.side == "blue":
                by_round.setdefault(t.round, 0)
                by_round[t.round] += 1
        assert by_round and all(v == 1 for v in by_round.values())
    run(go())


def test_config_persists_across_reset(make_engine):
    async def go():
        eng, _ = make_engine()
        eng.set_config(difficulty="hard", max_turns=12)
        await eng.reset(6)
        await eng.reset(7)
        assert eng.config["difficulty"] == "hard" and eng.max_turns == 12
    run(go())
