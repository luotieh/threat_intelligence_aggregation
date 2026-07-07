from app.services.selection import (
    SEVERITY_TIERS,
    indicator_source,
    select_top_per_source,
)


def test_indicator_source_prefers_source_tag(make_indicator):
    ind = make_indicator(tags=[{"name": "tlp:green"}, {"name": "source:otx"}])
    assert indicator_source(ind) == "otx"


def test_indicator_source_falls_back_to_org(make_indicator):
    ind = make_indicator(tags=[{"name": "tlp:green"}], source_org="CIRCL")
    assert indicator_source(ind) == "CIRCL"


def test_indicator_source_unknown_when_nothing(make_indicator):
    ind = make_indicator(tags=[], source_org=None)
    assert indicator_source(ind) == "unknown"


def test_select_truncates_top_n_per_source(db, make_indicator):
    for i in range(3):
        db.add(make_indicator(value=f"o{i}", normalized_value=f"o{i}",
                              confidence=90 - i, tags=[{"name": "source:otx"}]))
    for i in range(3):
        db.add(make_indicator(value=f"w{i}", normalized_value=f"w{i}",
                              confidence=90 - i, tags=[{"name": "source:whoisxml"}]))
    db.commit()
    groups = select_top_per_source(db, top_n=2, min_severity="high")
    assert [g["source"] for g in groups] == ["otx", "whoisxml"]
    assert all(len(g["items"]) == 2 for g in groups)


def test_select_severity_filter_excludes_medium(db, make_indicator):
    db.add(make_indicator(value="h", normalized_value="h", severity="high",
                          tags=[{"name": "source:otx"}]))
    db.add(make_indicator(value="m", normalized_value="m", severity="medium",
                          tags=[{"name": "source:otx"}]))
    db.commit()
    groups = select_top_per_source(db, top_n=10, min_severity="high")
    values = [i.value for g in groups for i in g["items"]]
    assert values == ["h"]


def test_select_ranks_by_confidence_desc(db, make_indicator):
    db.add(make_indicator(value="lo", normalized_value="lo", confidence=40,
                          tags=[{"name": "source:otx"}]))
    db.add(make_indicator(value="hi", normalized_value="hi", confidence=95,
                          tags=[{"name": "source:otx"}]))
    db.commit()
    groups = select_top_per_source(db, top_n=1, min_severity="high")
    assert groups[0]["items"][0].value == "hi"


def test_select_medium_tier_includes_high_and_medium(db, make_indicator):
    db.add(make_indicator(value="h", normalized_value="h", severity="high",
                          tags=[{"name": "source:otx"}]))
    db.add(make_indicator(value="m", normalized_value="m", severity="medium",
                          tags=[{"name": "source:otx"}]))
    db.commit()
    groups = select_top_per_source(db, top_n=10, min_severity="medium")
    assert len(groups[0]["items"]) == 2
    assert SEVERITY_TIERS["medium"] == {"high", "medium"}
