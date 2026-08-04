"""NetnsIsolator + NftScopeEnforcer factory in composition root (W4-B T1)."""
from __future__ import annotations

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.egress.netns_isolator import NetnsIsolator
from secopent.infrastructure.egress.nft_scope import NftScopeEnforcer
from secopent.interfaces.api.main import create_app


def test_app_state_has_netns_isolator(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4b1.db"))
    assert isinstance(app.state.netns_isolator, NetnsIsolator)


def test_make_nft_enforcer_factory_builds_with_and_without_netns(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4b1.db"))
    make = app.state.make_nft_enforcer
    with_netns = make("secopent-asm-1")
    assert isinstance(with_netns, NftScopeEnforcer)
    assert with_netns._netns == "secopent-asm-1"
    without = make(None)
    assert isinstance(without, NftScopeEnforcer)
    assert without._netns is None


def test_legacy_singleton_enforcer_has_no_netns(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4b1.db"))
    assert app.state.nft_scope_enforcer._netns is None


def test_factory_propagated_to_api_subapp(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4b1.db"))
    api = next(m for m in app.routes if getattr(m, "path", "") == "/api")
    assert api.app.state.netns_isolator is app.state.netns_isolator
    assert callable(api.app.state.make_nft_enforcer)
