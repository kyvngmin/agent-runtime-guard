from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class CrownJewelAsset:
    asset_id: str
    asset_type: str
    criticality: int
    owner_team: str
    description: str


CROWN_JEWELS: Dict[str, CrownJewelAsset] = {
    "github_prod_repo": CrownJewelAsset(
        asset_id="github_prod_repo",
        asset_type="repo",
        criticality=5,
        owner_team="platform",
        description="Production source repository",
    ),
    "vector_db_main": CrownJewelAsset(
        asset_id="vector_db_main",
        asset_type="vector_db",
        criticality=5,
        owner_team="ai-platform",
        description="Primary retrieval index containing internal docs",
    ),
    "admin_workspace": CrownJewelAsset(
        asset_id="admin_workspace",
        asset_type="saas_app",
        criticality=5,
        owner_team="it",
        description="Primary admin workspace",
    ),
    "finance_bucket": CrownJewelAsset(
        asset_id="finance_bucket",
        asset_type="bucket",
        criticality=5,
        owner_team="finance",
        description="Sensitive financial data store",
    ),
}


def get_asset_criticality(asset_id: Optional[str]) -> Optional[int]:
    if not asset_id:
        return None
    asset = CROWN_JEWELS.get(asset_id)
    return asset.criticality if asset else None
