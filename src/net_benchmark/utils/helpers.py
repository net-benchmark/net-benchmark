from typing import Any

from tqdm import tqdm

from net_benchmark.utils.messages import info


def create_progress_bar(total: int, desc: str) -> Any:
    return tqdm(
        total=total, desc=info(desc), bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
    )
