import os
import pandas as pd

HISTORY_PATH = "history.csv"

def load_history() -> pd.DataFrame:
    if os.path.exists(HISTORY_PATH):
        return pd.read_csv(HISTORY_PATH)
    return pd.DataFrame(columns=["timestamp","type","indicator","score","level","signals"])

def save_history(df: pd.DataFrame) -> None:
    df.to_csv(HISTORY_PATH, index=False)

def append_history(df: pd.DataFrame, row: dict, max_history: int = 200) -> pd.DataFrame:
    df2 = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    if len(df2) > max_history:
        df2 = df2.tail(max_history)
    return df2